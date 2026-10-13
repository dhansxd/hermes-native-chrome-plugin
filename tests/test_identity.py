"""Manifest-scoped identity QA; no install, Chrome or live profile changes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path.home() / '.hermes/cache/scratch'
PRODUCTION = 'dyra-native-chrome'
CANDIDATE = 'dyra-native-chrome-candidate'


def load_root(root=ROOT):
    name = '_identity_fixture_' + hashlib.sha256(str(root).encode()).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(name, root / '__init__.py',
                                                submodule_search_locations=[str(root)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def relocate(parent, name, identity):
    root = Path(parent) / name
    shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns('__pycache__', 'tests', '.git'))
    manifest = root / 'plugin.yaml'
    manifest.write_text(manifest.read_text().replace('name: ' + PRODUCTION + '\n',
                                                   'name: ' + identity + '\n', 1))
    return load_root(root)


class IdentityTests(unittest.TestCase):
    def test_final_verification_identity_isolated_from_installed_candidate(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            verification = relocate(directory, 'verification', 'dyra-native-chrome-verification')
            candidate = relocate(directory, 'candidate', CANDIDATE)
            identity = verification.load_sibling('plugin_identity')
            self.assertEqual(identity.plugin_id(), 'dyra-native-chrome-verification')
            self.assertNotEqual(identity.daemon_name('same'), candidate.load_sibling('plugin_identity').daemon_name('same'))
            home = Path(directory) / 'shared-home'
            self.assertNotEqual(verification.load_sibling('lifecycle').state_path(home), candidate.load_sibling('lifecycle').state_path(home))
            from browser_harness import _ipc
            self.assertLess(len(os.fsencode(_ipc.sock_addr(identity.daemon_name('same')))), 104)

    def test_adjacent_manifest_identity_ignores_environment_and_global_collision(self):
        plugin = load_root()
        self.assertTrue((ROOT / 'plugin_identity.py').is_file(), 'manifest identity module missing')
        collision = types.ModuleType('plugin_identity')
        collision.plugin_id = lambda: 'foreign'
        with patch.dict(sys.modules, plugin_identity=collision), patch.dict(os.environ,
                DYRA_PLUGIN_ID='foreign', HERMES_PLUGIN_ID='foreign'):
            identity = plugin.load_sibling('plugin_identity')
            self.assertEqual(identity.plugin_id(), PRODUCTION)
            self.assertIs(sys.modules['plugin_identity'], collision)
            with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
                candidate = relocate(directory, 'relocated-candidate', CANDIDATE)
                self.assertEqual(candidate.load_sibling('plugin_identity').plugin_id(), CANDIDATE)

    def test_unknown_or_malformed_manifest_name_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            for index, name in enumerate(('foreign-plugin', '../escape', '', 'dyra-native-chrome-' + 'x' * 200)):
                with self.subTest(name=name):
                    plugin = relocate(directory, 'invalid-' + str(index), name)
                    with self.assertRaisesRegex(ValueError, 'unsupported_plugin_identity'):
                        plugin.load_sibling('plugin_identity').plugin_id()
            for index, text in enumerate(('{}', '[]', 'name: null', 'name: 42', '{broken')):
                with self.subTest(manifest=text):
                    plugin = relocate(directory, 'malformed-' + str(index), PRODUCTION)
                    (Path(plugin.__file__).parent / 'plugin.yaml').write_text(text)
                    with self.assertRaisesRegex(ValueError, 'unsupported_plugin_identity'):
                        plugin.load_sibling('plugin_identity').plugin_id()

    def test_daemon_identity_names_are_bounded_relocatable_and_collision_free(self):
        identity = load_root().load_sibling('plugin_identity')
        self.assertTrue(callable(getattr(identity, 'daemon_name', None)), 'single daemon-name API missing')
        namespace = '["dyra-native-chrome","task","default"]'
        self.assertEqual(identity.harness_prefix(), 'dyra-')
        self.assertEqual(identity.daemon_name(namespace), 'dyra-13df0e443ae09c6ea083')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            relocated = relocate(directory, 'production-copy', PRODUCTION).load_sibling('plugin_identity')
            candidate = relocate(directory, 'candidate-copy', CANDIDATE).load_sibling('plugin_identity')
            self.assertEqual(relocated.daemon_name(namespace), identity.daemon_name(namespace))
            self.assertEqual(candidate.harness_prefix(), '8b000-')
            self.assertNotEqual(candidate.daemon_name(namespace), identity.daemon_name(namespace))
            names = {module.daemon_name(ns) for module in (identity, candidate)
                     for ns in (namespace, '["task","other"]', 'x' * 10000, 'unicode-☃')}
            self.assertEqual(len(names), 8)
            for module in (identity, candidate):
                prefix = module.harness_prefix()
                self.assertLessEqual(len(prefix), 6)
                self.assertRegex(prefix, r'^[a-z0-9]+-$')
                for name in names:
                    self.assertLessEqual(len(name.encode('ascii')), 26)
                    self.assertRegex(name, r'^[a-z0-9]+-[0-9a-f]{20}$')
                    # Exercise the installed path formatter without connecting.
                    from browser_harness import _ipc
                    self.assertLess(len(os.fsencode(_ipc.sock_addr(name))), 104)

    def test_lifecycle_identity_isolated_state_and_reversible_selection(self):
        from test_lifecycle import OfficialCLI
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            production = relocate(directory, 'production', PRODUCTION)
            candidate = relocate(directory, 'candidate', CANDIDATE)
            old = production.load_sibling('lifecycle')
            new = candidate.load_sibling('lifecycle')
            self.assertEqual(new.PLUGIN, CANDIDATE)
            home = Path(directory) / 'shared-home'
            self.assertEqual(old.state_path(home), home / 'plugin-data' / PRODUCTION / 'lifecycle.json')
            self.assertEqual(new.state_path(home), home / 'plugin-data' / CANDIDATE / 'lifecycle.json')
            cli = OfficialCLI(home)
            cli.write({'plugins': {'enabled': [PRODUCTION], 'disabled': [CANDIDATE]},
                       'browser': {'backend': 'browser-use', 'headed': True,
                                   'cdp_url': 'http://127.0.0.1:19347'}})
            old._save(home, {'version': 1, 'desired_enabled': False, 'phase': 'detached',
                             'port': 19347, 'keys': {}})
            original_bytes = old.state_path(home).read_bytes()
            before = cli.read()['browser'].copy()
            self.assertEqual(new.attach(home, runner=cli, exclusive_config=True, port=19348),
                             {'status': 'attached'})
            self.assertIn(['hermes', 'plugins', 'enable', CANDIDATE], cli.calls)
            self.assertTrue(new.desired_enabled(home))
            self.assertFalse(old.desired_enabled(home))
            self.assertEqual(old.state_path(home).read_bytes(), original_bytes)
            self.assertEqual(new.detach(home, runner=cli, exclusive_config=True,
                drain=lambda **kwargs: {'status': 'absent', 'blockers': []}), {'status': 'detached'})
            self.assertEqual(cli.read()['browser'], before)
            self.assertEqual(cli.read()['plugins'], {'enabled': [PRODUCTION], 'disabled': [CANDIDATE]})
            self.assertEqual(old.state_path(home).read_bytes(), original_bytes)
            self.assertFalse(new.desired_enabled(home))
            # Standalone direct loading also resolves the adjacent manifest,
            # even with a foreign generic module occupying sys.modules.
            spec = importlib.util.spec_from_file_location('identity_standalone_lifecycle',
                                                          Path(candidate.__file__).with_name('lifecycle.py'))
            standalone = importlib.util.module_from_spec(spec)
            collision = types.ModuleType('plugin_identity')
            collision.plugin_id = lambda: 'foreign'
            with patch.dict(sys.modules, plugin_identity=collision):
                spec.loader.exec_module(standalone)
            self.assertEqual(standalone.PLUGIN, CANDIDATE)

    def test_middleware_selection_and_runtime_namespace_follow_manifest_only(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            production = relocate(directory, 'production', PRODUCTION)
            candidate = relocate(directory, 'candidate', CANDIDATE)
            home = Path(directory) / 'profile'
            home.mkdir()
            config = home / 'config.yaml'
            config.write_text('plugins:\n  enabled: [dyra-native-chrome]\n')
            self.assertTrue(production.plugin_selected(home))
            self.assertFalse(candidate.plugin_selected(home), 'candidate consumed production selection')
            config.write_text('plugins:\n  enabled: [dyra-native-chrome-candidate]\n')
            self.assertFalse(production.plugin_selected(home))
            self.assertTrue(candidate.plugin_selected(home))
            config.write_text('plugins:\n  enabled: [dyra-native-chrome-candidate]\n  disabled: [dyra-native-chrome-candidate]\n')
            self.assertFalse(candidate.plugin_selected(home))
            observed = []
            class Controller:
                app_helpers_enabled = False
                def acquire_session(self, namespace, *, kind):
                    self.namespace = namespace
                    return {'lease': 'fixture'}
                def prepare_driver(self, admission, name):
                    observed.append((self.namespace, name))
                    return {}
                def release(self, lease): pass
            for plugin, identity in ((production, PRODUCTION), (candidate, CANDIDATE)):
                control = Controller()
                payload = plugin.make_middleware(control)(tool_name='browser_exec',
                    args={'code': 'untouched', 'session': 'default'}, task_id='task', next_call=lambda args: args)
                namespace, name = observed[-1]
                self.assertEqual(namespace, json.dumps([identity, 'task', 'default'], separators=(',', ':')))
                self.assertEqual(name, plugin.load_sibling('plugin_identity').daemon_name(namespace))
                self.assertEqual(payload, {'code': 'untouched', 'session': name})
            self.assertNotEqual(observed[0][0], observed[1][0])
            self.assertNotEqual(observed[0][1], observed[1][1])

    def test_passive_discovery_does_not_import_darwin_only_yaml_dependency(self):
        import subprocess
        code = '''
import builtins, importlib.util
original = builtins.__import__
def deny_yaml(name, *args, **kwargs):
    if name == 'yaml':
        raise AssertionError('Darwin-only dependency imported during discovery')
    return original(name, *args, **kwargs)
builtins.__import__ = deny_yaml
spec = importlib.util.spec_from_file_location('passive_identity_fixture', ROOT / '__init__.py',
                                             submodule_search_locations=[str(ROOT)])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
'''
        result = subprocess.run([sys.executable, '-W', 'error', '-c',
            'from pathlib import Path; ROOT = Path(' + repr(str(ROOT)) + ')\n' + code],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
