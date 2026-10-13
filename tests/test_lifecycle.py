"""Lifecycle tests use temporary profiles and injected official CLI effects only."""
import importlib.util
import json
from pathlib import Path

import tempfile
import unittest
from unittest.mock import patch
import yaml

SOURCE = Path(__file__).resolve().parents[1] / 'lifecycle.py'


def load():
    assert SOURCE.exists(), 'standalone lifecycle API is missing'
    spec = importlib.util.spec_from_file_location('lifecycle_under_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OfficialCLI:
    """Filesystem effects of the public CLI, never invokes live Hermes."""
    def __init__(self, home):
        self.home = home
        self.calls = []
        self.observer = None
        self.fail_after = None

    def read(self):
        path = self.home / 'config.yaml'
        return yaml.safe_load(path.read_text()) if path.exists() else {}

    def write(self, value):
        self.home.mkdir(parents=True, exist_ok=True)
        (self.home / 'config.yaml').write_text(yaml.safe_dump(value))

    def __call__(self, argv, *, env):
        assert env['HERMES_HOME'] == str(self.home)
        assert argv[0] == 'hermes'
        if self.observer:
            self.observer(argv)
        self.calls.append(argv)
        config = self.read()
        if argv[1] == 'config':
            action, key = argv[2:4]
            section, leaf = key.split('.')
            if action == 'set':
                value = argv[4] if key in {'browser.backend', 'browser.cdp_url'} else json.loads(argv[4])
                config.setdefault(section, {})[leaf] = value
            else:
                config.get(section, {}).pop(leaf, None)
        else:
            assert argv[1:3] in (['plugins', 'enable'], ['plugins', 'disable'])
            plugins = config.setdefault('plugins', {})
            selected, excluded = plugins.setdefault('enabled', []), plugins.setdefault('disabled', [])
            if argv[2] == 'enable':
                if argv[3] not in selected:
                    selected.append(argv[3])
                if argv[3] in excluded:
                    excluded.remove(argv[3])
            else:
                if argv[3] in selected:
                    selected.remove(argv[3])
                if argv[3] not in excluded:
                    excluded.append(argv[3])
        self.write(config)
        if self.fail_after == len(self.calls):
            raise OSError('injected post-effect crash')


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve() / 'profile'

    def test_attach_commits_intent_after_official_effects_and_preserves_baseline(self):
        module = load()
        self.assertTrue(hasattr(module, 'attach'), 'attach API missing')
        cli = OfficialCLI(self.home)
        cli.write({'browser': {'backend': 'local', 'headed': False, 'allow_private_urls': False}})
        cli.observer = lambda argv: self.assertFalse(module.desired_enabled(self.home))
        result = module.attach(self.home, runner=cli, exclusive_config=True)
        self.assertEqual(result['status'], 'attached')
        self.assertTrue(module.desired_enabled(self.home))
        self.assertEqual(cli.calls[0], ['hermes', 'plugins', 'enable', 'dyra-native-chrome'])
        self.assertEqual(cli.read()['browser'], {'backend': 'browser-use', 'headed': True,
                         'allow_private_urls': False, 'cdp_url': 'http://127.0.0.1:19347'})
        journal = json.loads(module.state_path(self.home).read_text())
        self.assertEqual(journal['keys']['browser.backend']['before'], {'present': True, 'value': 'local'})
        self.assertEqual(journal['keys']['browser.cdp_url']['before'], {'present': False})
        calls = len(cli.calls)
        module.attach(self.home, runner=cli, exclusive_config=True)
        self.assertEqual(len(cli.calls), calls)
        self.assertEqual(json.loads(module.state_path(self.home).read_text()), journal)

    def test_exit_zero_enable_without_effect_never_commits(self):
        import subprocess
        module = load()
        for selection in ({}, {'enabled': [module.PLUGIN], 'disabled': [module.PLUGIN]}):
            with self.subTest(selection=selection):
                home = self.home / str(len(selection))
                cli = OfficialCLI(home)
                cli.write({'plugins': selection})
                def rejected(argv, *, env):
                    if argv[1:3] == ['plugins', 'enable']:
                        return subprocess.CompletedProcess(argv, 0, stdout='Plugin rejected')
                    return cli(argv, env=env)
                with self.assertRaisesRegex(module.LifecycleError, 'plugin_enable_unverified'):
                    module.attach(home, runner=rejected, exclusive_config=True)
                self.assertFalse(module.desired_enabled(home))
                self.assertNotIn('browser', cli.read())

    def test_reattach_after_bare_disable_rechecks_selection(self):
        module = load()
        cli = OfficialCLI(self.home)
        module.attach(self.home, runner=cli, exclusive_config=True)
        baseline = module.state_path(self.home).read_text()
        cli(['hermes', 'plugins', 'disable', module.PLUGIN], env={'HERMES_HOME': str(self.home)})
        self.assertEqual(module.attach(self.home, runner=cli, exclusive_config=True)['status'], 'attached')
        self.assertIn(module.PLUGIN, cli.read()['plugins']['enabled'])
        self.assertNotIn(module.PLUGIN, cli.read()['plugins']['disabled'])
        self.assertEqual(module.state_path(self.home).read_text(), baseline)

    def test_idempotent_attach_refuses_user_config_edits(self):
        module = load()
        for disabled in (False, True):
            with self.subTest(disabled=disabled):
                home = self.home / str(disabled)
                cli = OfficialCLI(home)
                module.attach(home, runner=cli, exclusive_config=True)
                if disabled:
                    cli(['hermes', 'plugins', 'disable', module.PLUGIN], env={'HERMES_HOME': str(home)})
                config = cli.read()
                config['browser']['backend'] = 'user-choice'
                cli.write(config)
                count = len(cli.calls)
                with self.assertRaisesRegex(module.LifecycleError, 'config_conflict'):
                    module.attach(home, runner=cli, exclusive_config=True)
                self.assertEqual(len(cli.calls), count)
                self.assertEqual(cli.read(), config)

    def test_attach_final_readback_before_commit(self):
        module = load()
        for drift in ('selection', 'earlier_key'):
            with self.subTest(drift=drift):
                home = self.home / drift
                cli = OfficialCLI(home)
                def changing(argv, *, env):
                    cli(argv, env=env)
                    if argv[1:4] == ['config', 'set', 'browser.headed']:
                        config = cli.read()
                        if drift == 'selection':
                            config['plugins']['disabled'] = [module.PLUGIN]
                        else:
                            config['browser']['backend'] = 'user-choice'
                        cli.write(config)
                expected = 'plugin_enable_unverified' if drift == 'selection' else 'config_write_unverified'
                with self.assertRaisesRegex(module.LifecycleError, expected):
                    module.attach(home, runner=changing, exclusive_config=True)
                self.assertFalse(module.desired_enabled(home))

    def test_exit_zero_disable_without_effect_keeps_detach_pending(self):
        import subprocess
        module = load()
        cli = OfficialCLI(self.home)
        module.attach(self.home, runner=cli, exclusive_config=True)
        def rejected(argv, *, env):
            if argv[1:3] == ['plugins', 'disable']:
                return subprocess.CompletedProcess(argv, 0, stdout='Disable rejected')
            return cli(argv, env=env)
        with self.assertRaisesRegex(module.LifecycleError, 'plugin_disable_unverified'):
            module.detach(self.home, runner=rejected, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)
        self.assertFalse(module.desired_enabled(self.home))
        self.assertEqual(module.status(self.home)['status'], 'detaching')
        self.assertEqual(module.detach(self.home, runner=cli, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)['status'], 'detached')

    def test_idempotent_detach_rechecks_disable_effect(self):
        module = load()
        cli = OfficialCLI(self.home)
        module.attach(self.home, runner=cli, exclusive_config=True)
        module.detach(self.home, runner=cli, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)
        cli(['hermes', 'plugins', 'enable', module.PLUGIN], env={'HERMES_HOME': str(self.home)})
        module.detach(self.home, runner=cli, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)
        self.assertNotIn(module.PLUGIN, cli.read()['plugins']['enabled'])
        self.assertIn(module.PLUGIN, cli.read()['plugins']['disabled'])

    def test_detach_revokes_before_drain_and_preserves_user_changes(self):
        module = load()
        self.assertTrue(hasattr(module, 'detach'), 'detach API missing')
        cli = OfficialCLI(self.home)
        cli.write({'browser': {'backend': 'local', 'headed': False}})
        module.attach(self.home, runner=cli, exclusive_config=True)
        current = cli.read()
        current['browser']['backend'] = 'user-choice'
        cli.write(current)
        count = len(cli.calls)
        def drain(**kwargs):
            self.assertEqual(kwargs, {'home': self.home, 'port': 19347})
            self.assertFalse(module.desired_enabled(self.home))
            self.assertEqual(len(cli.calls), count)
            return {'status': 'draining', 'blockers': ['active_operations']}
        result = module.detach(self.home, runner=cli, drain=drain, exclusive_config=True)
        self.assertEqual(result['status'], 'draining')
        self.assertEqual(len(cli.calls), count)
        result = module.detach(self.home, runner=cli, drain=lambda **kw: {'status': 'detached'}, exclusive_config=True)
        self.assertEqual(result['status'], 'detached')
        self.assertEqual(cli.read()['browser'], {'backend': 'user-choice', 'headed': False})
        self.assertEqual(cli.calls[-1], ['hermes', 'plugins', 'disable', 'dyra-native-chrome'])
        count = len(cli.calls)
        module.detach(self.home, runner=cli, drain=lambda **kw: self.fail('repeat drain'), exclusive_config=True)
        self.assertEqual(len(cli.calls), count)

    def test_malformed_selection_refuses_before_official_writes(self):
        module = load()
        for selection in ('scalar', {'enabled': 'dyra-native-chrome'}, {'disabled': [True]}):
            with self.subTest(selection=selection):
                cli = OfficialCLI(self.home)
                cli.write({'plugins': selection})
                def rejected(argv, *, env):
                    cli.calls.append(argv)  # Official parser rejects malformed selection without effects.
                with self.assertRaisesRegex(module.LifecycleError, 'config_invalid'):
                    module.attach(self.home, runner=rejected, exclusive_config=True)
                self.assertEqual(cli.calls, [])
                self.assertFalse(module.state_path(self.home).exists())

    def test_mutation_preconditions_fail_closed_without_writes(self):
        module = load()
        self.assertTrue(hasattr(module, 'LifecycleError'), 'typed errors missing')
        cli = OfficialCLI(self.home)
        with patch.object(module.sys, 'platform', 'linux'):
            with self.assertRaisesRegex(module.LifecycleError, 'unsupported_platform'):
                module.attach(self.home, runner=cli, exclusive_config=True)
        self.assertFalse(self.home.exists())
        with self.assertRaisesRegex(module.LifecycleError, 'exclusive_config_required'):
            module.attach(self.home, runner=cli)
        self.assertFalse(self.home.exists())
        cli.write({'browser': {'cdp_url': 'http://127.0.0.1:19347'}})
        with self.assertRaisesRegex(module.LifecycleError, 'ambiguous_baseline'):
            module.attach(self.home, runner=cli, exclusive_config=True)
        self.assertEqual(cli.calls, [])
        self.assertFalse(module.state_path(self.home).exists())

    def test_attach_recovers_crash_without_overwriting_intervening_changes(self):
        module = load()
        cli = OfficialCLI(self.home)
        cli.write({'browser': {'backend': 'old', 'headed': False}})
        cli.fail_after = 2  # backend effect landed, acknowledgment lost
        with self.assertRaises(Exception):
            module.attach(self.home, runner=cli, exclusive_config=True)
        self.assertFalse(module.desired_enabled(self.home))
        baseline = json.loads(module.state_path(self.home).read_text())['keys']
        config = cli.read()
        config['browser']['backend'] = 'intervening-user-value'
        cli.write(config)
        cli.fail_after = None
        with self.assertRaisesRegex(module.LifecycleError, 'config_conflict'):
            module.attach(self.home, runner=cli, exclusive_config=True)
        self.assertEqual(cli.read()['browser']['backend'], 'intervening-user-value')
        module.detach(self.home, runner=cli, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)
        self.assertEqual(cli.read()['browser'], {'backend': 'intervening-user-value', 'headed': False})
        self.assertEqual(json.loads(module.state_path(self.home).read_text())['keys']['browser.backend']['before'],
                         baseline['browser.backend']['before'])
        module.attach(self.home, runner=cli, exclusive_config=True)
        journal = json.loads(module.state_path(self.home).read_text())
        self.assertEqual(journal['keys']['browser.backend']['before']['value'], 'intervening-user-value')

    def test_verify_effects_and_type_sensitive_restore(self):
        module = load()
        cli = OfficialCLI(self.home)
        def no_config_effect(argv, *, env):
            if argv[1] == 'plugins':
                return cli(argv, env=env)
        with self.assertRaisesRegex(module.LifecycleError, 'config_write_unverified'):
            module.attach(self.home, runner=no_config_effect, exclusive_config=True)
        self.assertFalse(module.desired_enabled(self.home))
        module.attach(self.home, runner=cli, exclusive_config=True)
        config = cli.read()
        config['browser']['headed'] = 1  # bool True != user-written integer 1
        cli.write(config)
        module.detach(self.home, runner=cli, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)
        self.assertEqual(cli.read()['browser'], {'headed': 1})
        self.assertIs(type(cli.read()['browser']['headed']), int)

    def test_corrupt_journal_and_config_never_mutate(self):
        module = load()
        cli = OfficialCLI(self.home)
        path = module.state_path(self.home)
        path.parent.mkdir(parents=True)
        for value in ('{bad', '[]', '{"desired_enabled":true,"phase":"attached"}'):
            path.write_text(value)
            with self.assertRaisesRegex(module.LifecycleError, 'journal_invalid'):
                module.desired_enabled(self.home)
            with self.assertRaisesRegex(module.LifecycleError, 'journal_invalid'):
                module.detach(self.home, runner=cli, exclusive_config=True)
            self.assertEqual(path.read_text(), value)
        path.unlink()
        for value in ('[]', 'browser: scalar', '{bad'):
            (self.home / 'config.yaml').write_text(value)
            with self.assertRaisesRegex(module.LifecycleError, 'config_invalid'):
                module.attach(self.home, runner=cli, exclusive_config=True)
            self.assertFalse(path.exists())
        self.assertEqual(cli.calls, [])

    def test_lifecycle_lock_serializes_operations_and_releases_on_failure(self):
        module = load()
        cli = OfficialCLI(self.home)
        attempted = []
        def observe(argv):
            if attempted:
                return
            attempted.append(True)
            with self.assertRaisesRegex(module.LifecycleError, 'operation_busy'):
                module.detach(self.home, runner=cli, drain=lambda **kw: {'status': 'draining'}, exclusive_config=True)
        cli.observer = observe
        module.attach(self.home, runner=cli, exclusive_config=True)
        self.assertEqual(attempted, [True])
        module.detach(self.home, runner=cli, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)
        self.assertFalse(module.desired_enabled(self.home))

    def test_cli_status_errors_and_official_runner_without_runtime(self):
        module = load()
        self.assertTrue(hasattr(module, 'main'), 'CLI missing')
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            code = module.main(['--home', str(self.home), 'status'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), {'status': 'unattached', 'desired_enabled': False})
        self.assertFalse(self.home.exists())
        out = io.StringIO()
        with redirect_stdout(out):
            code = module.main(['--home', str(self.home), 'attach'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())['error']['code'], 'exclusive_config_required')
        cli = OfficialCLI(self.home)
        with patch.object(module.subprocess, 'run') as run:
            run.side_effect = lambda argv, **kw: (cli(argv, env=kw['env']), type('Result', (), {'returncode': 0})())[1]
            module.attach(self.home, exclusive_config=True)
        self.assertTrue(module.desired_enabled(self.home))
        self.assertFalse(any(name == 'hermes_cli' or name.startswith('hermes_cli.') for name in module.sys.modules))

    def test_default_drain_uses_local_controller_without_start_or_runtime(self):
        module = load()
        self.assertTrue(hasattr(module, '_controller_class'), 'offline controller seam missing')
        cli = OfficialCLI(self.home)
        module.attach(self.home, runner=cli, exclusive_config=True)
        seen = []
        class FakeController:
            def __init__(inner, **kwargs):
                seen.append(kwargs)
            def detach(inner):
                self.assertFalse(module.desired_enabled(self.home))
                return {'status': 'detached', 'blockers': []}
        with patch.object(module, '_controller_class', return_value=FakeController):
            self.assertEqual(module.detach(self.home, runner=cli, exclusive_config=True)['status'], 'detached')
        self.assertEqual(seen[0]['home'], self.home)
        self.assertEqual(seen[0]['token_file'], module.state_path(self.home).parent / 'control-token')
        with self.assertRaisesRegex(module.LifecycleError, 'broker_start_forbidden'):
            seen[0]['starter']()
        cls = module._controller_class()
        self.assertEqual(cls.__name__, 'Controller')
        self.assertFalse(any(name == 'hermes_cli' or name.startswith('hermes_cli.') for name in module.sys.modules))

    def test_port_change_requires_detach_and_invalid_ports_never_commit(self):
        module = load()
        cli = OfficialCLI(self.home)
        for port in (0, 65536, True, 'bad'):
            with self.assertRaisesRegex(module.LifecycleError, 'invalid_port'):
                module.attach(self.home, runner=cli, exclusive_config=True, port=port)
            self.assertFalse(module.state_path(self.home).exists())
        module.attach(self.home, runner=cli, exclusive_config=True)
        with self.assertRaisesRegex(module.LifecycleError, 'port_conflict'):
            module.attach(self.home, runner=cli, exclusive_config=True, port=19348)
        self.assertTrue(module.desired_enabled(self.home))

    def test_detached_reply_with_blockers_cannot_restore(self):
        module = load()
        cli = OfficialCLI(self.home)
        module.attach(self.home, runner=cli, exclusive_config=True)
        count = len(cli.calls)
        result = module.detach(self.home, runner=cli,
            drain=lambda **kw: {'status': 'detached', 'blockers': ['active_operations']}, exclusive_config=True)
        self.assertEqual(result['status'], 'draining')
        self.assertEqual(len(cli.calls), count)
        self.assertFalse(module.desired_enabled(self.home))

    def test_crash_recovery_matrix_and_raw_null_restoration(self):
        # Characterization of recovery seams already built from earlier REDs.
        module = load()
        for crash in range(1, 5):
            with self.subTest(crash=crash):
                home = self.home / str(crash)
                cli = OfficialCLI(home)
                cli.write({'browser': {'headed': None}, 'other': {'keep': 4}})
                cli.fail_after = crash
                with self.assertRaises(module.LifecycleError):
                    module.attach(home, runner=cli, exclusive_config=True)
                self.assertFalse(module.desired_enabled(home))
                cli.fail_after = None
                module.attach(home, runner=cli, exclusive_config=True)
                self.assertTrue(module.desired_enabled(home))
                cli.fail_after = len(cli.calls) + 2
                with self.assertRaises(module.LifecycleError):
                    module.detach(home, runner=cli, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)
                self.assertFalse(module.desired_enabled(home))
                cli.fail_after = None
                module.detach(home, runner=cli, drain=lambda **kw: {'status': 'absent'}, exclusive_config=True)
                self.assertEqual(cli.read()['browser'], {'headed': None})
                self.assertEqual(cli.read()['other'], {'keep': 4})

    def test_controller_absence_and_wrong_service_are_not_conflated(self):
        # No real socket or process is touched: exercise local controller branches.
        module = load()
        cls = module._controller_class()
        import errno
        import urllib.error
        with patch.object(module, '_controller_class', return_value=cls):
            with patch('urllib.request.OpenerDirector.open', side_effect=urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, 'refused'))):
                self.assertEqual(module.default_drain(home=self.home, port=19347)['status'], 'absent')
            import io
            with patch('urllib.request.OpenerDirector.open', return_value=io.BytesIO(b'{"service":"other"}')):
                with self.assertRaisesRegex(module.LifecycleError, 'drain_failed'):
                    module.default_drain(home=self.home, port=19347)

    def test_cli_structures_exit_zero_rejection_as_verification_error(self):
        import io
        import subprocess
        from contextlib import redirect_stdout
        module = load()
        cli = OfficialCLI(self.home)
        cli.write({'plugins': {'enabled': [], 'disabled': [module.PLUGIN]}})
        def rejected(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout='Enable rejected', stderr='')
        out = io.StringIO()
        with patch.object(module.subprocess, 'run', side_effect=rejected), redirect_stdout(out):
            code = module.main(['--home', str(self.home), '--exclusive-config', 'attach'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue()), {'status': 'error',
            'error': {'code': 'plugin_enable_unverified'}})
        self.assertFalse(module.desired_enabled(self.home))

    def test_standalone_controller_import_and_real_absence_never_starts(self):
        # Characterization: the existing real import is already standalone-safe.
        import socket
        import subprocess
        import sys
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        code = (
            'import importlib.util,json,sys; '
            f'spec=importlib.util.spec_from_file_location("isolated_lifecycle", {str(SOURCE)!r}); '
            'module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); '
            'assert module._controller_class().__name__ == "Controller"; '
            f'result=module.default_drain(home={str(self.home)!r}, port={port}); '
            'assert not any(n == "hermes_cli" or n.startswith("hermes_cli.") for n in sys.modules); '
            'print(json.dumps(result))')
        result = subprocess.run([sys.executable, '-c', code], capture_output=True,
                                text=True, check=True, cwd=self.temp.name)
        self.assertEqual(json.loads(result.stdout), {'status': 'absent', 'blockers': []})
        self.assertEqual(result.stderr, '')
        self.assertFalse(self.home.exists())

    def test_standalone_script_status_uses_only_temporary_profile(self):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, str(SOURCE), '--home', str(self.home), 'status'],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), {'status': 'unattached', 'desired_enabled': False})
        self.assertEqual(result.stderr, '')
        self.assertFalse(self.home.exists())

    def test_passive_intent_has_no_filesystem_side_effects(self):
        module = load()
        with patch.dict('os.environ', {'HERMES_HOME': str(self.home)}):
            self.assertFalse(module.desired_enabled())
        self.assertFalse(module.desired_enabled(self.home))
        self.assertFalse(self.home.exists())
        path = self.home / 'plugin-data/dyra-native-chrome/lifecycle.json'
        path.parent.mkdir(parents=True)
        path.write_text('{broken')
        with self.assertRaisesRegex(module.LifecycleError, 'journal_invalid'):
            module.desired_enabled(self.home)


if __name__ == '__main__':
    unittest.main()
