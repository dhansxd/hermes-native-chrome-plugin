"""Packaging tests: no Chrome, no installation, no live configuration."""
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_root(root=ROOT, name='packaging_fixture'):
    spec = importlib.util.spec_from_file_location(name, root / '__init__.py', submodule_search_locations=[str(root)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PackagingTests(unittest.TestCase):
    def test_controller_rejects_foreign_listener_and_detaches_without_start(self):
        import io
        import json
        from unittest.mock import Mock
        module = load_root().load_sibling('controller')
        control = module.Controller(home=ROOT / 'profile-a')
        control.opener = Mock()
        control.opener.open.return_value = io.BytesIO(b'{"service":"dyra-native-chrome"}')
        with patch.object(control, 'request', return_value={'service': 'dyra-native-chrome', 'home': str(ROOT / 'profile-b'), 'protocol': 1}), patch.object(control, 'starter') as start:
            with self.assertRaisesRegex(module.ControlFailure, 'profile_conflict'):
                control.ensure()
            start.assert_not_called()
        self.assertTrue(callable(getattr(control, 'detach', None)))
        with patch.object(control, 'health', return_value=False), patch.object(control, 'starter') as start:
            self.assertEqual(control.detach()['status'], 'absent')
            start.assert_not_called()
        with patch.object(control, 'health', return_value=True), patch.object(control, 'request', return_value={'status':'detached'}) as request:
            self.assertEqual(control.detach(timeout=2)['status'], 'detached')
            request.assert_called_once_with('detach', {'timeout': 2})

    def test_passive_controller_uses_lifecycle_port_and_closes_local_generation(self):
        plugin = load_root()
        from unittest.mock import Mock
        instance = Mock()
        instance.app_helpers_enabled = False
        instance.acquire_session.return_value = {'lease': 'owned'}
        ctx = Mock(home=ROOT / 'profile-a')
        callbacks = {}
        ctx.register_middleware.side_effect = lambda kind, callback: callbacks.update(call=callback)
        ctx.on_unload.side_effect = lambda callback: callbacks.update(unload=callback)
        lifecycle = types.SimpleNamespace(desired_enabled=lambda home: True, _read_state=lambda home: {'port': 23456})
        factory = Mock(return_value=instance)
        with patch('platform.system', return_value='Darwin'), patch.object(plugin, 'plugin_selected', return_value=True), patch.object(plugin, 'load_sibling', side_effect=lambda name: lifecycle if name == 'lifecycle' else types.SimpleNamespace(Controller=factory)):
            plugin.register(ctx)
            # Vault dispatch remains off without a previous browser binding. Use
            # preparation failure to exercise instance creation without Chrome.
            instance.prepare_driver.side_effect = RuntimeError('fixture')
            callbacks['call'](tool_name='browser_exec', args={'code':'x'}, task_id='task', next_call=lambda _: self.fail())
            factory.assert_called_once_with(home=(ROOT / 'profile-a').resolve(), port=23456)
            callbacks['unload']()
            instance.close.assert_called_once_with()
            instance.detach.assert_not_called()
            instance.release.assert_called_once_with('owned')

    def test_selection_is_read_per_call_without_hot_reload(self):
        plugin = load_root()
        self.assertTrue(callable(getattr(plugin, 'plugin_selected', None)))
        with tempfile.TemporaryDirectory(dir=Path.home() / '.hermes/cache/scratch') as d:
            home = Path(d)
            self.assertFalse(plugin.plugin_selected(home))
            (home / 'config.yaml').write_text('plugins:\n  enabled: [dyra-native-chrome]\n')
            self.assertTrue(plugin.plugin_selected(home))
            (home / 'config.yaml').write_text('plugins:\n  enabled: [dyra-native-chrome]\n  disabled: [dyra-native-chrome]\n')
            self.assertFalse(plugin.plugin_selected(home))

    def test_corrupt_lifecycle_refuses_browser_instead_of_stale_config_fallback(self):
        import json
        plugin = load_root()
        class Context:
            def __init__(self, home): self.home = home
            def register_middleware(self, kind, callback): self.callback = callback
            def on_unload(self, callback): self.cleanup = callback
        with tempfile.TemporaryDirectory(dir=Path.home() / '.hermes/cache/scratch') as d:
            home = Path(d)
            (home / 'config.yaml').write_text('plugins:\n  enabled: [dyra-native-chrome]\nbrowser:\n  cdp_url: http://127.0.0.1:19347\n')
            journal = plugin.load_sibling('lifecycle').state_path(home)
            journal.parent.mkdir(parents=True)
            journal.write_text('{broken')
            ctx = Context(home)
            with patch('platform.system', return_value='Darwin'):
                plugin.register(ctx)
            for tool in ('browser_exec', 'browser_vault_list'):
                result = ctx.callback(tool_name=tool, args={'code': 'untouched'}, task_id='task',
                    next_call=lambda _: 'unsafe-fallback')
                self.assertNotEqual(result, 'unsafe-fallback')
                self.assertEqual(json.loads(result)['error']['code'], 'lifecycle_invalid')
            self.assertEqual(ctx.callback(tool_name='read_file', args={}, next_call=lambda _: 'unrelated'), 'unrelated')
            self.assertEqual(journal.read_text(), '{broken')
            ctx.cleanup()

    def test_profile_conflict_is_typed_and_never_falls_back(self):
        plugin = load_root()
        module = plugin.load_sibling('controller')
        control = types.SimpleNamespace(acquire_session=lambda *a, **k: (_ for _ in ()).throw(module.ControlFailure('profile_conflict')))
        result = plugin.make_middleware(control)(tool_name='browser_exec', args={'code':'x'}, task_id='task', next_call=lambda _: self.fail('fallback'))
        self.assertIn('profile_conflict', result)

    def test_acquisition_reactivates_own_broker_before_admission(self):
        from unittest.mock import Mock
        module = load_root().load_sibling('controller')
        control = module.Controller(home=ROOT / 'profile-a')
        with patch.object(control, 'ensure'), patch.object(control, 'request', side_effect=[{'status': 'active'}, {'lease': 'fixture'}]) as request:
            self.assertEqual(control.acquire_session('ns'), {'lease':'fixture'})
            self.assertEqual([call.args[0] for call in request.call_args_list], ['activate', 'acquire'])

    def test_child_prefix_and_server_imports_are_relocatable(self):
        plugin = load_root()
        controller = plugin.load_sibling('controller')
        self.assertTrue(callable(getattr(controller, 'bundle_preamble', None)))
        namespace = {}
        collision = types.ModuleType('controller')
        with patch.dict(sys.modules, controller=collision):
            exec(controller.bundle_preamble(), namespace)
        self.assertIs(namespace['Controller'], controller.Controller)
        self.assertIsNot(sys.modules.get('controller'), collision)
        server = plugin.load_sibling('server')
        with patch('platform.system', return_value='Linux'):
            with self.assertRaisesRegex(RuntimeError, 'unsupported_platform'):
                server.make_app(token_file=ROOT / 'must-not-create' / 'token')
        self.assertFalse((ROOT / 'must-not-create').exists())
        with tempfile.TemporaryDirectory(dir=Path.home() / '.hermes/cache/scratch') as d:
            with patch('platform.system', return_value='Darwin'):
                app = server.make_app(home=d)
            self.assertTrue(any(route.resource.canonical == '/control/identity' for route in app.router.routes()))

    def test_controller_state_is_explicit_home_scoped_and_platform_guarded(self):
        module = load_root().load_sibling('controller')
        import inspect
        self.assertIn('home', inspect.signature(module.Controller).parameters)
        home = ROOT / 'test-home-not-created'
        control = module.Controller(home=home)
        self.assertEqual(control.token_file, home / 'plugin-data/dyra-native-chrome/control-token')
        with patch('platform.system', return_value='Linux'), patch.object(module.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(module.ControlFailure, 'unsupported_platform'):
                control.start()
            spawn.assert_not_called()
        with patch.object(control, 'request', side_effect=AssertionError('no global cleanup')):
            control.close()
        self.assertTrue(control.closed)
        with self.assertRaisesRegex(module.ControlFailure, 'detached'):
            control.acquire_session('later')

    def test_passive_registration_gates_each_call_and_unloads_locally(self):
        plugin = load_root()
        class Context:
            home = ROOT / 'unused-home'
            def register_middleware(self, kind, callback): self.callback = callback
            def on_unload(self, callback): self.cleanup = callback
        class FakeController:
            instances = []
            def __init__(self, **kwargs):
                self.kwargs = kwargs; self.closed = False; self.instances.append(self)
            def acquire_session(self, *a, **k): raise AssertionError('no admission expected')
            def close(self): self.closed = True
        state = {'enabled': False}
        lifecycle = types.SimpleNamespace(desired_enabled=lambda home: state['enabled'])
        original = plugin.load_sibling
        def sibling(name):
            if name == 'lifecycle': return lifecycle
            if name == 'controller': return types.SimpleNamespace(Controller=FakeController)
            return original(name)
        ctx = Context()
        with patch.object(plugin, 'load_sibling', side_effect=sibling), patch.object(plugin, 'plugin_selected', return_value=True), patch('platform.system', return_value='Darwin'):
            plugin.register(ctx)
            self.assertEqual(FakeController.instances, [])
            self.assertTrue(hasattr(ctx, 'cleanup'), 'unload registration missing')
            args = {'code': 'untouched', 'session': 'bad space'}
            calls = []
            for tool in ('browser_exec', 'browser_vault_list'):
                self.assertEqual(ctx.callback(tool_name=tool, args=args, next_call=lambda value: calls.append(value) or 'native'), 'native')
            self.assertEqual(calls, [args, args])
            self.assertTrue(all(value is args for value in calls))
            state['enabled'] = True
            self.assertIn('missing_session_identity', ctx.callback(tool_name='browser_exec', args=args, next_call=lambda _: self.fail()))
            ctx.cleanup()
            self.assertEqual(FakeController.instances, [])
            self.assertEqual(ctx.callback(tool_name='browser_exec', args=args, next_call=lambda _: 'retired'), 'retired')
        unsupported = Context()
        with patch('platform.system', return_value='Linux'):
            plugin.register(unsupported)
        self.assertFalse(hasattr(unsupported, 'callback'))

    def test_relocated_siblings_ignore_global_module_collisions(self):
        with tempfile.TemporaryDirectory(dir=Path.home() / '.hermes/cache/scratch') as directory:
            root = Path(directory) / 'relocated'
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns('__pycache__', 'tests'))
            plugin = load_root(root, 'relocated_fixture')
            collision = types.ModuleType('native')
            with patch.dict(sys.modules, native=collision):
                self.assertTrue(callable(getattr(plugin, 'load_sibling', None)), 'standalone sibling loader missing')
                broker = plugin.load_sibling('broker')
                native = plugin.load_sibling('native')
                self.assertIs(broker.NativeFailure, native.NativeFailure)
                self.assertIs(sys.modules['native'], collision)
                self.assertEqual(Path(native.__file__).parent, root)
                self.assertTrue(plugin.load_sibling('app_launch').VerifiedApp)


class DrainTests(unittest.IsolatedAsyncioTestCase):
    async def test_fake_official_cli_real_http_default_drain_and_reattach(self):
        import asyncio
        import json
        from aiohttp import ClientSession
        from aiohttp.test_utils import TestServer
        from test_lifecycle import OfficialCLI
        plugin = load_root()
        lifecycle = plugin.load_sibling('lifecycle')
        server = plugin.load_sibling('server')
        with tempfile.TemporaryDirectory(dir=Path.home() / '.hermes/cache/scratch') as d:
            home = Path(d).resolve()
            cli = OfficialCLI(home)
            cli.write({'browser': {'backend': 'local', 'headed': False},
                       'plugins': {'enabled': ['other'], 'disabled': [lifecycle.PLUGIN]}})
            with patch('platform.system', return_value='Darwin'):
                app = server.make_app(home=home)
            with patch.object(lifecycle, '_no_start', side_effect=AssertionError('must never start')) as start:
                async with TestServer(app, host='127.0.0.1') as endpoint:
                    result = await asyncio.to_thread(lifecycle.attach, home, runner=cli,
                        exclusive_config=True, port=endpoint.port)
                    self.assertEqual(result, {'status': 'attached'})
                    self.assertTrue(plugin.plugin_selected(home))
                    cli(['hermes', 'plugins', 'disable', lifecycle.PLUGIN], env={'HERMES_HOME': str(home)})
                    self.assertFalse(plugin.plugin_selected(home))
                    await asyncio.to_thread(lifecycle.attach, home, runner=cli,
                        exclusive_config=True, port=endpoint.port)
                    self.assertTrue(plugin.plugin_selected(home))
                    self.assertEqual((await asyncio.to_thread(lifecycle.detach, home,
                        runner=cli, exclusive_config=True)), {'status': 'detached'})
                    self.assertFalse(lifecycle.desired_enabled(home))
                    self.assertFalse(plugin.plugin_selected(home))
                    self.assertEqual(cli.read()['browser'], {'backend': 'local', 'headed': False})
                    self.assertEqual(cli.read()['plugins'], {'enabled': ['other'],
                        'disabled': [lifecycle.PLUGIN]})
                    # Drain revokes admission but does not terminate the broker.
                    async with ClientSession() as client:
                        async with client.get(endpoint.make_url('/health')) as response:
                            self.assertEqual(response.status, 200)
                        async with client.post(endpoint.make_url('/control/detach'), json={}) as response:
                            self.assertEqual(response.status, 401)
                    port = endpoint.port
                # Real connection refusal is absence, never a start request.
                self.assertEqual(await asyncio.to_thread(lifecycle.default_drain,
                    home=home, port=port), {'status': 'absent', 'blockers': []})
                start.assert_not_called()

    async def test_loopback_authenticated_lifecycle_and_bound_lock(self):
        import asyncio
        import json
        import time
        from aiohttp import ClientSession
        from aiohttp.test_utils import TestServer
        plugin = load_root()
        server = plugin.load_sibling('server')
        lifecycle = plugin.load_sibling('lifecycle')
        controller = plugin.load_sibling('controller')
        with tempfile.TemporaryDirectory(dir=Path.home() / '.hermes/cache/scratch') as home:
            with patch('platform.system', return_value='Darwin'):
                app = server.make_app(home=home)
            async with TestServer(app, host='127.0.0.1') as endpoint:
                control = controller.Controller(home=home, port=endpoint.port)
                self.assertTrue(await asyncio.to_thread(control.health))
                async with ClientSession() as client:
                    async with client.post(endpoint.make_url('/control/detach'), json={'timeout': 0}) as response:
                        self.assertEqual(response.status, 401)
                    async with client.post(endpoint.make_url('/control/acquire'), json={'namespace': 'unused'}) as response:
                        self.assertEqual(response.status, 409)
                self.assertEqual((await asyncio.to_thread(control.detach, timeout=0))['status'], 'detached')
                with patch.object(lifecycle, 'desired_enabled', return_value=True):
                    self.assertEqual((await asyncio.to_thread(control.request, 'activate', {}))['status'], 'active')
        broker = plugin.load_sibling('broker').SessionBroker(object(), control_token='fixture')
        class Request:
            headers = {'Authorization': 'Bearer fixture'}
            async def json(self): return {'timeout': .01}
        await broker.lock.acquire()
        try:
            start = time.monotonic()
            result = json.loads((await broker.detach(Request())).text)
            self.assertLess(time.monotonic() - start, .25)
            self.assertEqual(result, {'status': 'blocked', 'blockers': ['pending_operations']})
        finally:
            broker.lock.release()

    async def test_authenticated_drain_preserves_work_and_revokes_only_when_quiet(self):
        import asyncio
        import json
        from aiohttp import web
        module = load_root().load_sibling('broker')
        broker = module.SessionBroker(object(), control_token='fixture')
        self.assertTrue(callable(getattr(broker, 'detach', None)))
        class Request:
            headers = {'Authorization': 'Bearer fixture'}
            async def json(self): return {'timeout': 0}
        unauthorized = Request(); unauthorized.headers = {}
        with self.assertRaises(web.HTTPUnauthorized):
            await broker.detach(unauthorized)
        scope = module.SessionScope(broker.transport, 'task', control_token='fixture')
        broker.scopes['task'] = scope
        scope.leases['lease'] = 'task'; broker.leases['lease'] = (scope, 'browser')
        scope.capability = 'old'; scope.downloads.add('download')
        body = json.loads((await broker.detach(Request())).text)
        self.assertEqual(body['status'], 'blocked')
        self.assertIn('active_calls', body['blockers'])
        self.assertIn('transfers', body['blockers'])
        self.assertIn('lease', scope.leases)
        self.assertIn('download', scope.downloads)
        self.assertEqual(scope.capability, 'old')
        class Admission(Request):
            async def json(self): return {'namespace': 'new'}
        response = await broker.acquire(Admission())
        self.assertEqual(response.status, 409)
        broker.leases.clear(); scope.leases.clear(); scope.downloads.clear()
        from unittest.mock import AsyncMock
        websocket = AsyncMock()
        scope.clients[websocket] = {'session': 'bound'}
        scope.client_capabilities[websocket] = 'old'
        scope.targets.add('preserved'); scope.preserve = True
        body = json.loads((await broker.detach(Request())).text)
        self.assertEqual(body['status'], 'detached')
        self.assertIsNone(scope.capability)
        websocket.close.assert_awaited_once()
        self.assertEqual(scope.targets, {'preserved'})
        self.assertTrue(scope.preserve)
        self.assertTrue(callable(getattr(broker, 'activate', None)))
        await broker.activate(Request())
        self.assertFalse(broker.draining)
        self.assertTrue(scope.capability)
        self.assertNotEqual(scope.capability, 'old')


if __name__ == '__main__':
    unittest.main()
