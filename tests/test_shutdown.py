"""Real child/HTTP shutdown QA. No Chrome, signals, or live profile state."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path.home() / '.hermes/cache/scratch'


def load(name):
    spec = importlib.util.spec_from_file_location('_shutdown_bundle', ROOT / '__init__.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_sibling(name)


class ChildShutdownTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='shutdown-qa-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        lifecycle = load('lifecycle')
        lifecycle._save(self.home, {'version': 1, 'desired_enabled': False,
            'phase': 'detaching', 'port': self.port, 'keys': {}})
        # Reuse the effective parent's dependency paths; no installs/bootstrap.
        code = f'''
import sys, asyncio, inspect
sys.path[:] = {sys.path!r}
import importlib.util
from aiohttp import web
spec = importlib.util.spec_from_file_location('_shutdown_server', {str(ROOT / 'server.py')!r})
server = importlib.util.module_from_spec(spec); spec.loader.exec_module(server)
async def run():
    stop = asyncio.Event()
    kwargs = {{'home': {str(self.home)!r}, 'port': {self.port}}}
    if 'stop_event' in inspect.signature(server.make_app).parameters:
        kwargs['stop_event'] = stop
    app = server.make_app(**kwargs)
    broker = next(route.handler.__self__ for route in app.router.routes()
                  if route.resource.canonical == '/control/detach')
    async def fixture(request):
        broker.authorize(request)
        data = await request.json()
        scope = broker.scopes.get('fixture')
        if scope is None:
            scope = server.load('broker').SessionScope(broker.transport, 'fixture', control_token=broker.control_token)
            broker.scopes['fixture'] = scope
        broker.transport.pending.clear()
        broker.leases.clear(); scope.leases.clear(); scope.recovery_guards.clear()
        if data.get('mode') == 'pending':
            broker.transport.pending[1] = asyncio.get_running_loop().create_future()
        if data.get('mode') == 'busy':
            scope.recovery_guards['busy'] = True
        if data.get('mode') == 'lease':
            scope.leases['fixture'] = 'fixture'
            broker.leases['fixture'] = (scope, 'browser')
        return web.json_response({{'ok': True}})
    app.router.add_post('/control/fixture', fixture)
    runner = web.AppRunner(app, access_log=None, shutdown_timeout=1)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', {self.port}).start()
    print('ready', flush=True)
    loop = asyncio.get_running_loop()
    loop.add_reader(sys.stdin.fileno(), stop.set)
    try:
        await stop.wait()
    finally:
        loop.remove_reader(sys.stdin.fileno())
        await runner.cleanup()
asyncio.run(run())
'''
        self.child = subprocess.Popen([sys.executable, '-Werror', '-c', code],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env={**os.environ, 'HERMES_HOME': str(self.home)}, cwd=self.home)
        self.addCleanup(self.finish_child)
        ready, _, _ = select.select([self.child.stdout], [], [], 10)
        self.assertTrue(ready, 'child readiness timeout')
        self.assertEqual(self.child.stdout.readline().strip(), 'ready')
        self.control = load('controller').Controller(home=self.home, port=self.port,
            starter=lambda: self.fail('must never start a broker'))
        self.assertTrue(self.control.health())

    def finish_child(self):
        if self.child.poll() is None:
            self.child.stdin.write('\n'); self.child.stdin.flush()
        out, err = self.child.communicate(timeout=10)
        self.assertEqual(self.child.returncode, 0, err)
        self.assertEqual(err, '')

    def test_busy_guard_refuses_drain_and_stop_even_after_prior_tombstone(self):
        drained = self.control.detach(timeout=0)
        self.control.request('fixture', {'mode': 'busy'})
        result = self.control.detach(timeout=0)
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('pending_operations', result['blockers'])
        self.assert_http(409, 'stop', {'home': str(self.home), 'drain_id': drained['drain_id']})
        self.assertTrue(self.control.health())
        self.control.request('fixture', {'mode': 'quiet'})

    def test_auth_home_tombstone_and_explicit_intent_gates_keep_child_alive(self):
        self.assert_http(409, 'stop', {'home': str(self.home), 'drain_id': 'no-drain'})
        drained = self.control.detach(timeout=0)
        payload = {'home': str(self.home), 'drain_id': drained['drain_id']}
        self.assert_http(401, 'stop', payload, token='wrong')
        self.assert_http(403, 'stop', {**payload, 'home': str(self.home / 'other')})
        self.assert_http(409, 'stop', {**payload, 'drain_id': 'wrong'})
        wrong = load('controller').Controller(home=self.home / 'other', port=self.port,
            token_file=self.control.token_file, starter=lambda: self.fail('no start'))
        with self.assertRaisesRegex(load('controller').ControlFailure, 'profile_conflict'):
            wrong.detach()
        lifecycle = load('lifecycle')
        keys = {key: {'before': {'present': False}, 'installed': {'present': True, 'value': value}}
            for key, value in {'browser.backend': 'browser-use', 'browser.headed': True,
                'browser.cdp_url': f'http://127.0.0.1:{self.port}'}.items()}
        lifecycle._save(self.home, {'version': 1, 'desired_enabled': True,
            'phase': 'attached', 'port': self.port, 'keys': keys})
        self.assert_http(409, 'stop', payload)
        lifecycle.state_path(self.home).write_text('{broken')
        self.assert_http(503, 'stop', payload)
        lifecycle.state_path(self.home).unlink()
        self.assert_http(409, 'stop', payload)
        self.assertTrue(self.control.health())

    def test_pending_and_lease_refuse_stop_after_prior_drain(self):
        drained = self.control.detach(timeout=0)
        for mode, blocker in [('pending', 'pending_operations'), ('lease', 'active_calls')]:
            with self.subTest(mode=mode):
                self.control.request('fixture', {'mode': mode})
                result = self.control.detach(timeout=0)
                self.assertEqual(result['status'], 'blocked')
                self.assertIn(blocker, result['blockers'])
                self.assert_http(409, 'stop', {'home': str(self.home), 'drain_id': drained['drain_id']})
                self.assertTrue(self.control.health())
        self.control.request('fixture', {'mode': 'quiet'})

    def test_failed_drain_invalidates_prior_quiet_tombstone(self):
        drained = self.control.detach(timeout=0)
        self.control.request('fixture', {'mode': 'pending'})
        self.assertEqual(self.control.detach(timeout=0)['status'], 'blocked')
        self.control.request('fixture', {'mode': 'quiet'})
        self.assert_http(409, 'stop', {'home': str(self.home), 'drain_id': drained['drain_id']})

    def test_real_server_main_acknowledges_stop_and_exits(self):
        # Exercise the actual CLI runner, with only an owned-stdin rescue seam.
        home = self.home / 'main-child'
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        lifecycle = load('lifecycle')
        lifecycle._save(home, {'version': 1, 'desired_enabled': False,
            'phase': 'detaching', 'port': port, 'keys': {}})
        code = f'''
import sys, asyncio, importlib.util
sys.path[:] = {sys.path!r}
spec = importlib.util.spec_from_file_location('_main_qa', {str(ROOT / 'server.py')!r})
server = importlib.util.module_from_spec(spec); spec.loader.exec_module(server)
original = server.make_app
def app(**kwargs):
    result = original(**kwargs)
    asyncio.get_running_loop().add_reader(sys.stdin.fileno(), kwargs['stop_event'].set)
    return result
server.make_app = app
sys.argv = ['server.py', '--home', {str(home)!r}, '--port', {str(port)!r}]
server.main()
'''
        child = subprocess.Popen([sys.executable, '-Werror', '-c', code], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=self.home)
        control = load('controller').Controller(home=home, port=port)
        try:
            deadline = time.monotonic() + 5
            while not control.health():
                self.assertIsNone(child.poll(), 'main child failed startup')
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
            self.assertEqual(lifecycle.default_drain(home=home, port=port)['status'], 'detached')
            child.wait(timeout=5)
            self.assertEqual(child.returncode, 0)
            self.assertFalse(control.health())
        finally:
            if child.poll() is None:
                child.stdin.write('\n'); child.stdin.flush()
            out, err = child.communicate(timeout=5)
            self.assertEqual(err, '')
            self.assertEqual(child.returncode, 0)

    def test_default_drain_does_not_stop_when_busy_and_retry_finishes(self):
        lifecycle = load('lifecycle')
        self.control.request('fixture', {'mode': 'busy'})
        result = lifecycle.default_drain(home=self.home, port=self.port)
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(self.control.health())
        self.assertIsNone(self.child.poll())
        self.control.request('fixture', {'mode': 'quiet'})
        self.assertEqual(lifecycle.default_drain(home=self.home, port=self.port)['status'], 'detached')
        self.child.wait(timeout=5)
        self.assertFalse(self.control.health())

    def test_default_drain_waits_for_listener_absence_and_child_exit(self):
        ownership = self.control.token_file.parent / 'ownership.json'
        retained = b'{"qa_retained_uncertainty":true}\n'
        ownership.write_bytes(retained)
        result = load('lifecycle').default_drain(home=self.home, port=self.port)
        self.assertEqual(result['status'], 'detached')
        self.assertEqual(ownership.read_bytes(), retained)
        self.assertFalse(self.control.health(), 'default drain left its daemon listening')
        self.child.wait(timeout=5)
        self.assertEqual(self.child.returncode, 0)

    def assert_http(self, expected, operation, data, token=None):
        import urllib.error
        import urllib.request
        request = urllib.request.Request(self.control.base + '/control/' + operation,
            data=json.dumps(data).encode(), headers={'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + (self.control.token() if token is None else token)})
        try:
            with self.control.opener.open(request, timeout=2) as response:
                code = response.status
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
        self.assertEqual(code, expected)
        self.assertIsNone(self.child.poll())

    def test_quiet_stop_ack_listener_absence_child_exit_and_retry(self):
        drained = self.control.detach(timeout=0)
        self.assertEqual(drained['status'], 'detached')
        # RED is the real HTTP missing stop operation, not a missing helper API.
        import urllib.error
        try:
            stopped = self.control.request('stop', {'home': str(self.home),
                'drain_id': drained.get('drain_id')})
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            self.fail(f'quiet child stop must succeed, got HTTP {status}')
        self.assertEqual(stopped, {'status': 'stopping', 'blockers': []})
        # Stdin remains open: only the authenticated stop may end the child.
        self.child.wait(timeout=5)
        self.assertEqual(self.child.returncode, 0)
        self.assertFalse(self.control.health())
        self.assertEqual(self.control.detach(), {'status': 'absent', 'blockers': []})
        self.assertEqual(load('lifecycle').default_drain(home=self.home, port=self.port),
            {'status': 'absent', 'blockers': []})


class CleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_owned_runner_api_exists_for_child_main(self):
        self.assertTrue(callable(getattr(load('server'), 'serve', None)),
            'child main needs an owned stoppable async runner')

    async def test_soft_cleanup_closes_real_transports_without_cdp_or_journal_mutation(self):
        from aiohttp import ClientSession, WSMsgType, web
        from aiohttp.test_utils import TestServer
        module = load('broker')
        broker = module.SessionBroker(object(), control_token='fixture')
        scope = module.SessionScope(broker.transport, 'owned', control_token='fixture')
        broker.scopes['owned'] = scope
        scope.targets.add('preserved'); scope.preserve = True
        scope.leases['fixture'] = 'owned'
        scope.recovery_guards['uncertain'] = True
        broker.resource_unknown['owned'] = 1
        before = {'pendingBootstrap': True, 'scopes': {'owned': {'uncertain': True}}}
        broker.journal_state = json.loads(json.dumps(before))
        upstream_messages = []
        async def upstream(request):
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            async for message in ws:
                if message.type == WSMsgType.TEXT:
                    upstream_messages.append(message.data)
            return ws
        fixture = web.Application(); fixture.router.add_get('/ws', upstream)
        async with TestServer(fixture, host='127.0.0.1') as upstream_server:
            broker.transport.http = ClientSession()
            broker.transport.upstream = await broker.transport.http.ws_connect(upstream_server.make_url('/ws'))
            transport_ws = broker.transport.upstream
            http = broker.transport.http
            broker.transport.reader = asyncio.create_task(broker.transport.read_upstream())
            async with TestServer(broker.app(), host='127.0.0.1') as endpoint:
                async with ClientSession() as client:
                    driver = await client.ws_connect(endpoint.make_url('/devtools/browser/' + scope.capability))
                    async def forbidden(*args):
                        self.fail('soft cleanup called generic shutdown')
                    broker.shutdown = forbidden
                    broker.soft_stop = broker.closing = broker.transport.closing = True
                    await broker.cleanup_transports(None)
                    self.assertEqual((await driver.receive(timeout=2)).type, WSMsgType.CLOSE)
                    await driver.close()
            self.assertTrue(transport_ws.closed)
            self.assertTrue(http.closed)
        self.assertEqual(upstream_messages, [])
        self.assertEqual(scope.targets, {'preserved'})
        self.assertTrue(scope.preserve)
        self.assertTrue(scope.recovery_guards['uncertain'])
        self.assertEqual(broker.resource_unknown, {'owned': 1})
        self.assertEqual(broker.journal_state, before)


if __name__ == '__main__':
    unittest.main()
