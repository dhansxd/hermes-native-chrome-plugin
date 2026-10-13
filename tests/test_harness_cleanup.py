"""Owned named-IPC generation cleanup. Fixtures never contact Chrome."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
from support import SCRATCH


def load(name):
    spec = importlib.util.spec_from_file_location('_harness_test_bundle', ROOT / '__init__.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_sibling(name)


class NamedIPC:
    """Real private socket, supported connect/request API shape."""
    def __init__(self, path):
        self.path = path
        self.messages = []
        self.reply = {'pong': True, 'pid': os.getpid(), 'browser_kind': 'cdp'}
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path)); os.chmod(path, 0o600)
        self.listener.listen(); self.listener.settimeout(.05)
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        while not self.done.is_set():
            try:
                c, _ = self.listener.accept()
            except TimeoutError:
                continue
            with c:
                data = b''
                while not data.endswith(b'\n'):
                    part = c.recv(65536)
                    if not part: break
                    data += part
                if not data: continue
                req = json.loads(data); self.messages.append(req)
                response = (self.reply if req.get('meta') == 'ping' else
                            getattr(self, 'shutdown_reply', {'error': 'refused'}) if req.get('meta') == 'shutdown' else
                            {'target_id': 'target', 'session_id': 'session'})
                c.sendall((json.dumps(response) + '\n').encode())

    def sock_addr(self, name): return str(self.path)
    def connect(self, name, timeout=1):
        c = socket.socket(socket.AF_UNIX); c.settimeout(timeout); c.connect(str(self.path)); return c, None
    def request(self, c, token, req):
        c.sendall((json.dumps(req) + '\n').encode()); data = b''
        while not data.endswith(b'\n'): data += c.recv(65536)
        return json.loads(data)
    def close(self):
        self.done.set(); self.thread.join(timeout=2); self.listener.close()


class BrokerRegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from aiohttp.test_utils import TestClient, TestServer
        self.module = load('broker')
        self.broker = self.module.SessionBroker(object(), control_token='fixture')
        self.namespace = '["fixture","default"]'
        self.scope = self.module.SessionScope(self.broker.transport, self.namespace, control_token='fixture')
        self.broker.scopes[self.namespace] = self.scope
        self.scope.own('target'); self.scope.session_targets['session'] = 'target'
        self.scope.clients[object()] = {'session': 'target'}
        self.scope.leases['lease'] = self.namespace
        self.broker.leases['lease'] = (self.scope, 'browser')
        self.client = TestClient(TestServer(self.broker.app(), host='127.0.0.1'))
        await self.client.start_server()
        async def cleanup():
            self.scope.clients.clear()
            await self.client.close()
        self.addAsyncCleanup(cleanup)
        self.endpoint = str(self.client.make_url('/devtools/browser/' + self.scope.capability)).replace('http:', 'ws:')
        self.name = load('plugin_identity').daemon_name(self.namespace)

    async def post(self, operation, data):
        response = await self.client.post('/control/' + operation, json=data,
            headers={'Authorization': 'Bearer fixture'})
        body = await response.text()
        return response.status, json.loads(body) if response.content_type == 'application/json' else {}

    async def test_begin_unknown_admission_blocks_detach_without_inventing_ownership(self):
        status, reply = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        self.assertEqual(status, 200)
        self.scope.clients.clear(); self.scope.leases.clear(); self.broker.leases.clear()
        status, reply = await self.post('detach', {'timeout': 0})
        self.assertEqual(reply['status'], 'blocked')
        self.assertIn('harness_unverified', reply['blockers'])
        self.assertIsNone(self.broker.drain_id)

    async def test_registration_rechecks_exact_verified_selection_and_preserves_prior_generation(self):
        temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hr-')
        self.addCleanup(temp.cleanup)
        ipc = NamedIPC(Path(temp.name) / 's'); self.addCleanup(ipc.close)
        self.broker.harness_ipc = ipc
        status, reply = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        record = load('harness_cleanup').capture(self.name, self.endpoint, 'target', 'session', ipc=ipc)
        payload = {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint,
            'attempt': reply['attempt'], 'target_id': 'target', 'session_id': 'session', 'record': record}
        status, reply = await self.post('register-harness', payload)
        self.assertEqual(status, 200)
        self.assertEqual(reply, {'registered': True})
        self.assertEqual(self.broker.harness_registry[self.name], record)
        self.assertNotIn(self.name, self.broker.harness_pending)
        status, begin = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        self.assertEqual(status, 200)
        for change in [{'session_id': 'forged'}, {'record': {**record, 'process_ctime': 0}}, {'attempt': 'forged'}]:
            status, _ = await self.post('register-harness', {**payload, 'attempt': begin['attempt'], **change})
            self.assertEqual(status, 403)
            self.assertEqual(self.broker.harness_registry[self.name], record)
            self.assertIn(self.name, self.broker.harness_pending)

    async def test_registration_refuses_fresh_attach_tombstone_response(self):
        temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hr-'); self.addCleanup(temp.cleanup)
        ipc = NamedIPC(Path(temp.name) / 's'); self.addCleanup(ipc.close)
        self.broker.harness_ipc = ipc
        _, begin = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        record = load('harness_cleanup').capture(self.name, self.endpoint, 'target', 'session', ipc=ipc)
        self.scope.revoked_sessions['session'] = 'target'
        status, _ = await self.post('register-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint,
            'attempt': begin['attempt'], 'target_id': 'target', 'session_id': 'session', 'record': record})
        self.assertEqual(status, 403)
        self.assertEqual(self.broker.harness_registry, {})
        self.assertIn(self.name, self.broker.harness_pending)

    async def test_detach_cleanup_failure_preserves_registered_retry_authority(self):
        from unittest.mock import patch
        self.scope.clients.clear(); self.scope.leases.clear(); self.broker.leases.clear()
        record = {'name': self.name}
        self.broker.harness_registry[self.name] = record
        with patch.object(load('harness_cleanup'), 'retire', side_effect=TimeoutError('pending')):
            _, reply = await self.post('detach', {'timeout': 0})
        self.assertEqual(reply, {'status': 'blocked', 'blockers': ['harness_cleanup']})
        self.assertIs(self.broker.harness_registry[self.name], record)
        self.assertIsNone(self.broker.drain_id)
        with patch.object(load('harness_cleanup'), 'retire', return_value=None):
            _, reply = await self.post('detach', {'timeout': 0})
        self.assertEqual(reply['status'], 'detached')
        self.assertEqual(self.broker.harness_registry, {})

    async def test_begin_refuses_noncanonical_name_endpoint_or_missing_lease(self):
        for payload in [{'name': 'dyra-arbitrary'}, {'endpoint': self.endpoint + 'wrong'}, {'lease': 'missing'}]:
            status, _ = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint, **payload})
            self.assertEqual(status, 403)


class StopCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_refuses_cleanup_failure_and_preserves_retry_authority_before_ack(self):
        from aiohttp.test_utils import TestClient, TestServer
        from unittest.mock import patch
        temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hs-'); self.addCleanup(temp.cleanup)
        home = Path(temp.name)
        load('lifecycle')._save(home, {'version': 1, 'desired_enabled': False, 'phase': 'detaching', 'port': 19347, 'keys': {}})
        event = asyncio.Event()
        app = load('server').make_app(home=home, stop_event=event)
        broker = next(r.handler.__self__ for r in app.router.routes() if r.resource.canonical == '/control/detach')
        client = TestClient(TestServer(app, host='127.0.0.1')); await client.start_server()
        self.addAsyncCleanup(client.close)
        broker.draining = True; broker.drain_id = 'drain'
        record = {'name': 'owned'}; broker.harness_registry['owned'] = record
        headers = {'Authorization': 'Bearer ' + broker.control_token}
        payload = {'home': str(home), 'drain_id': 'drain'}
        with patch.object(load('harness_cleanup'), 'retire', side_effect=TimeoutError('pending')):
            response = await client.post('/control/stop', json=payload, headers=headers)
        self.assertEqual(response.status, 409)
        self.assertFalse(event.is_set())
        self.assertIs(broker.harness_registry['owned'], record)
        with patch.object(load('harness_cleanup'), 'retire', return_value=None):
            response = await client.post('/control/stop', json=payload, headers=headers)
        self.assertEqual(response.status, 200)
        self.assertTrue(event.is_set())
        self.assertEqual(broker.harness_registry, {})


class ControllerRegistrationTests(unittest.TestCase):
    def test_controller_reserves_before_child_and_registers_after_verified_capture(self):
        from unittest.mock import patch
        import subprocess
        module = load('controller')
        control = module.Controller(home=SCRATCH)
        name = load('plugin_identity').daemon_name('["fixture","default"]')
        admission = {'lease': 'lease', 'endpoint': control.base.replace('http:', 'ws:') + '/devtools/browser/cap'}
        events = []
        def request(operation, data):
            events.append(operation)
            return {'prepared': True, 'retired': False} if operation == 'prepare-harness' else {'attempt': 'attempt'} if operation == 'begin-harness' else {'registered': True} if operation == 'register-harness' else {'verified': True}
        control.request = request
        def run(args, **kwargs):
            events.append('child')
            # Both preparation and runtime capture use the installed effective Python.
            if 'harness_cleanup' in args[-1]:
                return subprocess.CompletedProcess(args, 0, json.dumps({'name': name}), '')
            return subprocess.CompletedProcess(args, 0, json.dumps({'target_id': 'target', 'session_id': 'session'}), '')
        with patch.object(module.subprocess, 'run', side_effect=run):
            selected = control.prepare_driver(admission, name)
        self.assertEqual(events, ['prepare-harness', 'begin-harness', 'child', 'verify-driver', 'child', 'register-harness'])
        self.assertEqual(selected['target_id'], 'target')

    def test_preparation_prior_endpoint_is_not_generation_retirement_authority(self):
        module = load('controller')
        messages = []
        class IPC:
            def connect(self, *args, **kwargs):
                class C:
                    def close(self): pass
                return C(), None
            def request(self, c, token, req):
                messages.append(req)
                return {'pong': True, 'pid': os.getpid(), 'browser_kind': 'cdp'} if req['meta'] == 'ping' else {'ok': True}
        with self.assertRaises(PermissionError):
            module.prepare_named_driver('owned', 'new', 'old', ipc=IPC(), validate_socket=lambda: None,
                wait_stopped=lambda pid: None, ensure=lambda: self.fail('must not reload'))
        self.assertEqual(messages, [])

    def test_failed_preparation_leaves_reserved_unknown_outcome_and_no_register(self):
        from unittest.mock import patch
        import subprocess
        module = load('controller')
        control = module.Controller(home=SCRATCH)
        name = load('plugin_identity').daemon_name('["fixture","default"]')
        events = []
        control.request = lambda operation, data: events.append(operation) or {'prepared': True, 'retired': False, 'attempt': 'attempt'}
        with patch.object(module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 20)):
            with self.assertRaises(module.ControlFailure):
                control.prepare_driver({'lease': 'lease', 'endpoint': control.base.replace('http:', 'ws:') + '/devtools/browser/cap'}, name)
        self.assertEqual(events, ['prepare-harness', 'begin-harness'])
        self.assertEqual(control.driver_endpoints, {})


class RealHarnessTests(unittest.IsolatedAsyncioTestCase):
    async def test_installed_daemon_downstream_fence_prevents_finalizer_close_and_confirms_exit(self):
        from aiohttp import web, WSMsgType
        from aiohttp.test_utils import TestServer, TestClient
        import subprocess
        import sys
        from browser_harness import _ipc
        temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='rh-')
        self.addCleanup(temp.cleanup)
        messages = []
        async def upstream(request):
            ws = web.WebSocketResponse(); await ws.prepare(request)
            async for msg in ws:
                if msg.type != WSMsgType.TEXT: continue
                data = json.loads(msg.data); messages.append(data['method'])
                method = data['method']
                result = {'targetInfos': [{'targetId': 'user', 'type': 'page', 'url': 'about:blank', 'browserContextId': 'context'}]} if method == 'Target.getTargets' else {'targetId': 'dedicated'} if method == 'Target.createTarget' else {'sessionId': 's-' + data['params']['targetId']} if method == 'Target.attachToTarget' else {'targetInfo': {'targetId': data['params']['targetId'], 'type': 'page', 'browserContextId': 'context'}} if method == 'Target.getTargetInfo' else {}
                await ws.send_json({'id': data['id'], 'result': result, **({'sessionId': data['sessionId']} if data.get('sessionId') else {})})
            return ws
        app = web.Application(); app.router.add_get('/ws', upstream)
        async with TestServer(app, host='127.0.0.1') as fake:
            broker_module = load('broker')
            broker = broker_module.SessionBroker(object(), control_token='fixture')
            broker.transport.http = __import__('aiohttp').ClientSession()
            broker.transport.upstream = await broker.transport.http.ws_connect(fake.make_url('/ws'))
            broker.transport.reader = asyncio.create_task(broker.transport.read_upstream())
            namespace = '["real-fixture","default"]'
            scope = broker_module.SessionScope(broker.transport, namespace, control_token='fixture')
            scope.context_id = 'context'; scope.own('user')
            broker.scopes[namespace] = scope
            scope.leases['lease'] = namespace; broker.leases['lease'] = (scope, 'browser')
            client = TestClient(TestServer(broker.app(), host='127.0.0.1')); await client.start_server()
            children = []
            try:
                for selected in ['dedicated', 'user']:
                    scope.capability = 'fixture-cap'; broker.draining = False
                    scope.leases['lease'] = namespace; broker.leases['lease'] = (scope, 'browser')
                    name = load('plugin_identity').daemon_name(namespace)
                    endpoint = str(client.make_url('/devtools/browser/' + scope.capability)).replace('http:', 'ws:')
                    env = {**os.environ, 'BU_NAME': name, 'BU_CDP_WS': endpoint, 'BH_RUNTIME_DIR': temp.name, 'BH_TMP_DIR': temp.name}
                    # Isolated IPC namespace with the exact installed harness implementation.
                    code = 'import asyncio,sys\nfrom browser_harness import daemon\nasync def run():\n d=daemon.Daemon(); await d.start(); print("ready",flush=True); await daemon.serve(d)\nasyncio.run(run())\n'
                    child = subprocess.Popen([sys.executable, '-c', code], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    children.append(child)
                    ready = await asyncio.wait_for(asyncio.to_thread(child.stdout.readline), 10)
                    self.assertEqual(ready.strip(), 'ready')
                    class FixtureIPC:
                        def sock_addr(self, name): return str(Path(temp.name) / 'bu.sock')
                        def connect(self, name, timeout=1):
                            c = socket.socket(socket.AF_UNIX); c.settimeout(timeout); c.connect(self.sock_addr(name)); return c, None
                        request = staticmethod(_ipc.request)
                    ipc = FixtureIPC(); broker.harness_ipc = ipc
                    cleanup = load('harness_cleanup')
                    if selected == 'user':
                        attached = await asyncio.to_thread(cleanup.request, ipc, name, {'method': 'Target.attachToTarget', 'params': {'targetId': 'user', 'flatten': True}})
                        sid = attached['result']['sessionId']
                        await asyncio.to_thread(cleanup.request, ipc, name, {'meta': 'set_session', 'target_id': 'user', 'session_id': sid})
                    else:
                        status = await asyncio.to_thread(cleanup.request, ipc, name, {'meta': 'connection_status'})
                        self.assertEqual(status['target_id'], selected)
                        sid = status['session_id']
                    record = await asyncio.to_thread(cleanup.capture, name, endpoint, selected, sid, ipc=ipc)
                    headers = {'Authorization': 'Bearer fixture'}
                    begin_response = await client.post('/control/begin-harness', json={'lease': 'lease', 'name': name, 'endpoint': endpoint}, headers=headers)
                    begin = await begin_response.json()
                    registered = await client.post('/control/register-harness', json={'lease': 'lease', 'name': name, 'endpoint': endpoint,
                        'attempt': begin['attempt'], 'target_id': selected, 'session_id': sid, 'record': record}, headers=headers)
                    self.assertEqual(registered.status, 200, await registered.text())
                    scope.leases.clear(); broker.leases.clear()
                    before = len(messages)
                    from unittest.mock import patch
                    original_retire = cleanup.retire
                    fence = []
                    def retire_after_disconnect(record, **kwargs):
                        fence.append(not scope.clients and scope.capability is None)
                        return original_retire(record, **kwargs)
                    with patch.object(cleanup, 'retire', side_effect=retire_after_disconnect):
                        response = await client.post('/control/detach', json={'timeout': 1}, headers=headers)
                    self.assertEqual(fence, [True])
                    reply = await response.json()
                    self.assertEqual(reply['status'], 'detached', reply)
                    await asyncio.to_thread(child.wait, timeout=5)
                    self.assertEqual(child.returncode, 0)
                    self.assertEqual(broker.harness_registry, {})
                    self.assertFalse(scope.clients)
                    self.assertFalse(any(x in {'Browser.close', 'Target.closeTarget', 'Page.close'} for x in messages[before:]))
                    self.assertTrue(cleanup.exited(record))
            finally:
                # No signal rescue: downstream fence, then only exact named IPC.
                for ws in tuple(scope.clients): await ws.close()
                for child in children:
                    if child.poll() is None:
                        await asyncio.to_thread(cleanup.request, ipc, name, {'meta': 'shutdown'})
                        await asyncio.to_thread(child.wait, timeout=5)
                    child.stdout.close(); child.stderr.close()
                broker.soft_stop = True
                await client.close()


class CaptureTests(unittest.TestCase):
    def test_capture_rejects_untrusted_metadata_and_ping(self):
        module = load('harness_cleanup')
        for reply in [{'pong': True, 'pid': True, 'browser_kind': 'cdp'},
                      {'pong': True, 'pid': os.getpid(), 'browser_kind': 'local'}, []]:
            self.ipc.reply = reply
            with self.assertRaises(PermissionError):
                module.capture('owned', 'endpoint', 'target', 'session', ipc=self.ipc)
        self.ipc.reply = {'pong': True, 'pid': os.getpid(), 'browser_kind': 'cdp'}
        os.chmod(self.ipc.path, 0o666)
        with self.assertRaises(PermissionError):
            module.capture('owned', 'endpoint', 'target', 'session', ipc=self.ipc)

    def test_retire_changed_generation_never_sends_shutdown(self):
        module = load('harness_cleanup')
        record = module.capture('owned', 'endpoint', 'target', 'session', ipc=self.ipc)
        module.retire({**record, 'process_ctime': 0}, ipc=self.ipc, timeout=.05)
        with self.assertRaises(PermissionError):
            module.retire({**record, 'process_uid': -1}, ipc=self.ipc, timeout=.05)
        altered = {**record, 'socket': {**record['socket'], 'ino': -1}}
        with self.assertRaises(PermissionError):
            module.retire(altered, ipc=self.ipc, timeout=.05)
        self.assertNotIn('shutdown', [x['meta'] for x in self.ipc.messages])

    def test_retire_rechecks_socket_after_shutdown_connect_before_send(self):
        from unittest.mock import patch
        module = load('harness_cleanup')
        record = module.capture('owned', 'endpoint', 'target', 'session', ipc=self.ipc)
        original = self.ipc.connect
        calls = []
        def connect(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(True)
            if len(calls) == 2:
                os.chmod(self.ipc.path, 0o700)
            return result
        with patch.object(self.ipc, 'connect', side_effect=connect):
            with self.assertRaises(PermissionError):
                module.retire(record, ipc=self.ipc, timeout=.05)
        self.assertNotIn('shutdown', [x['meta'] for x in self.ipc.messages])

    def test_retire_ack_without_exit_times_out_and_preserves_record(self):
        module = load('harness_cleanup')
        record = module.capture('owned', 'endpoint', 'target', 'session', ipc=self.ipc)
        self.ipc.shutdown_reply = {'ok': True}
        with self.assertRaises(TimeoutError):
            module.retire(record, ipc=self.ipc, timeout=.05)
        self.assertEqual(record['pid'], os.getpid())
        self.assertEqual(self.ipc.messages[-1], {'meta': 'shutdown'})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hc-')
        self.addCleanup(self.temp.cleanup)
        # macOS AF_UNIX path length: keep the basename tiny.
        self.ipc = NamedIPC(Path(self.temp.name) / 's')
        self.addCleanup(self.ipc.close)

    def test_capture_binds_ping_process_generation_private_socket_selection(self):
        module = load('harness_cleanup')
        record = module.capture('owned', 'ws://127.0.0.1:1/devtools/browser/cap', 'target', 'session', ipc=self.ipc)
        import psutil
        self.assertEqual(record['pid'], os.getpid())
        self.assertEqual(record['process_ctime'], psutil.Process().create_time())
        self.assertEqual(record['process_uid'], os.getuid())
        st = Path(self.ipc.path).lstat()
        self.assertEqual(record['socket'], {'path': str(self.ipc.path), 'dev': st.st_dev, 'ino': st.st_ino, 'uid': os.getuid(), 'mode': 0o600})
        self.assertEqual((record['name'], record['target_id'], record['session_id']), ('owned', 'target', 'session'))
        self.assertEqual([x['meta'] for x in self.ipc.messages], ['ping', 'connection_status'])
