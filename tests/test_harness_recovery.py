"""Crash inventory fixtures: private metadata, never a Chrome connection."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_harness_cleanup as fixtures
from test_harness_cleanup import load, NamedIPC, SCRATCH


class DurableAdmissionTests(fixtures.BrokerRegistrationTests):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hrd-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        ownership = load('state_journal')
        self.journal = ownership.StateJournal(self.home / 'state' / 'ownership.json')
        state = ownership.new_state(fingerprint='a' * 64, browser_uuid='fixture', context_id='context')
        ownership.ensure_scope(state, self.namespace)
        self.journal.save(state)
        self.broker.journal = self.journal
        self.broker.journal_state = state
        self.broker.profile_home = str(self.home)

    async def test_registered_inventory_restores_exact_generation_and_retries_partial_exit(self):
        ipc = NamedIPC(self.home / 's'); self.addCleanup(ipc.close)
        self.broker.harness_ipc = ipc
        _, begin = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        cleanup = load('harness_cleanup')
        record = cleanup.capture(self.name, self.endpoint, 'target', 'session', ipc=ipc)
        status, _ = await self.post('register-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint,
            'attempt': begin['attempt'], 'target_id': 'target', 'session_id': 'session', 'record': record})
        self.assertEqual(status, 200)
        restarted = self.module.SessionBroker(object(), control_token='fixture', journal=self.journal)
        restarted.profile_home = str(self.home); restarted.harness_ipc = ipc
        from aiohttp.test_utils import TestClient, TestServer
        other = TestClient(TestServer(restarted.app(), host='127.0.0.1'))
        await other.start_server(); self.addAsyncCleanup(other.close)
        original_request = ipc.request
        ipc.request = lambda c, token, req: ({'error': 'cdp_disconnected'} if req.get('meta') == 'connection_status' else original_request(c, token, req))
        retired = []
        def retire(rec, **kwargs):
            retired.append(rec)
            raise TimeoutError('partial exit')
        with patch.object(cleanup, 'retire', side_effect=retire):
            response = await other.post('/control/detach', json={'timeout': 0}, headers={'Authorization': 'Bearer fixture'})
            reply = await response.json()
        self.assertEqual(reply['status'], 'blocked')
        self.assertEqual(len(retired), 1, 'registered generation was lost on broker restart')
        self.assertEqual(retired[0]['pid'], record['pid'])
        self.assertEqual(retired[0]['socket'], record['socket'])
        inventory = json.loads((self.journal.path.parent / 'harness-inventory.json').read_text())
        self.assertIn(self.name, inventory['records'])
        for secret in [self.endpoint, self.namespace, 'session_id', 'target_id']:
            self.assertNotIn(secret, json.dumps(inventory))
        with patch.object(cleanup, 'retire', return_value=None):
            response = await other.post('/control/detach', json={'timeout': 0}, headers={'Authorization': 'Bearer fixture'})
            self.assertEqual((await response.json())['status'], 'detached')
        self.assertEqual(json.loads((self.journal.path.parent / 'harness-inventory.json').read_text())['records'], {})

    async def test_cold_preparation_retires_verified_disconnected_generation_before_reservation(self):
        ipc = NamedIPC(self.home / 's'); self.addCleanup(ipc.close)
        self.broker.harness_ipc = ipc
        _, begin = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        cleanup = load('harness_cleanup')
        record = cleanup.capture(self.name, self.endpoint, 'target', 'session', ipc=ipc)
        status, _ = await self.post('register-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint,
            'attempt': begin['attempt'], 'target_id': 'target', 'session_id': 'session', 'record': record})
        self.assertEqual(status, 200)
        original_request = ipc.request
        ipc.request = lambda c, token, req: ({'error': 'cdp_disconnected'} if req.get('meta') == 'connection_status' else original_request(c, token, req))
        observed = []
        def retire(rec, **kw):
            observed.append(rec)
            self.assertFalse(self.broker.harness_pending, 'must retire before unknown creation reservation')
        with patch.object(cleanup, 'retire', side_effect=retire):
            status, reply = await self.post('prepare-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        self.assertEqual(status, 200)
        self.assertEqual(reply, {'prepared': True, 'retired': True})
        self.assertEqual(observed, [record])
        self.assertNotIn(self.name, self.broker.harness_registry)
        self.assertEqual(json.loads((self.journal.path.parent / 'harness-inventory.json').read_text())['records'], {})

    async def test_unknown_pending_blocks_registered_retirement_until_reconciled(self):
        self.scope.clients.clear(); self.scope.leases.clear(); self.broker.leases.clear()
        self.broker.harness_registry[self.name] = {'name': self.name}
        self.broker.harness_pending[self.name] = {'unknown': True}
        with patch.object(load('harness_cleanup'), 'retire', return_value=None) as retire:
            _, reply = await self.post('detach', {'timeout': 0})
            self.assertEqual(reply['status'], 'blocked')
            retire.assert_not_called()
        self.assertIn(self.name, self.broker.harness_registry)

    async def test_other_durable_scope_busy_blocks_all_cleanup(self):
        cleanup = load('harness_cleanup'); ownership = load('state_journal')
        ipc = NamedIPC(self.home / 's'); self.addCleanup(ipc.close)
        record = cleanup.capture(self.name, self.endpoint, 'target', 'session', ipc=ipc)
        inventory = cleanup.InventoryJournal(self.journal.path.with_name('harness-inventory.json'), self.home)
        saved = inventory.empty(); saved['records'][self.name] = cleanup.durable_record(record, self.namespace); inventory.save(saved)
        state = self.journal.load(); ownership.ensure_scope(state, 'other'); ownership.set_guards(state, 'other', busy=True); self.journal.save(state)
        restarted = self.module.SessionBroker(object(), control_token='fixture', journal=self.journal)
        restarted.profile_home = str(self.home); restarted.harness_ipc = ipc
        ipc.request = lambda c, token, req: {'error': 'cdp_disconnected'} if req.get('meta') == 'connection_status' else {'pong': True, 'pid': os.getpid(), 'browser_kind': 'cdp'}
        with patch.object(cleanup, 'retire', return_value=None) as retire:
            self.assertEqual(await restarted.cleanup_harnesses(timeout=0), ['harness_inventory'])
            retire.assert_not_called()

    async def test_failed_inventory_commit_blocks_later_admission(self):
        await self.broker.load_harness_inventory()
        cleanup = load('harness_cleanup')
        with patch.object(self.broker.harness_inventory_journal, 'save', side_effect=OSError('disk failure')):
            response = await self.client.post('/control/begin-harness', json={'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint}, headers={'Authorization': 'Bearer fixture'})
            self.assertGreaterEqual(response.status, 400)
        status, _ = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        self.assertEqual(status, 409)
        self.assertIsNone(self.broker.drain_id)

    async def test_failed_old_preparation_reconciles_only_unchanged_live_registered_generation(self):
        ipc = NamedIPC(self.home / 's'); self.addCleanup(ipc.close)
        self.broker.harness_ipc = ipc; cleanup = load('harness_cleanup')
        _, begin = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        record = cleanup.capture(self.name, self.endpoint, 'target', 'session', ipc=ipc)
        status, _ = await self.post('register-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint,
            'attempt': begin['attempt'], 'target_id': 'target', 'session_id': 'session', 'record': record})
        self.assertEqual(status, 200)
        # Reproduce the old ordering: reservation exists, but child did not replace generation.
        await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        original = ipc.request
        ipc.request = lambda c, token, req: {'error': 'cdp_disconnected'} if req.get('meta') == 'connection_status' else original(c, token, req)
        with patch.object(cleanup, 'retire', return_value=None):
            status, reply = await self.post('prepare-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        self.assertEqual(status, 200)
        self.assertTrue(reply['retired'])
        self.assertFalse(self.broker.harness_pending)

    async def test_unknown_pending_with_exited_prior_cannot_be_cleared(self):
        cleanup = load('harness_cleanup')
        self.broker.harness_registry[self.name] = {'name': self.name}
        self.broker.harness_pending[self.name] = {'unknown': True}
        with patch.object(cleanup, 'exited', return_value=True):
            status, _ = await self.post('prepare-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        self.assertEqual(status, 409)
        self.assertIn(self.name, self.broker.harness_pending)

    async def test_crash_before_registration_retains_unknown_admission(self):
        status, _ = await self.post('begin-harness', {'lease': 'lease', 'name': self.name, 'endpoint': self.endpoint})
        self.assertEqual(status, 200)
        restarted = self.module.SessionBroker(object(), control_token='fixture', journal=self.journal)
        restarted.profile_home = str(self.home)
        from aiohttp.test_utils import TestClient, TestServer
        other = TestClient(TestServer(restarted.app(), host='127.0.0.1'))
        await other.start_server(); self.addAsyncCleanup(other.close)
        response = await other.post('/control/detach', json={'timeout': 0}, headers={'Authorization': 'Bearer fixture'})
        reply = await response.json()
        self.assertEqual(reply['status'], 'blocked')
        self.assertIn('harness_unverified', reply['blockers'])
        persisted = (self.journal.path.parent / 'harness-inventory.json').read_text()
        for secret in [self.endpoint, self.namespace, 'lease', 'attempt', 'target_id', 'session_id']:
            self.assertNotIn(secret, persisted)


CHILD_BROKER = r'''
import asyncio, importlib.util, json, os, sys
from pathlib import Path
from aiohttp import web, ClientSession
root, home, upstream, port = sys.argv[1:]
spec = importlib.util.spec_from_file_location('_crash_fixture', Path(root) / '__init__.py')
bundle = importlib.util.module_from_spec(spec); spec.loader.exec_module(bundle)
async def run():
    identity = {'fingerprint': 'd' * 64, 'uuid': 'fixture', 'profile': 'Default', 'context_id': 'context'}
    class Connector:
        async def browser_identity(self, endpoint, context): return dict(identity)
    ownership = bundle.load_sibling('state_journal')
    journal = ownership.StateJournal(bundle.load_sibling('controller').state_directory(home) / 'ownership.json')
    journal.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if journal.load() is None:
        state = ownership.new_state(fingerprint=identity['fingerprint'], browser_uuid='fixture', context_id='context')
        ownership.ensure_scope(state, '["real-crash","default"]'); journal.save(state)
    module = bundle.load_sibling('broker')
    broker = module.SessionBroker(Connector(), control_token='fixture', journal=journal)
    broker.profile_home = home
    broker.journal_state = journal.load(); broker.journal_loaded = True
    class IPC:
        def sock_addr(self, name): return str(Path(home) / 'bu.sock')
        def connect(self, name, timeout=1):
            import socket
            c = socket.socket(socket.AF_UNIX); c.settimeout(timeout); c.connect(self.sock_addr(name)); return c, None
        from browser_harness import _ipc
        request = staticmethod(_ipc.request)
    broker.harness_ipc = IPC()
    if upstream != '-':
        broker.transport.http = ClientSession()
        broker.transport.upstream = await broker.transport.http.ws_connect(upstream)
        broker.transport.reader = asyncio.create_task(broker.transport.read_upstream())
        broker.transport.context_id = 'context'; broker.live_endpoint = {'fixture': True}
        scope = module.SessionScope(broker.transport, '["real-crash","default"]', control_token='fixture')
        scope.context_id = 'context'; scope.own('user'); scope.capability = 'fixture-cap'
        scope.leases['lease'] = scope.namespace; broker.leases['lease'] = (scope, 'browser')
        broker.scopes[scope.namespace] = scope
    event = asyncio.Event(); app = broker.app()
    async def crash(request):
        broker.authorize(request)
        os._exit(0)  # Only this owned fixture child; no signals to any process.
    async def release(request):
        broker.authorize(request)
        for scope in broker.scopes.values(): scope.leases.clear()
        broker.leases.clear()
        return web.json_response({'ok': True})
    async def cold(request):
        broker.authorize(request)
        scope = next(iter(broker.scopes.values()))
        await scope.disconnect()
        await broker.transport.disconnect()
        scope.session_targets.clear(); scope.provenance_sessions.clear()
        scope.capability = 'fresh-cap'
        broker.transport.http = ClientSession()
        broker.transport.upstream = await broker.transport.http.ws_connect(upstream)
        broker.transport.reader = asyncio.create_task(broker.transport.read_upstream())
        return web.json_response({'endpoint': f'ws://{request.host}/devtools/browser/fresh-cap'})
    async def finish(request):
        broker.authorize(request); broker.soft_stop = True; event.set()
        return web.json_response({'ok': True})
    app.router.add_post('/fixture/crash', crash)
    app.router.add_post('/fixture/release', release)
    app.router.add_post('/fixture/finish', finish)
    app.router.add_post('/fixture/cold', cold)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup(); site = web.TCPSite(runner, '127.0.0.1', int(port)); await site.start()
    print(site._server.sockets[0].getsockname()[1], flush=True)
    await event.wait(); await runner.cleanup()
asyncio.run(run())
'''


class RealCrashTests(unittest.IsolatedAsyncioTestCase):
    async def test_installed_harness_owned_child_crash_same_port_recovery_exits_zero_without_cdp_close(self):
        await self.run_crash_fixture()

    async def test_installed_harness_crash_before_registration_preserves_unknown_tombstone(self):
        await self.run_crash_fixture(register=False)

    async def test_installed_controller_first_cold_preparation_replaces_original_daemon_without_replay(self):
        await self.run_crash_fixture(cold=True)

    async def test_installed_harness_offline_detach_recovers_without_broker_start(self):
        await self.run_crash_fixture(offline=True)

    async def run_crash_fixture(self, *, register=True, cold=False, offline=False):
        """Real process characterization of the regression slices above."""
        import socket
        import subprocess
        import sys
        from aiohttp import web, WSMsgType, ClientSession
        from aiohttp.test_utils import TestServer
        from browser_harness import _ipc
        temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hrc-'); self.addCleanup(temp.cleanup)
        home = Path(temp.name); messages = []; children = []
        directory = load('controller').state_directory(home)
        async def upstream(request):
            ws = web.WebSocketResponse(); await ws.prepare(request)
            async for msg in ws:
                if msg.type != WSMsgType.TEXT: continue
                data = json.loads(msg.data); method = data['method']; messages.append(method)
                result = {'targetInfos': [{'targetId': 'user', 'type': 'page', 'url': 'about:blank', 'browserContextId': 'context'}]} if method == 'Target.getTargets' else {'targetId': 'dedicated'} if method == 'Target.createTarget' else {'sessionId': 's-' + data['params']['targetId']} if method == 'Target.attachToTarget' else {'targetInfo': {'targetId': data['params']['targetId'], 'type': 'page', 'browserContextId': 'context'}} if method == 'Target.getTargetInfo' else {}
                await ws.send_json({'id': data['id'], 'result': result, **({'sessionId': data['sessionId']} if data.get('sessionId') else {})})
            return ws
        app = web.Application(); app.router.add_get('/ws', upstream)
        namespace = '["real-crash","default"]'; name = load('plugin_identity').daemon_name(namespace)
        headers = {'Authorization': 'Bearer fixture'}
        class IPC:
            def sock_addr(self, name): return str(home / 'bu.sock')
            def connect(self, name, timeout=1):
                c = socket.socket(socket.AF_UNIX); c.settimeout(timeout); c.connect(self.sock_addr(name)); return c, None
            request = staticmethod(_ipc.request)
        ipc = IPC(); cleanup = load('harness_cleanup'); daemon = None; broker = None; port = 0
        async def start(upstream_url, port):
            child = subprocess.Popen([sys.executable, '-c', CHILD_BROKER, str(fixtures.ROOT), str(home), upstream_url, str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            children.append(child)
            line = await asyncio.wait_for(asyncio.to_thread(child.stdout.readline), 10)
            self.assertTrue(line.strip().isdigit(), child.stderr.read() if child.poll() is not None else line)
            return child, int(line.strip())
        async with TestServer(app, host='127.0.0.1') as fake, ClientSession() as http:
            try:
                broker, port = await start(str(fake.make_url('/ws')).replace('http:', 'ws:'), 0)
                base = f'http://127.0.0.1:{port}'; endpoint = base.replace('http:', 'ws:') + '/devtools/browser/fixture-cap'
                payload = {'lease': 'lease', 'name': name, 'endpoint': endpoint}
                async with http.post(base + '/control/begin-harness', json=payload, headers=headers) as response:
                    self.assertEqual(response.status, 200); begin = await response.json()
                env = {**os.environ, 'BU_NAME': name, 'BU_CDP_WS': endpoint, 'BH_RUNTIME_DIR': str(home), 'BH_TMP_DIR': str(home)}
                code = 'import asyncio\nfrom browser_harness import daemon\nasync def run():\n d=daemon.Daemon(); await d.start(); print("ready",flush=True); await daemon.serve(d)\nasyncio.run(run())\n'
                daemon = subprocess.Popen([sys.executable, '-c', code], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); children.append(daemon)
                self.assertEqual((await asyncio.wait_for(asyncio.to_thread(daemon.stdout.readline), 10)).strip(), 'ready')
                status = await asyncio.to_thread(cleanup.request, ipc, name, {'meta': 'connection_status'})
                record = await asyncio.to_thread(cleanup.capture, name, endpoint, status['target_id'], status['session_id'], ipc=ipc)
                if register:
                    async with http.post(base + '/control/register-harness', json={**payload, 'attempt': begin['attempt'], 'record': record, **status}, headers=headers) as response:
                        self.assertEqual(response.status, 200, await response.text())
                if cold:
                    before = len(messages)
                    async with http.post(base + '/fixture/cold', headers=headers) as response:
                        fresh_endpoint = (await response.json())['endpoint']
                    token_file = home / 'control-token'; token_file.write_text('fixture'); token_file.chmod(0o600)
                    control = load('controller').Controller(home=home, port=port, token_file=token_file)
                    control.driver_endpoints[name] = endpoint
                    # Installed preparation child uses isolated IPC; no native model action yet.
                    with patch.dict(os.environ, {'BH_RUNTIME_DIR': str(home), 'BH_TMP_DIR': str(home)}):
                        selected = await asyncio.to_thread(control.prepare_driver,
                            {'lease': 'lease', 'endpoint': fresh_endpoint}, name)
                    self.assertTrue(selected['verified'])
                    self.assertEqual(await asyncio.to_thread(daemon.wait, 5), 0)
                    self.assertNotIn('Target.closeTarget', messages[before:])
                    self.assertNotIn('Browser.close', messages[before:])
                    status = await asyncio.to_thread(cleanup.request, ipc, name, {'meta': 'connection_status'})
                    replacement = await asyncio.to_thread(cleanup.capture, name, fresh_endpoint, status['target_id'], status['session_id'], ipc=ipc)
                    self.assertNotEqual(replacement['pid'], record['pid'])
                    self.assertNotEqual(replacement['process_ctime'], record['process_ctime'])
                    async with http.post(base + '/fixture/release', headers=headers) as response: self.assertEqual(response.status, 200)
                    async with http.post(base + '/control/detach', json={'timeout': 5}, headers=headers) as response:
                        self.assertEqual((await response.json())['status'], 'detached')
                    self.assertTrue(cleanup.exited(replacement))
                    async with http.post(base + '/fixture/finish', headers=headers) as response: self.assertEqual(response.status, 200)
                    self.assertEqual(await asyncio.to_thread(broker.wait, 5), 0)
                    return
                async with http.post(base + '/fixture/release', headers=headers) as response: self.assertEqual(response.status, 200)
                before = len(messages)
                try:
                    await http.post(base + '/fixture/crash', headers=headers)
                except Exception: pass  # The fixture intentionally exits before replying.
                self.assertEqual(await asyncio.to_thread(broker.wait, 5), 0)
                deadline = asyncio.get_running_loop().time() + 5
                while True:
                    status = await asyncio.to_thread(cleanup.request, ipc, name, {'meta': 'connection_status'})
                    if status.get('error') in {'cdp_disconnected', 'not_attached'}: break
                    self.assertLess(asyncio.get_running_loop().time(), deadline)
                    await asyncio.sleep(.02)
                if offline:
                    script = ('import json,importlib.util; from pathlib import Path; '
                        f'spec=importlib.util.spec_from_file_location("_offline_fixture", {str(fixtures.ROOT / "__init__.py")!r}); '
                        'bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle); '
                        f'control=bundle.load_sibling("controller").Controller(home={str(home)!r}, port={port}); '
                        'print(json.dumps(control.detach(timeout=5)))')
                    result = await asyncio.to_thread(subprocess.run, [sys.executable, '-c', script], env=env,
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout), {'status': 'detached', 'blockers': []})
                    self.assertEqual(await asyncio.to_thread(daemon.wait, 5), 0)
                    self.assertNotIn('Target.closeTarget', messages[before:])
                    self.assertNotIn('Browser.close', messages[before:])
                    self.assertEqual(json.loads((directory / 'harness-inventory.json').read_text())['records'], {})
                    return
                broker, same_port = await start('-', port); self.assertEqual(same_port, port)
                async with http.post(base + '/control/detach', json={'timeout': 5}, headers=headers) as response:
                    reply = await response.json()
                    self.assertEqual(reply['status'], 'detached' if register else 'blocked', reply)
                if not register:
                    self.assertIn('harness_unverified', reply['blockers'])
                    self.assertIsNone(daemon.poll())
                    self.assertIn(name, json.loads((directory / 'harness-inventory.json').read_text())['pending'])
                    await asyncio.to_thread(cleanup.retire, record, ipc=ipc, timeout=5)  # Fixture owner teardown, not broker adoption.
                self.assertEqual(await asyncio.to_thread(daemon.wait, 5), 0)
                self.assertNotIn('Target.closeTarget', messages[before:]); self.assertNotIn('Browser.close', messages)
                self.assertNotIn('Target.disposeBrowserContext', messages)
                self.assertEqual(json.loads((directory / 'harness-inventory.json').read_text())['records'], {})
                async with http.post(base + '/fixture/finish', headers=headers) as response: self.assertEqual(response.status, 200)
                self.assertEqual(await asyncio.to_thread(broker.wait, 5), 0)
            finally:
                if broker and broker.poll() is None:
                    try: await http.post(f'http://127.0.0.1:{port}/fixture/finish', headers=headers)
                    except Exception: pass
                    await asyncio.to_thread(broker.wait, 5)
                if daemon and daemon.poll() is None:
                    # Transport already disconnected before exact owned-daemon cleanup.
                    rec = await asyncio.to_thread(cleanup.capture, name, endpoint, status.get('target_id'), status.get('session_id'), ipc=ipc) if not locals().get('record') else record
                    await asyncio.to_thread(cleanup.retire, rec, ipc=ipc, timeout=5)
                    await asyncio.to_thread(daemon.wait, 5)
                for child in children:
                    child.stdout.close(); child.stderr.close()


class InventorySafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_corrupt_replaced_socket_pid_wrong_profile_and_guarded_journal_fail_closed(self):
        temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hrv-'); self.addCleanup(temp.cleanup)
        home = Path(temp.name)
        ipc = NamedIPC(home / 's'); self.addCleanup(ipc.close)
        cleanup = load('harness_cleanup'); ownership = load('state_journal')
        namespace = '["generation","default"]'; name = load('plugin_identity').daemon_name(namespace)
        journal = ownership.StateJournal(home / 'state' / 'ownership.json')
        state = ownership.new_state(fingerprint='b' * 64, browser_uuid='fixture', context_id='context')
        ownership.ensure_scope(state, namespace); journal.save(state)
        inventory = cleanup.InventoryJournal(journal.path.with_name('harness-inventory.json'), home)
        original = inventory.empty()
        runtime = cleanup.capture(name, 'endpoint', 'target', 'session', ipc=ipc)
        original['records'][name] = cleanup.durable_record(runtime, namespace)
        for change in ['corrupt', 'socket', 'uid', 'namespace', 'binding', 'unknown_field', 'busy', 'transfer', 'uncertain', 'journal_namespace']:
            candidate = json.loads(json.dumps(original)); trusted = json.loads(json.dumps(state))
            if change == 'socket': candidate['records'][name]['socket']['ino'] += 1
            if change == 'uid': candidate['records'][name]['process_uid'] += 1
            if change == 'namespace': candidate['records'][name]['namespace_hash'] = '0' * 64
            if change == 'binding': candidate['binding'] = '0' * 64
            if change == 'unknown_field': candidate['records'][name]['endpoint'] = 'forbidden'
            if change in ('busy', 'uncertain'): trusted['scopes'][namespace]['guards'][change] = True
            if change == 'transfer': trusted['scopes'][namespace]['guards']['upload_status'] = 'in_progress'
            if change == 'journal_namespace': trusted['scopes'] = {}
            journal.save(trusted)
            inventory.path.write_text('{' if change == 'corrupt' else json.dumps(candidate)); os.chmod(inventory.path, 0o600)
            broker = load('broker').SessionBroker(object(), control_token='fixture', journal=journal)
            broker.profile_home = str(home); broker.harness_ipc = ipc
            before = len(ipc.messages)
            blockers = await broker.cleanup_harnesses(timeout=0)
            self.assertEqual(blockers, ['harness_inventory'], change)
            self.assertNotIn('shutdown', [m.get('meta') for m in ipc.messages[before:]], change)
        # PID reuse is original-generation absence, never authority to shutdown replacement.
        inventory.save(original); journal.save(state)
        broker = load('broker').SessionBroker(object(), control_token='fixture', journal=journal)
        broker.profile_home = str(home); broker.harness_ipc = ipc
        before = len(ipc.messages)
        with patch.object(cleanup, 'exited', return_value=True):
            self.assertEqual(await broker.cleanup_harnesses(timeout=0), [])
        self.assertNotIn('shutdown', [m.get('meta') for m in ipc.messages[before:]])


class ControllerRecoveryTests(unittest.TestCase):
    def test_offline_detach_does_not_claim_absence_with_durable_unknown(self):
        temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hro-'); self.addCleanup(temp.cleanup)
        home = Path(temp.name)
        controller = load('controller').Controller(home=home)
        path = load('controller').state_directory(home) / 'harness-inventory.json'
        path.parent.mkdir(parents=True, mode=0o700)
        inventory = load('harness_cleanup').InventoryJournal(path, home)
        state = inventory.empty()
        name = load('plugin_identity').daemon_name('namespace')
        state['pending'][name] = {'namespace_hash': load('harness_cleanup').namespace_hash('namespace')}
        inventory.save(state)
        controller.health = lambda: False
        controller.starter = lambda: self.fail('offline detach must never start broker')
        reply = controller.detach(timeout=0)
        self.assertEqual(reply['status'], 'blocked')
        self.assertIn('harness_unverified', reply['blockers'])

    def test_cold_preparation_refusal_is_sanitized_stale_driver(self):
        import io
        import urllib.error
        module = load('controller'); controller = module.Controller(home=SCRATCH)
        controller.token = lambda: 'fixture'
        error = urllib.error.HTTPError(controller.base + '/control/prepare-harness', 409, 'conflict', {},
            io.BytesIO(b'{"error":"stale_driver"}'))
        with patch.object(controller.opener, 'open', side_effect=error):
            try:
                controller.request('prepare-harness', {})
            except Exception as caught:
                self.assertIsInstance(caught, module.ControlFailure, 'raw HTTP error must not escape setup boundary')
                self.assertEqual(caught.code, 'stale_driver')
                self.assertFalse(caught.retryable)
            else:
                self.fail('preparation refusal must fail closed')

    def test_controller_retirement_precedes_reservation_and_forgets_old_endpoint(self):
        import subprocess
        controller = load('controller').Controller(home=SCRATCH)
        name = load('plugin_identity').daemon_name('["cold","default"]')
        admission = {'lease': 'lease', 'endpoint': controller.base.replace('http:', 'ws:') + '/devtools/browser/new'}
        controller.driver_endpoints[name] = controller.base.replace('http:', 'ws:') + '/devtools/browser/old'
        calls = []
        def request(op, data):
            calls.append(op)
            if op == 'prepare-harness': return {'prepared': True, 'retired': True}
            if op == 'begin-harness': return {'attempt': 'attempt'}
            return {'verified': True, 'registered': True}
        controller.request = request
        def run(args, **kwargs):
            script = args[-1]
            if 'prepare_named_driver(' in script:
                self.assertIn("None, ipc=_ipc", script, 'retired endpoint must not force old-generation refusal')
            return subprocess.CompletedProcess(args, 0, json.dumps({'target_id': 'target', 'session_id': 'session', 'name': name}), '')
        with patch.object(load('controller').subprocess, 'run', side_effect=run):
            controller.prepare_driver(admission, name)
        self.assertEqual(calls[:2], ['prepare-harness', 'begin-harness'])


if __name__ == '__main__':
    unittest.main()
