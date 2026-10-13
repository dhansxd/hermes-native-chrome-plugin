"""Service ownership race fixtures; isolated profiles, never Chrome or signals."""
import asyncio
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from test_harness_cleanup import load, ROOT, SCRATCH


CHILD_SERVER = r'''
import asyncio, importlib.util, json, sys
from pathlib import Path
from aiohttp import web
root, home, port = sys.argv[1:4]
inherited_fd = int(sys.argv[4]) if len(sys.argv) > 4 else None
spec = importlib.util.spec_from_file_location('_lock_fixture', Path(root) / '__init__.py')
bundle = importlib.util.module_from_spec(spec); spec.loader.exec_module(bundle)
server = bundle.load_sibling('server')
# Only the application is a fixture: server.serve owns real lock and loopback.
def make_app(*, home, token_file, port, stop_event):
    app = web.Application()
    async def health(request):
        return web.json_response({'service': bundle.load_sibling('plugin_identity').plugin_id()})
    async def identity(request):
        return web.json_response({'service': bundle.load_sibling('plugin_identity').plugin_id(), 'home': str(home), 'protocol': 1})
    async def detach(request):
        return web.json_response({'status': 'detached', 'blockers': [], 'live': True})
    app.router.add_get('/health', health)
    app.router.add_post('/control/identity', identity)
    app.router.add_post('/control/detach', detach)
    async def stop():
        await asyncio.to_thread(sys.stdin.readline)
        stop_event.set()
    asyncio.create_task(stop())
    return app
server.make_app = make_app
try:
    kwargs = {'service_lock_fd': inherited_fd} if inherited_fd is not None else {}
    asyncio.run(server.serve(home=home, port=int(port), **kwargs))
except Exception as error:
    print(type(error).__name__, flush=True)
    sys.exit(23)
'''


class ServiceLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='hlock-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / 'profile'
        self.controller_module = load('controller')
        self.directory = self.controller_module.state_directory(self.home)
        self.directory.mkdir(parents=True, mode=0o700)
        self.control = self.controller_module.Controller(home=self.home)

    def test_offline_conflict_rechecks_health_and_never_claims_absence(self):
        import hashlib
        binding = hashlib.sha256(json.dumps([str(self.home.resolve()), load('plugin_identity').plugin_id()],
            separators=(',', ':')).encode()).hexdigest()
        registry = self.home.parent / '.dyra-service-locks'
        registry.mkdir(mode=0o700, exist_ok=True)
        path = registry / (binding + '.lock')
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with patch.object(self.control, 'health', return_value=False) as health:
            reply = self.control.offline_detach(timeout=0)
        self.assertEqual(reply, {'status': 'blocked', 'blockers': ['service_lock']})
        health.assert_called_once_with()

    def test_offline_lock_owner_blocks_all_controller_start_paths_without_spawn(self):
        with load('harness_cleanup').service_lock(self.home):
            for method in (self.control.start, self.control.ensure):
                with self.subTest(method=method.__name__), patch.object(self.control, 'health', return_value=False), \
                        patch.object(self.controller_module.subprocess, 'Popen') as spawn:
                    with self.assertRaises(self.controller_module.ControlFailure) as caught:
                        method()
                    self.assertEqual(caught.exception.code, 'profile_conflict')
                    spawn.assert_not_called()
        # Injected starters are guarded too, not just the standard child path.
        with load('harness_cleanup').service_lock(self.home), patch.object(self.control, 'health', return_value=False), \
                patch.object(self.control, 'starter') as starter:
            with self.assertRaises(self.controller_module.ControlFailure):
                self.control.ensure()
            starter.assert_not_called()

    def test_unsafe_lock_failures_never_enter_inventory_or_spawn(self):
        # Characterization of the secure fd/path checks introduced with the lock.
        cleanup = load('harness_cleanup')
        with cleanup.service_lock(self.home):
            pass
        import hashlib
        binding = hashlib.sha256(json.dumps([str(self.home.resolve()), load('plugin_identity').plugin_id()],
            separators=(',', ':')).encode()).hexdigest()
        path = self.home.parent / '.dyra-service-locks' / (binding + '.lock')
        for variant in ('mode', 'symlink', 'hardlink'):
            with self.subTest(variant=variant):
                if variant == 'mode':
                    path.chmod(0o644)
                elif variant == 'symlink':
                    path.unlink(); path.symlink_to(self.home / 'uncreated')
                else:
                    path.unlink(); path.touch(mode=0o600); os.link(path, self.home / 'alias')
                with patch.object(self.control, 'health', return_value=False) as health, \
                        patch.object(cleanup.InventoryJournal, 'load') as inventory, \
                        patch.object(self.controller_module.subprocess, 'Popen') as spawn:
                    self.assertEqual(self.control.offline_detach(timeout=0),
                        {'status': 'blocked', 'blockers': ['service_lock']})
                    with self.assertRaises(self.controller_module.ControlFailure):
                        self.control.start()
                    inventory.assert_not_called(); spawn.assert_not_called()
                    self.assertGreaterEqual(health.call_count, 2)

    def test_replaced_lock_after_open_fails_closed_without_cleanup(self):
        cleanup = load('harness_cleanup')
        original = cleanup.os.open
        def replacing_open(path, flags, *args, **kwargs):
            fd = original(path, flags, *args, **kwargs)
            if isinstance(path, str) and path.endswith('.lock'):
                os.unlink(path, dir_fd=kwargs['dir_fd'])
                replacement = original(path, os.O_CREAT | os.O_RDWR, 0o600, dir_fd=kwargs['dir_fd'])
                os.close(replacement)
            return fd
        with patch.object(cleanup.os, 'open', side_effect=replacing_open), \
                patch.object(self.control, 'health', return_value=False), \
                patch.object(cleanup.InventoryJournal, 'load') as inventory:
            self.assertEqual(self.control.offline_detach(timeout=0),
                {'status': 'blocked', 'blockers': ['service_lock']})
            inventory.assert_not_called()

    def test_identity_home_binding_and_stable_inode_do_not_use_lifecycle_lock(self):
        cleanup = load('harness_cleanup')
        import hashlib
        binding = hashlib.sha256(json.dumps([str(self.home.resolve()), load('plugin_identity').plugin_id()],
            separators=(',', ':')).encode()).hexdigest()
        lock_path = self.home.parent / '.dyra-service-locks' / (binding + '.lock')
        with cleanup.service_lock(self.home):
            inode = lock_path.stat().st_ino
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(lock_path.parent.stat().st_mode & 0o777, 0o700)
            with cleanup.service_lock(self.home / 'different'):
                pass
            with patch.object(load('plugin_identity'), 'plugin_id', return_value='dyra-native-chrome-verification'):
                with cleanup.service_lock(self.home):
                    pass
        # Taking lifecycle.lock cannot obstruct service admission.
        path = self.directory / 'lifecycle.lock'
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with cleanup.service_lock(self.home):
                self.assertEqual(lock_path.stat().st_ino, inode)
        finally:
            os.close(fd)

    def test_controller_hands_lock_to_child_without_unlocked_start_gap(self):
        captured = {}
        def spawn(argv, **kwargs):
            captured.update(argv=argv, kwargs=kwargs)
            fd = kwargs.get('pass_fds', ())
            if not fd:
                return
            self.assertIn('--service-lock-fd', argv)
            self.assertEqual(int(argv[argv.index('--service-lock-fd') + 1]), fd[0])
            with self.assertRaises(load('harness_cleanup').ServiceLockBusy):
                with load('harness_cleanup').service_lock(self.home):
                    pass
        with patch.object(self.control, 'health', return_value=False), \
                patch.object(self.controller_module.subprocess, 'Popen', side_effect=spawn):
            self.control.start()
        self.assertEqual(len(captured['kwargs'].get('pass_fds', ())), 1,
            'startup must inherit owned lock, not reacquire after an unlocked gap')
        self.assertIn('--service-lock-fd', captured['argv'])

    def test_inherited_lock_survives_parent_close_until_child_runner_exit(self):
        cleanup = load('harness_cleanup')
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
        with cleanup.service_lock(self.home) as fd:
            child = subprocess.Popen([sys.executable, '-c', CHILD_SERVER, str(ROOT), str(self.home), str(port), str(fd)],
                pass_fds=(fd,), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.control.port = port; self.control.base = f'http://127.0.0.1:{port}'
        self.control.token_file.write_text('fixture'); self.control.token_file.chmod(0o600)
        try:
            import time
            deadline = time.monotonic() + 5
            while not self.control.health():
                if child.poll() is not None:
                    output, errors = child.communicate(input='\n', timeout=5)
                    self.fail((child.returncode, output, errors))
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
            with self.assertRaises(cleanup.ServiceLockBusy):
                with cleanup.service_lock(self.home):
                    pass
        finally:
            if child.poll() is None:
                child.communicate(input='\n', timeout=5)
        self.assertEqual(child.returncode, 0)
        with cleanup.service_lock(self.home):
            pass

    def test_real_controller_start_cli_handoff_and_authenticated_stop_without_chrome(self):
        # Characterization of actual Popen -> server.main inherited-fd parsing.
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
        self.control.port = port; self.control.base = f'http://127.0.0.1:{port}'
        lifecycle = load('lifecycle')
        lifecycle._save(self.home, {'version': 1, 'desired_enabled': False,
            'phase': 'detaching', 'port': port, 'keys': {}})
        original_spawn = subprocess.Popen
        children = []
        def spawn(argv, **kwargs):
            kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            child = original_spawn(argv, **kwargs); children.append(child); return child
        with patch.object(self.controller_module.subprocess, 'Popen', side_effect=spawn):
            self.control.start()
        child = children[0]
        try:
            import time
            deadline = time.monotonic() + 5
            while not self.control.health():
                self.assertIsNone(child.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
            self.assertEqual(lifecycle.default_drain(home=self.home, port=port)['status'], 'detached')
        finally:
            # No PID signals; the owned authenticated stop is the only teardown.
            if child.poll() is None and self.control.health():
                drained = self.control.detach(timeout=0)
                self.control.stop(drained)
            output, errors = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, (output, errors))
        self.assertEqual(errors, '')
        with load('harness_cleanup').service_lock(self.home):
            pass

    def child(self, port):
        return subprocess.Popen([sys.executable, '-c', CHILD_SERVER, str(ROOT), str(self.home), str(port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_concurrent_offline_cleanup_excludes_child_server_until_release(self):
        cleanup = load('harness_cleanup')
        entered = threading.Event(); release = threading.Event()
        original_load = cleanup.InventoryJournal.load
        def held_load(inventory):
            entered.set()
            if not release.wait(10):
                raise TimeoutError('fixture barrier')
            return original_load(inventory)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
        self.control.port = port; self.control.base = f'http://127.0.0.1:{port}'
        replies = []
        worker = threading.Thread(target=lambda: replies.append(self.control.offline_detach(timeout=0)))
        with patch.object(cleanup.InventoryJournal, 'load', held_load):
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                child = self.child(port)
                output, errors = child.communicate(input='\n', timeout=5)
                self.assertEqual(child.returncode, 23, (output, errors))
                self.assertIn('ServiceLockBusy', output)
                self.assertFalse(self.control.health())
            finally:
                release.set(); worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(replies, [{'status': 'absent', 'blockers': []}])
        # Same port/profile can actually serve once the offline owner releases.
        self.control.token_file.write_text('fixture'); self.control.token_file.chmod(0o600)
        child = self.child(port)
        try:
            import time
            deadline = time.monotonic() + 5
            while not self.control.health():
                self.assertIsNone(child.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
            self.assertEqual(self.control.offline_detach(timeout=0),
                {'status': 'detached', 'blockers': [], 'live': True})
        finally:
            output, errors = child.communicate(input='\n', timeout=5)
        self.assertEqual(child.returncode, 0, (output, errors))
        with cleanup.service_lock(self.home):
            pass  # Server lock includes runner cleanup and is released afterward.


if __name__ == '__main__':
    unittest.main()
