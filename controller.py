"""Synchronous admission client, using the existing runtime only."""
import json
import os
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load(name):
    import importlib.util
    spec = importlib.util.spec_from_file_location('_controller_bundle_entry', ROOT / '__init__.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_sibling(name)

def effective_home(home=None):
    if home is None:
        try:
            from hermes_constants import get_hermes_home
            home = get_hermes_home()
        except ImportError:
            home = os.environ.get('HERMES_HOME', str(Path.home() / '.hermes'))
    return Path(home).expanduser().resolve()


def state_directory(home=None):
    return effective_home(home) / 'plugin-data' / load('plugin_identity').plugin_id()
DEFAULT_PORT = 19347


def bundle_preamble():
    """Child-only private loader, independent of checkout and generic imports."""
    return (
        'import importlib.util as _dyra_util\n'
        f'_dyra_spec = _dyra_util.spec_from_file_location("_dyra_bundle_entry", {str(ROOT / "__init__.py")!r})\n'
        '_dyra_bundle = _dyra_util.module_from_spec(_dyra_spec)\n'
        '_dyra_spec.loader.exec_module(_dyra_bundle)\n'
        '_dyra_controller = _dyra_bundle.load_sibling("controller")\n'
        'Controller = _dyra_controller.Controller\n'
        'restore_driver_selection = _dyra_controller.restore_driver_selection\n'
        'ControlFailure = _dyra_controller.ControlFailure\n'
        'prepare_named_driver = _dyra_controller.prepare_named_driver\n'
        'wait_named_process_exit = _dyra_controller.wait_named_process_exit\n')


class ControlFailure(ConnectionError):
    def __init__(self, code, *, retryable=False):
        allowed = {'unsupported_platform', 'profile_conflict', 'detached', 'startup', 'consent_expired', 'helper_ax', 'ws_denied', 'profile_marker',
                   'resource_limit', 'owned_target_lost', 'lease_conflict', 'stale_driver', 'upstream_uncertain', 'scope_create_rejected', 'journal_invalid', 'journal_commit_failed', 'journal_bootstrap_pending', 'journal_endpoint_unavailable', 'journal_generation_ambiguous'}
        self.code = code if code in allowed else 'upstream_uncertain'
        self.retryable = retryable and self.code in {'startup', 'consent_expired', 'helper_ax'}
        super().__init__(self.code)


def prepare_named_driver(name, endpoint, expected_endpoint, *, ipc, validate_socket, wait_stopped, ensure, wait_missing=None, _retire=False, target_id=None):
    """Preparation only; stale bindings refuse until registered quiet retirement.

    Unknown daemons are never stopped; normal exact status verification may still
    admit them. No downstream model action or CDP mutation is retried here.
    """
    changed = _retire or (expected_endpoint is not None and expected_endpoint != endpoint)
    try:
        validate_socket()
        present = True
    except FileNotFoundError:
        present = False
    if not present and expected_endpoint is not None:
        if wait_missing is None:
            raise FileNotFoundError('known named driver exit not observed')
        wait_missing()
    if changed and present:
        # An endpoint string is not a process-generation capability. Only the
        # broker's registered drain path may retire a named daemon, after its
        # downstream fence. Refuse preparation rather than reload an unknown.
        raise PermissionError('registered quiet retirement required')
    try:
        validate_socket()
        present = True
    except FileNotFoundError:
        present = False
    if not present or changed:
        ensure()
    validate_socket()
    connection, token = ipc.connect(name, timeout=5)
    try:
        status = ipc.request(connection, token, {'meta': 'connection_status'})
    finally:
        connection.close()
    if (not changed and expected_endpoint == endpoint and isinstance(status, dict)
            and status.get('error') in {'cdp_disconnected', 'not_attached'}):
        return prepare_named_driver(name, endpoint, expected_endpoint, ipc=ipc,
            validate_socket=validate_socket, wait_stopped=wait_stopped, wait_missing=wait_missing, ensure=ensure, _retire=True, target_id=target_id)
    if (not isinstance(status, dict) or not status.get('target_id')
            or not status.get('session_id') or status.get('error')):
        raise PermissionError('exact driver selection unavailable')
    if target_id is not None and status['target_id'] != target_id:
        def request(payload):
            connection, token = ipc.connect(name, timeout=5)
            try:
                return ipc.request(connection, token, payload)
            finally:
                connection.close()
        attached = request({'method': 'Target.attachToTarget', 'params': {'targetId': target_id, 'flatten': True}})
        sid = attached.get('result', {}).get('sessionId')
        if not sid or attached.get('error'):
            raise PermissionError('borrowed attach unavailable')
        changed = request({'meta': 'set_session', 'target_id': target_id, 'session_id': sid})
        if changed.get('error') or changed.get('session_id') != sid:
            raise PermissionError('borrowed selection rejected')
        status = request({'meta': 'connection_status'})
        if status.get('error') or status.get('target_id') != target_id or status.get('session_id') != sid:
            raise PermissionError('borrowed selection not proven')
    # Never expose URLs, page content or IPC tokens to the coordinator.
    return {'target_id': status['target_id'], 'session_id': status['session_id']}


def restore_driver_selection(selection, *, lease, name, control, ipc_request=None):
    """Restore pre-preamble verified runtime selection, never navigate/replay.

    The broker revalidates exact lease, target and live client session before
    supported named IPC changes; identifiers are runtime-only, without URLs.
    """
    target, sid = selection.get('target_id'), selection.get('session_id')
    if not isinstance(target, str) or not target or not isinstance(sid, str) or not sid:
        raise PermissionError('pre-exec selection unavailable')
    verified = control.request('verify-driver', {'lease': lease, 'target_id': target, 'session_id': sid})
    if verified.get('verified') is not True:
        raise PermissionError('pre-exec selection revoked')
    if ipc_request is None:
        from browser_harness import _ipc
        def ipc_request(payload):
            connection, token = _ipc.connect(name, timeout=5)
            try:
                return _ipc.request(connection, token, payload)
            finally:
                connection.close()
    displaced = ipc_request({'meta': 'connection_status'})
    changed = ipc_request({'meta': 'set_session', 'target_id': target, 'session_id': sid})
    status = ipc_request({'meta': 'connection_status'})
    if (changed.get('error') or changed.get('session_id') != sid or status.get('error')
            or status.get('target_id') != target or status.get('session_id') != sid):
        raise PermissionError('restored selection unproven')
    verified = control.request('verify-driver', {'lease': lease, 'target_id': target, 'session_id': sid})
    if verified.get('verified') is not True:
        raise PermissionError('restored selection revoked')
    if (not displaced.get('error') and displaced.get('target_id') != target
            and displaced.get('target_id') and displaced.get('session_id')):
        try:
            control.request('cleanup-preamble', {'lease': lease,
                'target_id': displaced['target_id'], 'session_id': displaced['session_id'],
                'selected_target_id': target, 'selected_session_id': sid})
        except urllib.error.HTTPError as error:
            if error.code != 409:
                raise
            error.close()  # Unsafe/used blank retained; never clear risk or replay.


def wait_named_process_exit(pid, *, timeout=5):
    """Observe exit, including unreaped zombies; never signal or trust PID reuse."""
    import psutil
    if type(pid) is not int or not 0 < pid < 2 ** 31:
        raise PermissionError('invalid named daemon pid')
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    deadline = time.monotonic() + timeout
    while True:
        try:
            if not process.is_running() or process.status() in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}:
                return
        except psutil.NoSuchProcess:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError('named shutdown pending')
        time.sleep(.05)


class Controller:
    app_helpers_enabled = True  # Source-only until this plugin/server bundle is activated.
    def __init__(self, *, home=None, port=DEFAULT_PORT, token_file=None, starter=None):
        self.home = effective_home(home)
        self.closed = False
        self.port = int(port)
        self.token_file = Path(token_file) if token_file is not None else state_directory(self.home) / 'control-token'
        self.starter = starter or self.start
        self.base = f'http://127.0.0.1:{self.port}'
        self.driver_endpoints = {}  # Runtime-only capabilities; never journaled.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def token(self):
        metadata = self.token_file.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PermissionError('control token must be owned regular file mode 0600')
        return self.token_file.read_text().strip()

    def health(self):
        # Refusal is absence. Any responding but unproven listener is a conflict;
        # never launch over it or send lifecycle controls to another profile.
        import errno
        try:
            with self.opener.open(self.base + '/health', timeout=1) as response:
                body = json.load(response)
        except urllib.error.URLError as error:
            if getattr(error.reason, 'errno', None) == errno.ECONNREFUSED:
                return False
            raise ControlFailure('profile_conflict') from None
        except (OSError, ValueError):
            raise ControlFailure('profile_conflict') from None
        if not isinstance(body, dict) or body.get('service') != load('plugin_identity').plugin_id():
            raise ControlFailure('profile_conflict')
        try:
            identity = self.request('identity', {})
        except Exception:
            raise ControlFailure('profile_conflict') from None
        if identity != {'service': load('plugin_identity').plugin_id(), 'home': str(self.home), 'protocol': 1}:
            raise ControlFailure('profile_conflict')
        return True

    def detach(self, *, timeout=5):
        """Authenticated bounded drain; never ensure/start or restore config."""
        if not self.health():
            return self.offline_detach(timeout=timeout)
        return self.request('detach', {'timeout': max(0, min(float(timeout), 10))})

    def offline_detach(self, *, timeout=5):
        """Recover only private inventory and trusted journal, never launch/connect Chrome."""
        cleanup = load('harness_cleanup')
        try:
            with cleanup.service_lock(self.home):
                return self._offline_detach_locked(cleanup, timeout=timeout)
        except Exception:
            # A starting service may hold authority before binding its listener.
            # Health is rechecked, but conflict never authorizes offline cleanup.
            try:
                if self.health():
                    return self.request('detach', {'timeout': max(0, min(float(timeout), 10))})
            except Exception:
                pass
            return {'status': 'blocked', 'blockers': ['service_lock']}

    def _offline_detach_locked(self, cleanup, *, timeout):
        import asyncio
        directory = state_directory(self.home)
        try:
            if self.health():
                return self.request('detach', {'timeout': max(0, min(float(timeout), 10))})
            inventory = cleanup.InventoryJournal(directory / 'harness-inventory.json', self.home).load()
            if inventory['pending']:
                return {'status': 'blocked', 'blockers': ['harness_unverified']}
            if not inventory['records']:
                return {'status': 'absent', 'blockers': []}
            if self.health():
                return self.request('detach', {'timeout': max(0, min(float(timeout), 10))})
            journal = load('state_journal').StateJournal(directory / 'ownership.json')
            broker = load('broker').SessionBroker(object(), control_token='', journal=journal)
            broker.profile_home = str(self.home)
            # Recovery checks durable guards and exact disconnected named IPC;
            # connector is deliberately unusable and no leases are manufactured.
            blockers = asyncio.run(broker.cleanup_harnesses(timeout=max(0, min(float(timeout), 10))))
            return {'status': 'blocked' if blockers else 'detached', 'blockers': blockers}
        except Exception:
            return {'status': 'blocked', 'blockers': ['harness_inventory']}

    def stop(self, drained, *, timeout=5):
        """Stop only the authenticated quiet child; observe refusal, never signal."""
        if not self.health():
            return {'status': 'absent', 'blockers': []}
        if (drained.get('status') != 'detached' or drained.get('blockers')
                or not isinstance(drained.get('drain_id'), str) or not drained['drain_id']):
            return {'status': 'blocked', 'blockers': ['quiet_drain_required']}
        reply = self.request('stop', {'home': str(self.home), 'drain_id': drained['drain_id']})
        if reply != {'status': 'stopping', 'blockers': []}:
            return {'status': 'blocked', 'blockers': ['stop_unconfirmed']}
        deadline = time.monotonic() + max(0, min(float(timeout), 10))
        while self.health():
            if time.monotonic() >= deadline:
                return {'status': 'blocked', 'blockers': ['listener']}
            time.sleep(.05)
        return {'status': 'detached', 'blockers': []}

    def close(self):
        # Retire this controller generation only. In-flight middleware owns its
        # lease until finally/release; unload must not revoke active operations.
        self.closed = True
        self.driver_endpoints.clear()

    def start(self):
        import platform
        if platform.system() != 'Darwin':
            raise ControlFailure('unsupported_platform')
        cleanup = load('harness_cleanup')
        try:
            with cleanup.service_lock(self.home) as lock_fd:
                if self.health():
                    return
                # Shared open-file description keeps ownership uninterrupted
                # from spawn through the child's listener and final cleanup.
                subprocess.Popen([sys.executable, str(ROOT / 'server.py'), '--port', str(self.port), '--home', str(self.home), '--token-file', str(self.token_file), '--service-lock-fd', str(lock_fd)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=(lock_fd,))
        except Exception:
            if self.health():
                return
            raise ControlFailure('profile_conflict') from None

    def ensure(self):
        if self.closed:
            raise ControlFailure('detached')
        if self.health():
            return
        if self.starter == self.start:
            self.start()
        else:
            try:
                with load('harness_cleanup').service_lock(self.home):
                    if self.health():
                        return
                    self.starter()
            except Exception:
                if self.health():
                    return
                raise ControlFailure('profile_conflict') from None
        deadline = time.monotonic() + 5
        while not self.health():
            if time.monotonic() >= deadline:
                raise ControlFailure('startup')
            time.sleep(.05)

    def request(self, operation, data):
        encoded = json.dumps(data).encode()
        request = urllib.request.Request(self.base + '/control/' + operation, data=encoded, headers={'Authorization': 'Bearer ' + self.token(), 'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=35) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            # Keep the existing exact-resume verification path; only acquire
            # responses carry a setup retry boundary.
            if operation not in {'acquire', 'driver-capacity', 'prepare-harness', 'begin-harness', 'register-harness'}:
                raise
            try:
                body = json.load(error)
                code = body.get('error', 'upstream_uncertain')
                retryable = body.get('retryable') is True
            except (ValueError, OSError, AttributeError):
                code, retryable = 'upstream_uncertain', False
            finally:
                error.close()
            raise ControlFailure(code, retryable=retryable) from None
        except (OSError, ValueError):
            raise ControlFailure('upstream_uncertain') from None

    def acquire(self, namespace):
        self.ensure()
        return self.request('acquire', {'namespace': namespace})['lease']

    def list_existing(self, expected_origin, *, namespace='__existing_discovery__'):
        return self.request('list-existing', {'expected_origin': expected_origin, 'namespace': namespace})

    def borrow_existing(self, namespace, target_id, context_id, expected_origin):
        return self.request('borrow-existing', {'namespace': namespace, 'target_id': target_id,
            'context_id': context_id, 'expected_origin': expected_origin})

    def acquire_session(self, namespace, *, kind='browser'):
        self.ensure()
        self.request('activate', {})
        return self.request('acquire', {'namespace': namespace, 'kind': kind})

    def prepare_driver(self, admission, name, *, expected_endpoint=None):
        """Prestart the supported harness daemon with a per-child CDP binding.

        Native browser_exec will reuse BU_NAME's daemon, whose endpoint is pinned
        at startup. Never execute model code here or retry a native action. An
        existing daemon must prove its exact broker session before dispatch.
        """
        import re
        from urllib.parse import urlsplit
        if (not isinstance(name, str) or len(name) > 64
                or not re.fullmatch(re.escape(load('plugin_identity').harness_prefix()) + r'[A-Za-z0-9_-]+', name)):
            raise ValueError('invalid internal driver name')
        endpoint = admission['endpoint']
        parsed = urlsplit(endpoint)
        if (parsed.scheme != 'ws' or parsed.hostname != '127.0.0.1' or parsed.port != self.port
                or not parsed.path.startswith('/devtools/browser/') or parsed.query or parsed.fragment):
            raise PermissionError('unexpected scoped broker endpoint')
        prepared = self.request('prepare-harness', {'lease': admission['lease'], 'name': name, 'endpoint': endpoint})
        if prepared.get('prepared') is not True:
            raise ControlFailure('stale_driver')
        if prepared.get('retired') is True:
            self.driver_endpoints.pop(name, None)
            expected_endpoint = None
        attempt = self.request('begin-harness', {'lease': admission['lease'], 'name': name, 'endpoint': endpoint})['attempt']
        # Only nonsecret runtime-location settings are inherited. No .env switch,
        # cloud credentials, GUI fallback or process-global os.environ mutation.
        allowed = ('HOME', 'PATH', 'TMPDIR', 'PYTHONPATH', 'BH_RUNTIME_DIR',
                   'BH_RUNTIME_DIR_SHARED', 'BH_TMP_DIR', 'BH_TMP_DIR_SHARED')
        env = {key: os.environ[key] for key in allowed if key in os.environ}
        env.update(BU_NAME=name, BU_CDP_WS=endpoint, ANONYMIZED_TELEMETRY='false')
        previous = expected_endpoint or self.driver_endpoints.get(name)
        if previous is not None:
            old = urlsplit(previous)
            if (old.scheme != 'ws' or old.hostname != '127.0.0.1' or old.port != self.port
                    or not old.path.startswith('/devtools/browser/') or old.query or old.fragment):
                raise PermissionError('unexpected previous scoped endpoint')
        script = (
            'import json, os, stat, sys, time\n'
            'from pathlib import Path\n'
            + bundle_preamble() +
            'from browser_harness.admin import ensure_daemon\n'
            'from browser_harness import _ipc\n'
            'def validate_socket():\n'
            f'    metadata = Path(_ipc.sock_addr({name!r})).lstat()\n'
            '    assert stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid()\n'
            '    assert stat.S_IMODE(metadata.st_mode) in {0o600, 0o700}\n'
            'def wait_stopped(pid):\n'
            '    wait_named_process_exit(pid)\n'
            f'    _ipc.cleanup_endpoint({name!r})\n'
            'def wait_missing():\n'
            f'    path = _ipc.pid_path({name!r})\n'
            '    try: metadata = path.lstat()\n'
            '    except FileNotFoundError: return\n'
            '    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():\n'
            '        raise PermissionError("named pid record untrusted")\n'
            '    raw = path.read_text()\n'
            '    try: record = json.loads(raw)\n'
            '    except ValueError: record = int(raw.strip())\n'
            '    pid = record.get("pid") if isinstance(record, dict) else record\n'
            '    wait_named_process_exit(pid)\n'
            'def ensure():\n'
            f'    if not Path(_ipc.sock_addr({name!r})).exists():\n'
            '        try:\n'
            f'            Controller(port={self.port!r}, token_file={str(self.token_file)!r}).request(\'driver-capacity\', {{\'lease\': {admission["lease"]!r}}})\n'
            '        except ControlFailure as error:\n'
            '            print(json.dumps({"error": error.code}))\n'
            '            sys.exit(0)\n'
            f'        ensure_daemon(wait=10, name={name!r})\n'
            f'status = prepare_named_driver({name!r}, {endpoint!r}, {previous!r}, ipc=_ipc, '
            f'validate_socket=validate_socket, wait_stopped=wait_stopped, wait_missing=wait_missing, ensure=ensure, target_id={admission.get("borrowed_target_id")!r})\n'
            'print(json.dumps(status))\n')
        try:
            result = subprocess.run([sys.executable, '-c', script], env=env,
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=20, check=False)
        except (subprocess.TimeoutExpired, OSError):
            raise ControlFailure('stale_driver') from None
        if result.returncode != 0:
            raise ControlFailure('stale_driver')
        try:
            status = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise ControlFailure('stale_driver') from None
        if isinstance(status, dict) and status.get('error') == 'resource_limit':
            raise ControlFailure('resource_limit')
        if (not isinstance(status, dict) or not status.get('target_id')
                or not status.get('session_id') or status.get('error')):
            raise ControlFailure('stale_driver')
        selection = {'lease': admission['lease'], 'target_id': status['target_id'],
                     'session_id': status['session_id']}
        try:
            verified = self.request('verify-driver', selection)
            return self.register_driver(admission, name, attempt, status, verified, env)
        except urllib.error.HTTPError as error:
            # Only the broker's exact active-target revocation tombstone permits
            # a fresh attach. Generic 403, paused/released targets and transport
            # errors fail closed. This is preparation, never model-code replay.
            if error.code != 403:
                raise
            try:
                body = json.load(error)
            except (ValueError, OSError):
                raise PermissionError('driver verification rejected') from None
            finally:
                error.close()
            if body.get('error') != 'fresh_attach_required':
                raise PermissionError('driver verification rejected') from None
        attach = (
            'import json, os, stat\n'
            'from pathlib import Path\n'
            'from browser_harness import _ipc\n'
            f'metadata = Path(_ipc.sock_addr({name!r})).lstat()\n'
            'assert stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid()\n'
            'assert stat.S_IMODE(metadata.st_mode) in {0o600, 0o700}\n'
            'def request(payload):\n'
            f'    connection, token = _ipc.connect({name!r}, timeout=5)\n'
            '    try:\n'
            '        return _ipc.request(connection, token, payload)\n'
            '    finally:\n'
            '        connection.close()\n'
            f'response = request({{"method": "Target.attachToTarget", "params": {{"targetId": {status["target_id"]!r}, "flatten": True}}}})\n'
            'sid = response["result"]["sessionId"]\n'
            f'changed = request({{"meta": "set_session", "session_id": sid, "target_id": {status["target_id"]!r}}})\n'
            'assert changed.get("session_id") == sid and not changed.get("error")\n'
            'status = request({"meta": "connection_status"})\n'
            'print(json.dumps(status))\n')
        try:
            result = subprocess.run([sys.executable, '-c', attach], env=env,
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=20, check=False)
        except (subprocess.TimeoutExpired, OSError):
            raise ControlFailure('stale_driver') from None
        if result.returncode != 0:
            raise ControlFailure('stale_driver')
        fresh = json.loads(result.stdout)
        if (fresh.get('target_id') != status['target_id'] or not fresh.get('session_id')
                or fresh['session_id'] == status['session_id'] or fresh.get('error')):
            raise PermissionError('fresh scoped selection not proven')
        verified = self.request('verify-driver', {'lease': admission['lease'],
                            'target_id': fresh['target_id'], 'session_id': fresh['session_id']})
        return self.register_driver(admission, name, attempt, fresh, verified, env)

    def register_driver(self, admission, name, attempt, status, verified, env):
        if verified.get('verified') is not True:
            raise ControlFailure('stale_driver')
        script = ('import json\n' + bundle_preamble() +
            f'cleanup = _dyra_bundle.load_sibling("harness_cleanup")\n'
            f'print(json.dumps(cleanup.capture({name!r}, {admission["endpoint"]!r}, {status["target_id"]!r}, {status["session_id"]!r})))\n')
        try:
            result = subprocess.run([sys.executable, '-c', script], env=env,
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=False)
            if result.returncode:
                raise ControlFailure('stale_driver')
            record = json.loads(result.stdout)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            raise ControlFailure('stale_driver') from None
        reply = self.request('register-harness', {'lease': admission['lease'], 'name': name,
            'endpoint': admission['endpoint'], 'attempt': attempt, 'target_id': status['target_id'],
            'session_id': status['session_id'], 'record': record})
        if reply.get('registered') is not True:
            raise ControlFailure('stale_driver')
        self.driver_endpoints[name] = admission['endpoint']
        return {**verified, 'target_id': status['target_id'], 'session_id': status['session_id']}

    def release(self, lease):
        return self.request('release', {'lease': lease})

    def bind_vault(self, lease, session='default', *, status_reader=None):
        if status_reader is None:
            import importlib.util
            spec = importlib.util.spec_from_file_location('dyra_native_binding', ROOT / 'binding.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            status_reader = module.driver_status
        status = status_reader(session)
        self.request('bind-vault', {'lease': lease, 'target_id': status['target_id'], 'session_id': status['session_id']})
        return status


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Explicit user control; never starts Chrome')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--home', type=Path)
    parser.add_argument('--token-file', type=Path)
    commands = parser.add_subparsers(dest='command', required=True)
    takeover = commands.add_parser('takeover')
    takeover.add_argument('action', choices=('status', 'pause', 'release', 'resume'))
    takeover.add_argument('--namespace', required=True)
    takeover.add_argument('--target')
    upload = commands.add_parser('upload')
    upload.add_argument('action', choices=('status', 'completed', 'canceled'))
    upload.add_argument('--namespace', required=True)
    upload.add_argument('--target')
    policy = commands.add_parser('input-mode')
    policy.add_argument('--namespace', required=True)
    policy.add_argument('--mode', choices=('emulate', 'foreground', 'deny'), required=True)
    abort = commands.add_parser('abort-bootstrap')
    abort.add_argument('--namespace', required=True)
    abort.add_argument('--acknowledge-unknown-launch', action='store_true', required=True)
    args = parser.parse_args(argv)
    controller = Controller(home=args.home, port=args.port, token_file=args.token_file)
    if args.command == 'abort-bootstrap':
        result = controller.request('abort-bootstrap', {'namespace': args.namespace,
            'acknowledge_unknown_launch': args.acknowledge_unknown_launch})
    elif args.command == 'upload':
        if args.action == 'status':
            result = controller.request('upload-status', {'namespace': args.namespace})
        else:
            if not args.target:
                parser.error('--target required to resolve upload')
            result = controller.request('upload-resolve', {'namespace': args.namespace,
                'target_id': args.target, 'outcome': args.action})
    elif args.command == 'takeover':
        if args.action == 'status':
            result = controller.request('takeover-status', {'namespace': args.namespace})
        else:
            if not args.target:
                parser.error('--target required for takeover action')
            result = controller.request('takeover', {'namespace': args.namespace, 'target_id': args.target, 'action': args.action})
    else:
        result = controller.request('input-mode', {'namespace': args.namespace, 'mode': args.mode})
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
