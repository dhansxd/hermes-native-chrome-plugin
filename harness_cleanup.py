"""Exact named generations and private metadata inventory; never discover names."""
import hashlib
import json
import re
import secrets
import state_journal as ownership
import plugin_identity
from contextlib import contextmanager
import fcntl


class ServiceLockBusy(PermissionError):
    """The profile/identity service is owned by another runner or cleanup."""


@contextmanager
def service_lock(home, *, inherited_fd=None):
    """Nonblocking owner-only service authority; never unlink the lock inode.

    Separate from lifecycle.lock: attach holds that lock while starting us.
    Importing this module is passive. Only an owning runner/operation calls here.
    """
    home = Path(home).expanduser().resolve()
    binding = hashlib.sha256(json.dumps([str(home), plugin_identity.plugin_id()],
        separators=(',', ':')).encode()).hexdigest()
    # A sibling registry also fences first startup of an absent profile without
    # creating that profile during detach. Identity and canonical home are bound.
    path = home.parent / '.dyra-service-locks' / (binding + '.lock')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for index, part in enumerate(path.parent.parts[1:]):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=directory)
                except FileExistsError:
                    pass  # Another owner may have created it; validate below.
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            metadata = os.fstat(directory)
            final = index == len(path.parent.parts[1:]) - 1
            if (metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022
                    or (final and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700))):
                raise PermissionError('unsafe service directory')
        if inherited_fd is None:
            fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
        else:
            if type(inherited_fd) is not int or inherited_fd < 3:
                raise PermissionError('invalid service descriptor')
            fd = inherited_fd
            os.set_inheritable(fd, False)
        ownership._check_file(os.fstat(fd))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ServiceLockBusy('service ownership conflict') from None
        current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        held = os.fstat(fd)
        ownership._check_file(current)
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            raise PermissionError('service lock replaced')
        yield fd
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def namespace_hash(namespace):
    return hashlib.sha256(namespace.encode('utf-8')).hexdigest()


class InventoryJournal(ownership.StateJournal):
    """Same private atomic storage discipline, separate metadata-only schema."""
    def __init__(self, path, home):
        super().__init__(path)
        self.binding = hashlib.sha256(json.dumps([str(Path(home).resolve()),
            plugin_identity.plugin_id()], separators=(',', ':')).encode()).hexdigest()

    def empty(self):
        return {'version': 1, 'binding': self.binding, 'records': {}, 'pending': {}}

    def validate(self, value):
        def keys(obj, expected):
            if not isinstance(obj, dict) or set(obj) != set(expected):
                raise ownership.JournalError('invalid harness inventory fields')
        keys(value, ('version', 'binding', 'records', 'pending'))
        if type(value['version']) is not int or value['version'] != 1 or value['binding'] != self.binding:
            raise ownership.JournalError('harness inventory binding mismatch')
        for group in ('records', 'pending'):
            if not isinstance(value[group], dict):
                raise ownership.JournalError('invalid harness inventory')
            for name, record in value[group].items():
                if not re.fullmatch(re.escape(plugin_identity.harness_prefix()) + '[0-9a-f]{20}', name):
                    raise ownership.JournalError('invalid exact harness name')
                expected = ('namespace_hash',) if group == 'pending' else ('namespace_hash', 'pid', 'process_ctime', 'process_uid', 'socket')
                keys(record, expected)
                if not isinstance(record['namespace_hash'], str) or not re.fullmatch('[0-9a-f]{64}', record['namespace_hash']):
                    raise ownership.JournalError('invalid harness namespace hash')
                if group == 'pending':
                    continue
                if (type(record['pid']) is not int or not 0 < record['pid'] < 2**31
                        or type(record['process_ctime']) not in (float, int) or not 0 < record['process_ctime'] < 10**12
                        or type(record['process_uid']) is not int or record['process_uid'] != os.getuid()):
                    raise ownership.JournalError('invalid harness process generation')
                keys(record['socket'], ('dev', 'ino', 'uid', 'mode'))
                sock = record['socket']
                if (any(type(sock[k]) is not int or sock[k] < 0 for k in sock)
                        or sock['uid'] != os.getuid() or sock['mode'] not in (0o600, 0o700)):
                    raise ownership.JournalError('invalid harness socket generation')
        return value

    def save(self, state):
        self.validate(state)
        payload = json.dumps(state, sort_keys=True, allow_nan=False).encode()
        if len(payload) > ownership.MAX_BYTES:
            raise ownership.JournalError('harness inventory too large')
        directory = self._directory(create=True)
        name = '.harness-' + secrets.token_hex(16)
        try:
            self._existing(directory)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload); stream.flush(); os.fsync(stream.fileno())
            self._existing(directory)
            os.replace(name, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try: os.unlink(name, dir_fd=directory)
            except FileNotFoundError: pass
            os.close(directory)

    def load(self):
        try:
            directory = self._directory()
        except ownership.JournalError as error:
            if isinstance(error.__cause__, FileNotFoundError):
                return self.empty()
            raise
        try:
            if self._existing(directory) is None:
                return self.empty()
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                ownership._check_file(os.fstat(stream.fileno()))
                payload = stream.read(ownership.MAX_BYTES + 1)
                if len(payload) > ownership.MAX_BYTES:
                    raise ownership.JournalError('harness inventory too large')
                return self.validate(json.loads(payload, object_pairs_hook=ownership._unique_object))
        finally:
            os.close(directory)


def durable_record(record, namespace):
    return {'namespace_hash': namespace_hash(namespace),
            **{key: record[key] for key in ('pid', 'process_ctime', 'process_uid')},
            'socket': {key: record['socket'][key] for key in ('dev', 'ino', 'uid', 'mode')}}


def revive(name, record, namespace, *, ipc=None):
    if name != plugin_identity.daemon_name(namespace) or record['namespace_hash'] != namespace_hash(namespace):
        raise PermissionError('harness namespace unproven')
    if ipc is None:
        from browser_harness import _ipc as ipc
    result = {'name': name, **{key: record[key] for key in ('pid', 'process_ctime', 'process_uid')},
              'socket': {'path': str(ipc.sock_addr(name)), **record['socket']}}
    if exited(result):
        return result  # Absence authorizes pruning, never touching a replacement.
    if process_identity(result['pid']) != {key: result[key] for key in ('pid', 'process_ctime', 'process_uid')} or socket_identity(ipc.sock_addr(name)) != result['socket']:
        raise PermissionError('harness generation unproven')
    ping = request(ipc, name, {'meta': 'ping'})
    if not isinstance(ping, dict) or ping.get('pong') is not True or ping.get('browser_kind') != 'cdp' or ping.get('pid') != result['pid']:
        raise PermissionError('harness generation unproven')
    if socket_identity(ipc.sock_addr(name)) != result['socket'] or process_identity(result['pid'])['process_ctime'] != result['process_ctime']:
        raise PermissionError('harness generation changed')
    return result

import os
from pathlib import Path
import stat
import time

import psutil


def socket_identity(path):
    metadata = Path(path).lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid()
            or mode not in {0o600, 0o700}):
        raise PermissionError('private named socket required')
    return {'path': str(path), 'dev': metadata.st_dev, 'ino': metadata.st_ino,
            'uid': metadata.st_uid, 'mode': mode}


def request(ipc, name, payload, *, timeout=1):
    connection, token = ipc.connect(name, timeout=timeout)
    try:
        return ipc.request(connection, token, payload)
    finally:
        connection.close()


def process_identity(pid):
    if type(pid) is not int or not 0 < pid < 2 ** 31:
        raise PermissionError('invalid named pid')
    process = psutil.Process(pid)
    uid = process.uids().real
    if uid != os.getuid():
        raise PermissionError('named process owner mismatch')
    return {'pid': pid, 'process_ctime': process.create_time(), 'process_uid': uid}


def capture(name, endpoint, target_id, session_id, *, ipc=None):
    if ipc is None:
        from browser_harness import _ipc as ipc
    before = socket_identity(ipc.sock_addr(name))
    ping = request(ipc, name, {'meta': 'ping'})
    if not isinstance(ping, dict) or ping.get('pong') is not True or ping.get('browser_kind') != 'cdp':
        raise PermissionError('named CDP identity unproven')
    process = process_identity(ping.get('pid'))
    status = request(ipc, name, {'meta': 'connection_status'})
    if (not isinstance(status, dict) or status.get('error')
            or status.get('target_id') != target_id or status.get('session_id') != session_id):
        raise PermissionError('named selection changed')
    if socket_identity(ipc.sock_addr(name)) != before or process_identity(process['pid']) != process:
        raise PermissionError('named generation changed')
    return {'name': name, 'endpoint': endpoint, 'target_id': target_id,
            'session_id': session_id, 'socket': before, **process}


def exited(record):
    try:
        process = psutil.Process(record['pid'])
        # Reuse is not authority to touch the new process. The recorded one exited.
        return (process.create_time() != record['process_ctime'] or not process.is_running()
                or process.status() in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD})
    except psutil.NoSuchProcess:
        return True


def retire(record, *, ipc=None, timeout=5):
    """Shutdown unchanged registered generation; ACK alone never proves exit."""
    if ipc is None:
        from browser_harness import _ipc as ipc
    deadline = time.monotonic() + max(0, timeout)
    if exited(record):
        return
    process = process_identity(record['pid'])
    if any(process[k] != record[k] for k in process):
        raise PermissionError('named process generation changed')
    if socket_identity(ipc.sock_addr(record['name'])) != record['socket']:
        raise PermissionError('named socket generation changed')
    # Supported harness IPC serves one request per connection.
    connection, token = ipc.connect(record['name'], timeout=max(.01, timeout))
    try:
        ping = ipc.request(connection, token, {'meta': 'ping'})
    finally:
        connection.close()
    if (not isinstance(ping, dict) or ping.get('pong') is not True
            or ping.get('browser_kind') != 'cdp' or ping.get('pid') != record['pid']):
        raise PermissionError('named ping generation changed')
    # IPC is one-shot; revalidate immediately before the shutdown connection.
    if socket_identity(ipc.sock_addr(record['name'])) != record['socket'] or process_identity(record['pid']) != process:
        raise PermissionError('named generation changed')
    connection, token = ipc.connect(record['name'], timeout=max(.01, deadline - time.monotonic()))
    try:
        if socket_identity(ipc.sock_addr(record['name'])) != record['socket'] or process_identity(record['pid']) != process:
            raise PermissionError('named generation changed during connect')
        reply = ipc.request(connection, token, {'meta': 'shutdown'})
    finally:
        connection.close()
    if not isinstance(reply, dict) or reply.get('ok') is not True or reply.get('error'):
        raise PermissionError('named shutdown refused')
    while not exited(record):
        if time.monotonic() >= deadline:
            raise TimeoutError('named shutdown exit pending')
        time.sleep(min(.02, max(0, deadline - time.monotonic())))
