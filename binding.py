"""Read actual daemon selection; no browser launch, script, or secret material."""
import os
import stat
from pathlib import Path


def driver_status(name='default'):
    from browser_harness import _ipc
    if _ipc.IS_WINDOWS:
        # This original-profile integration is currently macOS-only.
        raise PermissionError('private POSIX harness IPC required')
    endpoint = Path(_ipc.sock_addr(name))
    metadata = endpoint.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o700}:
        raise PermissionError('harness IPC must be an owned private socket')
    def request(meta):
        connection, token = _ipc.connect(name, timeout=5)
        try:
            return _ipc.request(connection, token, {'meta': meta})
        finally:
            connection.close()
    ping = request('ping')
    if not isinstance(ping, dict) or ping.get('pong') is not True or type(ping.get('pid')) is not int or ping['pid'] <= 0 or ping.get('browser_kind') != 'cdp':
        raise PermissionError('live native CDP harness required')
    status = request('connection_status')
    if not isinstance(status, dict) or not status.get('target_id') or not status.get('session_id') or status.get('error'):
        raise PermissionError('driver has no live page selection')
    page = status.get('page') or {}
    if page.get('targetId') != status['target_id']:
        raise PermissionError('driver has no real active page')
    return {'pid': ping['pid'], 'target_id': status['target_id'], 'session_id': status['session_id']}
