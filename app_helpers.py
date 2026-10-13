"""Trusted execution prefix installs wrappers; model body is never parsed/replayed."""
import functools
import inspect


def install(namespace, *, controller=None, lease=None, name=None, ipc_request=None):
    if namespace.get('_dyra_app_helpers_installed'):
        return
    if controller is None:
        from controller import Controller
        controller = Controller(**namespace['_dyra_app_control'])
        lease = namespace['_dyra_app_lease']
        name = namespace['_dyra_app_name']
    if ipc_request is None:
        from browser_harness import _ipc
        def ipc_request(payload):
            connection, token = _ipc.connect(name, timeout=5)
            try:
                return _ipc.request(connection, token, payload)
            finally:
                connection.close()
    original_goto = namespace['goto_url']
    def route(url, intent):
        response = controller.request('app-route', {'lease': lease, 'url': url, 'intent': intent})
        if not isinstance(response, dict) or response.get('error'):
            raise PermissionError('app route refused; no replay')
        target = response.get('target_id')
        if not target:
            return None
        attached = ipc_request({'method': 'Target.attachToTarget', 'params': {'targetId': target, 'flatten': True}})
        sid = attached.get('result', {}).get('sessionId')
        if not sid or attached.get('error'):
            raise PermissionError('app attach unproven; no replay')
        changed = ipc_request({'meta': 'set_session', 'target_id': target, 'session_id': sid})
        status = ipc_request({'meta': 'connection_status'})
        if (changed.get('error') or changed.get('session_id') != sid or status.get('error')
                or status.get('target_id') != target or status.get('session_id') != sid):
            raise PermissionError('app helper selection unproven')
        verified = controller.request('verify-driver', {'lease': lease, 'target_id': target, 'session_id': sid})
        if verified.get('verified') is not True:
            raise PermissionError('app scoped binding unproven')
        return target
    def wrap(original, new_tab):
        signature = inspect.signature(original)
        @functools.wraps(original)
        def wrapped(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            url = bound.arguments.get('url', 'about:blank')
            target = route(url, 'new_tab' if new_tab else 'goto_url') if url != 'about:blank' else None
            if target is None:
                return original(*args, **kwargs)
            result = original_goto(url)
            return target if new_tab else result
        return wrapped
    namespace['new_tab'] = wrap(namespace['new_tab'], True)
    namespace['goto_url'] = wrap(original_goto, False)
    namespace['_dyra_app_helpers_installed'] = True
