"""General Hermes plugin: admission middleware, not a replacement tool."""
import hashlib
import json
import re
import threading
from pathlib import Path
import builtins
import importlib.util
import sys
import types

_ROOT = Path(__file__).resolve().parent
_PACKAGE = '_dyra_native_' + hashlib.sha256(str(_ROOT).encode()).hexdigest()[:16]
_IMPORT_LOCK = threading.RLock()


def load_sibling(name):
    """Load the flat bundle privately, including legacy absolute sibling imports.

    Never alias generic names in sys.modules or modify the host's sys.path.
    Each module's import function redirects only bundled Python siblings.
    """
    if not re.fullmatch(r'[a-z][a-z0-9_]*', name) or not (_ROOT / (name + '.py')).is_file():
        raise ImportError('unknown bundled module')
    with _IMPORT_LOCK:
        if _PACKAGE not in sys.modules:
            package = types.ModuleType(_PACKAGE)
            package.__path__ = [str(_ROOT)]
            sys.modules[_PACKAGE] = package
        qualified = _PACKAGE + '.' + name
        if qualified in sys.modules:
            return sys.modules[qualified]
        spec = importlib.util.spec_from_file_location(qualified, _ROOT / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        def owned_import(import_name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and '.' not in import_name and (_ROOT / (import_name + '.py')).is_file():
                return load_sibling(import_name)
            return builtins.__import__(import_name, globals, locals, fromlist, level)
        module.__dict__['__builtins__'] = {**vars(builtins), '__import__': owned_import}
        sys.modules[qualified] = module
        try:
            exec(compile(spec.loader.get_source(qualified), str(spec.origin), 'exec'), module.__dict__)
        except BaseException:
            sys.modules.pop(qualified, None)
            raise
        return module


_IDENTITY = load_sibling('plugin_identity')


def plugin_selected(home):
    """Read profile selection on every call; CLI disable need not hot-reload."""
    import yaml
    try:
        config = yaml.safe_load((Path(home) / 'config.yaml').read_text())
        plugins = config.get('plugins', {})
        enabled, disabled = plugins.get('enabled', []), plugins.get('disabled', [])
        identity = _IDENTITY.plugin_id()
        return (isinstance(enabled, list) and isinstance(disabled, list)
                and identity in enabled and identity not in disabled)
    except (OSError, ValueError, AttributeError, yaml.YAMLError):
        return False


def tool_error(code):
    return json.dumps({'status': 'tool_error', 'error': {'code': code, 'message': 'Native Chrome admission/execution failed; no fallback or mutation replay'}})


def make_middleware(controller, *, supervisor_lookup=None):
    last_sessions = {}
    session_lock = threading.Lock()
    task_locks = {}
    routed = hasattr(controller, 'acquire_session')
    if supervisor_lookup is None:
        def supervisor_lookup(task):
            from tools.browser_supervisor import SUPERVISOR_REGISTRY
            if routed:
                from tools.browser_tool_cdp import _resolve_cdp_override
                # Only called after exclusive exact vault binding. Browser root
                # discovery stays closed; no process-global active identity.
                return SUPERVISOR_REGISTRY.get_or_start(task, _resolve_cdp_override(controller.base))
            return SUPERVISOR_REGISTRY.get(task)
    def dispatch(*, tool_name, args, next_call, **kwargs):
        is_vault = tool_name.startswith('browser_vault_')
        identity = kwargs.get('task_id') or kwargs.get('session_id')
        if is_vault and (not identity or str(identity) not in last_sessions):
            return tool_error('vault_target_binding_unverified')
        if tool_name != 'browser_exec' and not is_vault:
            return next_call(args)
        lease = None
        result = None
        try:
            identity = kwargs.get('task_id') or kwargs.get('session_id')
            if not identity:
                return tool_error('missing_session_identity')
            session = last_sessions[str(identity)] if is_vault else str(args.get('session') or 'default')
            if not is_vault and args.get('session') and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', args['session']):
                return tool_error('invalid_session_name')
            namespace = json.dumps([_IDENTITY.plugin_id(), str(identity), session], separators=(',', ':'))
            # One bounded identity-scoped name is shared with broker registration.
            internal = _IDENTITY.daemon_name(namespace)
            payload = args
            if routed:
                for attempt in range(2):
                    try:
                        admission = controller.acquire_session(namespace, kind='vault' if is_vault else 'browser')
                        break
                    except Exception as error:
                        # Only broker-proven initial setup may repeat. No driver
                        # preparation or native code is inside this retry loop.
                        if (attempt or not getattr(error, 'retryable', False)
                                or getattr(error, 'code', None) not in {'startup', 'consent_expired'}):
                            raise
                lease = admission['lease']
                if not is_vault:
                    selection = controller.prepare_driver(admission, internal)
                    payload = {**args, 'session': internal}
                    if getattr(controller, 'app_helpers_enabled', False):
                        prefix = (load_sibling('controller').bundle_preamble() +
                            f'_dyra_app_control = {dict(port=controller.port, token_file=str(controller.token_file))!r}\n'
                            f'_dyra_app_lease = {lease!r}\n'
                            f'_dyra_app_name = {internal!r}\n'
                            f'restore_driver_selection({selection!r}, lease=_dyra_app_lease, name=_dyra_app_name, control=Controller(**_dyra_app_control))\n'
                            'app_helpers = _dyra_bundle.load_sibling("app_helpers")\napp_helpers.install(globals())\n')
                        payload['code'] = prefix + args['code']
            else:
                lease = controller.acquire(namespace)
            if is_vault:
                controller.bind_vault(lease, internal if routed else session)
                supervisor = supervisor_lookup(str(identity))
                if supervisor is None or not supervisor.focus_page('').get('ok'):
                    return tool_error('vault_supervisor_binding_failed')
            result = next_call(payload)
            if not is_vault:
                last_sessions[str(identity)] = session
        except Exception as error:
            allowed = {'profile_conflict', 'unsupported_platform', 'detached', 'startup', 'consent_expired', 'helper_ax', 'ws_denied', 'profile_marker',
                       'resource_limit', 'owned_target_lost', 'lease_conflict', 'stale_driver', 'upstream_uncertain',
                       'scope_create_rejected', 'journal_invalid', 'journal_commit_failed', 'journal_bootstrap_pending', 'journal_endpoint_unavailable'}
            code = getattr(error, 'code', 'upstream_uncertain')
            result = tool_error(code if code in allowed else 'upstream_uncertain')
        finally:
            if lease is not None:
                try:
                    controller.release(lease)
                except Exception:
                    result = tool_error('release_failed')
        return result
    def middleware(*, tool_name, args, next_call, **kwargs):
        identity = kwargs.get('task_id') or kwargs.get('session_id')
        if routed and identity and (tool_name == 'browser_exec' or tool_name.startswith('browser_vault_')):
            # Last-selection and supervisor state are task-local. A task's names
            # serialize; distinct tasks execute concurrently on distinct scopes.
            with session_lock:
                lock = task_locks.setdefault(str(identity), threading.RLock())
            with lock:
                return dispatch(tool_name=tool_name, args=args, next_call=next_call, **kwargs)
        return dispatch(tool_name=tool_name, args=args, next_call=next_call, **kwargs)
    return middleware


def register(ctx):
    import platform
    if platform.system() != 'Darwin':
        return  # Unsupported platforms are passive, including plugin discovery.
    home = getattr(ctx, 'home', None) or getattr(getattr(ctx, '_manager', None), 'home_path', None)
    if home is None:
        from hermes_constants import get_hermes_home
        home = get_hermes_home()
    home = Path(home).expanduser().resolve()
    retired = threading.Event()
    # Delayed import: plugin registration never starts a process or opens sockets.
    class LazyController:
        def __init__(self):
            self.instance = None
        def get(self):
            if self.instance is None:
                state = load_sibling('lifecycle')._read_state(home)
                self.instance = load_sibling('controller').Controller(home=home, port=state['port'])
            return self.instance
        app_helpers_enabled = True
        @property
        def port(self):
            return self.get().port
        @property
        def token_file(self):
            return self.get().token_file
        @property
        def base(self):
            return self.get().base
        def acquire_session(self, namespace, *, kind='browser'):
            return self.get().acquire_session(namespace, kind=kind)
        def prepare_driver(self, admission, name):
            return self.get().prepare_driver(admission, name)
        def acquire(self, namespace):
            return self.get().acquire(namespace)
        def release(self, lease):
            return self.get().release(lease)
        def bind_vault(self, lease, session):
            return self.get().bind_vault(lease, session)
    controller = LazyController()
    active = make_middleware(controller)
    def gate(*, tool_name, args, next_call, **kwargs):
        if retired.is_set() or (tool_name != 'browser_exec' and not tool_name.startswith('browser_vault_')):
            return next_call(args)
        try:
            enabled = load_sibling('lifecycle').desired_enabled(home) and plugin_selected(home)
        except Exception:
            return tool_error('lifecycle_invalid')
        if not enabled:
            return next_call(args)
        return active(tool_name=tool_name, args=args, next_call=next_call, **kwargs)
    def unload():
        retired.set()
        if controller.instance is not None:
            controller.instance.close()  # Local generation only; no global detach/config writes.
    ctx.register_middleware('tool_execution', gate)
    ctx.on_unload(unload)
