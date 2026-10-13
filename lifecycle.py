"""Standalone profile lifecycle; importing this module never imports Hermes."""
import json
import os
import tempfile
import sys
import argparse
import subprocess
from pathlib import Path
from functools import wraps
import fcntl

# Direct-file CLI and private bundle loading both resolve only our manifest.
# Never trust a process-global module alias or modify the host import path.
import importlib.util
_identity_spec = importlib.util.spec_from_file_location(
    '_dyra_lifecycle_identity', Path(__file__).with_name('plugin_identity.py'))
_identity = importlib.util.module_from_spec(_identity_spec)
_identity_spec.loader.exec_module(_identity)
PLUGIN = _identity.plugin_id()


class LifecycleError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _preconditions(exclusive_config):
    if sys.platform != 'darwin':
        raise LifecycleError('unsupported_platform')
    if not exclusive_config:
        raise LifecycleError('exclusive_config_required')


def _save(home, state):
    path = state_path(home)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.lifecycle-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(state, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_state(home):
    try:
        state = json.loads(state_path(home).read_text())
        if (not isinstance(state, dict) or state.get('version') != 1
                or type(state.get('desired_enabled')) is not bool
                or state.get('phase') not in {'pending', 'attached', 'detaching', 'detached'}
                or type(state.get('port')) is not int or not 1 <= state['port'] <= 65535
                or not isinstance(state.get('keys'), dict)):
            raise ValueError()
        if state['desired_enabled'] != (state['phase'] == 'attached'):
            raise ValueError()
        expected = {'browser.backend': 'browser-use', 'browser.headed': True,
                    'browser.cdp_url': f"http://127.0.0.1:{state['port']}"}
        if state['keys'] and set(state['keys']) != set(expected):
            raise ValueError()
        if state['phase'] in {'attached', 'pending'} and not state['keys']:
            raise ValueError()
        for key, entry in state['keys'].items():
            if not isinstance(entry, dict):
                raise ValueError()
            for field in ('before', 'installed'):
                raw = entry[field]
                if (not isinstance(raw, dict) or type(raw.get('present')) is not bool
                        or set(raw) != ({'present', 'value'} if raw['present'] else {'present'})):
                    raise ValueError()
            if not _same(entry['installed'], {'present': True, 'value': expected[key]}):
                raise ValueError()
        return state
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise LifecycleError('journal_invalid') from error


def _config(home):
    import yaml
    try:
        config = yaml.safe_load((resolve_home(home) / 'config.yaml').read_text())
        config = {} if config is None else config
        if not isinstance(config, dict) or ('browser' in config and not isinstance(config['browser'], dict)):
            raise ValueError()
        _selection(config)
        return config
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise LifecycleError('config_invalid') from error


def _selection(config):
    plugins = config.get('plugins', {})
    if not isinstance(plugins, dict):
        raise LifecycleError('config_invalid')
    enabled, disabled = plugins.get('enabled', []), plugins.get('disabled', [])
    if (not isinstance(enabled, list) or not isinstance(disabled, list)
            or any(not isinstance(value, str) for value in enabled + disabled)):
        raise LifecycleError('config_invalid')
    return enabled, disabled


def _require_selection(home, *, enabled):
    selected, excluded = _selection(_config(home))
    verified = (PLUGIN in selected and PLUGIN not in excluded) if enabled else (PLUGIN not in selected and PLUGIN in excluded)
    if not verified:
        raise LifecycleError('plugin_enable_unverified' if enabled else 'plugin_disable_unverified')


def _raw(config, key):
    node = config
    for part in key.split('.'):
        if not isinstance(node, dict) or part not in node:
            return {'present': False}
        node = node[part]
    return {'present': True, 'value': node}


def official_runner(argv, *, env):
    return subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, text=True)


def _command(home, runner, *args):
    try:
        result = (runner or official_runner)(['hermes', *args],
            env={**os.environ, 'HERMES_HOME': str(resolve_home(home))})
        if getattr(result, 'returncode', 0) != 0:
            raise LifecycleError('official_cli_failed')
    except (OSError, subprocess.SubprocessError) as error:
        raise LifecycleError('official_cli_failed') from error


def _same(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def _set(home, runner, key, raw):
    if raw['present']:
        value = raw['value']
        _command(home, runner, 'config', 'set', key,
                 value if isinstance(value, str) else json.dumps(value))
    else:
        _command(home, runner, 'config', 'unset', key)
    if not _same(_raw(_config(home), key), raw):
        raise LifecycleError('config_write_unverified')


def _serialized(operation):
    @wraps(operation)
    def wrapped(home=None, **kwargs):
        _preconditions(kwargs.get('exclusive_config', False))
        home = resolve_home(home)
        directory = state_path(home).parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(directory / 'lifecycle.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise LifecycleError('operation_busy') from error
            return operation(home, **kwargs)
        finally:
            os.close(fd)
    return wrapped


@_serialized
def attach(home=None, *, runner=None, exclusive_config=False, port=19347):
    _preconditions(exclusive_config)
    if type(port) is not int or not 1 <= port <= 65535:
        raise LifecycleError('invalid_port')
    home = resolve_home(home)
    state = _read_state(home)
    if state and state['phase'] != 'detached' and state['port'] != port:
        raise LifecycleError('port_conflict')
    if state and state['phase'] == 'attached':
        config = _config(home)
        for key, entry in state['keys'].items():
            if not _same(_raw(config, key), entry['installed']):
                raise LifecycleError('config_conflict')
        selected, excluded = _selection(config)
        if PLUGIN in selected and PLUGIN not in excluded:
            return {'status': 'attached'}
        state.update(desired_enabled=False, phase='pending')
        _save(home, state)
    values = {'browser.backend': 'browser-use', 'browser.cdp_url': f'http://127.0.0.1:{port}',
              'browser.headed': True}
    if state and state['phase'] == 'detaching':
        raise LifecycleError('detach_pending')
    if not state or state['phase'] == 'detached':
        config = _config(home)
        if _raw(config, 'browser.cdp_url') == {'present': True, 'value': values['browser.cdp_url']}:
            raise LifecycleError('ambiguous_baseline')
        state = {'version': 1, 'desired_enabled': False, 'phase': 'pending', 'port': port,
                 'keys': {key: {'before': _raw(config, key),
                                'installed': {'present': True, 'value': value}}
                          for key, value in values.items()}}
        _save(home, state)
    for key, entry in state['keys'].items():
        current = _raw(_config(home), key)
        if not any(_same(current, entry[field]) for field in ('before', 'installed')):
            raise LifecycleError('config_conflict')
    _command(home, runner, 'plugins', 'enable', PLUGIN)
    _require_selection(home, enabled=True)
    for key, entry in state['keys'].items():
        current = _raw(_config(home), key)
        if _same(current, entry['installed']):
            continue
        if not _same(current, entry['before']):
            raise LifecycleError('config_conflict')
        _set(home, runner, key, entry['installed'])
    _require_selection(home, enabled=True)
    config = _config(home)
    if any(not _same(_raw(config, key), entry['installed']) for key, entry in state['keys'].items()):
        raise LifecycleError('config_write_unverified')
    state.update(desired_enabled=True, phase='attached')
    _save(home, state)
    return {'status': 'attached'}


def _controller_class():
    import importlib.util
    spec = importlib.util.spec_from_file_location('_dyra_lifecycle_controller', Path(__file__).with_name('controller.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Controller


def _no_start():
    raise LifecycleError('broker_start_forbidden')


def default_drain(*, home, port):
    try:
        controller = _controller_class()(home=home, port=port,
            token_file=state_path(home).parent / 'control-token', starter=_no_start)
        drained = controller.detach()
        if (drained.get('status') == 'detached' and not drained.get('blockers')
                and drained.get('stop_required') is True):
            return controller.stop(drained)
        return drained
    except LifecycleError:
        raise
    except Exception as error:
        raise LifecycleError('drain_failed') from error


@_serialized
def detach(home=None, *, runner=None, drain=None, exclusive_config=False):
    _preconditions(exclusive_config)
    home = resolve_home(home)
    state = _read_state(home)
    if state and state['phase'] == 'detached':
        selected, excluded = _selection(_config(home))
        if PLUGIN not in selected and PLUGIN in excluded:
            return {'status': 'detached'}
    if state is None:
        state = {'version': 1, 'desired_enabled': False, 'phase': 'detaching',
                 'port': 19347, 'keys': {}}
    state.update(desired_enabled=False, phase='detaching')
    _save(home, state)
    drained = (drain or default_drain)(home=home, port=state['port'])
    if (not isinstance(drained, dict) or drained.get('status') not in {'absent', 'detached'}
            or drained.get('blockers')):
        return {'status': 'draining'}
    for key, entry in state['keys'].items():
        if entry.get('restored'):
            continue
        current = _raw(_config(home), key)
        if _same(current, entry['installed']):
            _set(home, runner, key, entry['before'])
        entry['restored'] = True
        _save(home, state)
    _command(home, runner, 'plugins', 'disable', PLUGIN)
    _require_selection(home, enabled=False)
    state['phase'] = 'detached'
    _save(home, state)
    return {'status': 'detached'}


def resolve_home(home=None):
    return Path(home or os.environ.get('HERMES_HOME') or Path.home() / '.hermes').expanduser().resolve()


def state_path(home=None):
    return resolve_home(home) / 'plugin-data' / PLUGIN / 'lifecycle.json'


def desired_enabled(home=None) -> bool:
    """Passive registration gate; corruption raises, absence stays passive."""
    state = _read_state(home)
    return state is not None and state['desired_enabled'] is True and state['phase'] == 'attached'


def status(home=None):
    if sys.platform != 'darwin':
        raise LifecycleError('unsupported_platform')
    state = _read_state(home)
    return {'status': state['phase'] if state else 'unattached',
            'desired_enabled': bool(state and state['desired_enabled'])}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Standalone lifecycle command, not a native Hermes command.')
    parser.add_argument('--home')
    parser.add_argument('--port', type=int, default=19347)
    parser.add_argument('--exclusive-config', action='store_true',
                        help='Confirm no other config writers for this entire operation; no CAS is available.')
    parser.add_argument('operation', choices=('attach', 'detach', 'status'))
    args = parser.parse_args(argv)
    try:
        if args.operation == 'status':
            result = status(args.home)
        elif args.operation == 'attach':
            result = attach(args.home, port=args.port, exclusive_config=args.exclusive_config)
        else:
            result = detach(args.home, exclusive_config=args.exclusive_config)
        print(json.dumps(result))
        return 3 if result['status'] == 'draining' else 0
    except LifecycleError as error:
        print(json.dumps({'status': 'error', 'error': {'code': error.code}}))
        return 2
    except Exception:
        print(json.dumps({'status': 'error', 'error': {'code': 'lifecycle_failed'}}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
