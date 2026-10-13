"""Durable ownership metadata only; importing never touches Chrome or disk.

The broker must serialize saves and supply independently verified generation and
profile/context identity. This journal is provenance, not a security sandbox
against another process running as the same user. Never pass credentials, URLs,
page contents, capabilities or flattened CDP sessions into these APIs.

Integration contract (SessionBroker/SessionScope; parent integrates):
* Before admission/janitor/bootstrap creation, load the journal and independently
  discover the exact live browser UUID, SHA-256 browser/profile provenance
  fingerprint, Default mapping and browserContextId. Never hash a URL, token or
  cookies to produce the fingerprint. No marker/tab discovery is creation proof.
* Call recovery_plan(saved, live_identity, targetInfos, live_parents=edges).
  Supply attached edges only from freshly proven parent-target bindings; omit
  unavailable edges and accept conservative retirement. URLs are ignored. Do
  not call scope.own() on arbitrary discovered targets to manufacture proof.
* On an exact match, save plan['state'] BEFORE publishing recovery. Construct
  fresh SessionScope objects, set targets=owned, parents, page_targets,
  preserve, and takeover=await restore_takeover(scope_plan). Put owned scopes
  in router.scopes, tombstone-only scopes in router.retired. Reset idle time to
  monotonic now. Leave leases/clients/session_targets/provenance_sessions/vault
  bindings empty; capabilities are newly generated runtime-only values. Preserve
  tombstones in retired scopes and prevent later event registration from
  re-owning unverified IDs. The plan does not create/attach/close Chrome targets.
* A generation mismatch yields no restore actions, state=None and all live IDs
  preserved. Archive/retain old metadata, independently prove the new generation
  through the existing Default launcher contract, then start a separate fresh
  journal. Never overwrite history and silently adopt old IDs or close them.
  Missing/changed-context/changed-lineage IDs become terminal released records;
  persist the revised plan before later admission so ID reappearance cannot
  revive stale ownership. Corrupt/unsafe journal errors deny adoption/cleanup;
  absence permits only newly confirmed creation, not discovery adoption.
* Maintain a metadata mirror using register_created only after a confirmed
  Target.createTarget result, register_descendant only on a proven opener or
  parent flattened-attach event, set_takeover for every affected tree ID, and
  set_guards for activity. Save under one broker-level serialized writer. Save
  mutation_pending=True BEFORE each potentially mutating CDP send; unknown
  outcome retains pending/uncertain. Persist busy before admission/tool dispatch
  and clear only after verified completion. Creation failure before its result
  leaves unknown targets unowned, never inferred from URLs or a new-tab diff.
* Persist upload_status='in_progress' BEFORE DOM.setFileInputFiles or any upload
  submission. A returned tool/HTTP response is not site transfer completion.
  Keep in_progress/uncertain after restart until independently confirmed site
  completion or explicit authenticated reconciliation. Download completion must
  not clear preserve/uncertain/upload guards. No request IDs, paths or URLs are
  needed in the journal. Existing upload guard integration must map its state to
  this conservative aggregate, not infer completion from download activity.
* Pause/release must durably record tree revocation before draining/ACK; failed
  persistence blocks future admission and cleanup. Persist active resume only
  after authenticated explicit resume; never clear independent guards. For
  cleanup, durably pause intended tree before send, recheck live generation,
  ownership, takeover, descendants, admission/activity and elapsed idle, send
  once, then record released only after success=True. A crash/unconfirmed close
  leaves paused/uncertain resources preserved. cleanup_candidates is advisory,
  never a bypass of SessionScope.sweep/close_if_active or an immediate close.
* Any save failure is fail-closed: revoke admission, preserve resources, do not
  replay mutation. Broker must recheck generation across discovery/plan/save
  and again at dispatch; local filesystem validation is not a same-user sandbox.
"""
import json
import os
from pathlib import Path
import secrets
import stat
import re

MAX_BYTES = 4 * 1024 * 1024
GUARD_DEFAULTS = {'preserve': False, 'uncertain': False, 'mutation_pending': False,
                  'busy': False, 'downloads_pending': False, 'upload_status': 'none'}
UPLOAD_STATES = ('none', 'in_progress', 'uncertain', 'complete', 'canceled')


def _keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise JournalError('unknown or missing journal fields')


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,1024}', value):
        raise JournalError('invalid opaque identifier')


def _namespace(value):
    # Native plugin uses JSON-encoded [conversation_identity, session_name].
    if (not isinstance(value, str) or not value or len(value) > 1024
            or any(ord(char) < 32 for char in value) or '://' in value):
        raise JournalError('invalid scope namespace')


def validate(state):
    """Strict whitelist; reject unknown versions/fields rather than drop them."""
    if isinstance(state, dict) and type(state.get('version')) is int and state['version'] == 2:
        _keys(state, ('version', 'browser', 'scopes', 'pendingBootstrap'))
        intent = state['pendingBootstrap']
        _keys(intent, ('namespace', 'profile'))
        _namespace(intent['namespace'])
        if intent['profile'] != 'Default' or state['browser'] is not None or state['scopes'] != {}:
            raise JournalError('pending bootstrap cannot carry ownership or identity')
        return state
    _keys(state, ('version', 'browser', 'scopes'))
    if type(state['version']) is not int or state['version'] not in (1, VERSION):
        raise JournalError('unsupported journal version')
    browser = state['browser']
    _keys(browser, ('fingerprint', 'uuid', 'profile', 'context_id'))
    if (not isinstance(browser['fingerprint'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', browser['fingerprint'])
            or browser['profile'] != 'Default'):
        raise JournalError('invalid browser/profile fingerprint')
    _identifier(browser['uuid'])
    _identifier(browser['context_id'])
    if not isinstance(state['scopes'], dict):
        raise JournalError('invalid scopes')
    seen = set()
    for namespace, scope in state['scopes'].items():
        _namespace(namespace)
        _keys(scope, ('targets', 'guards') if state['version'] == 1 else ('targets', 'guards', 'unknown_creates'))
        if state['version'] != 1 and (type(scope['unknown_creates']) is not int or scope['unknown_creates'] < 0):
            raise JournalError('invalid resource reservation')
        _validate_guards(scope['guards'])
        if not isinstance(scope['targets'], dict):
            raise JournalError('invalid targets')
        for target, record in scope['targets'].items():
            _identifier(target)
            if target in seen:
                raise JournalError('target shared by scopes')
            seen.add(target)
            _keys(record, ('proof', 'parent', 'page', 'takeover') if state['version'] == 1 else ('proof', 'parent', 'page', 'takeover', 'disposable', 'mutation_risk'))
            if state['version'] != 1 and (record['disposable'] not in ('blank', 'marker', 'protected') or type(record['mutation_risk']) is not bool):
                raise JournalError('invalid disposable/risk metadata')
            if record['proof'] == 'created':
                if record['parent'] is not None or record['page'] is not True:
                    raise JournalError('invalid root creation proof')
            elif record['proof'] in ('opener', 'attached'):
                _identifier(record['parent'])
                if record['parent'] not in scope['targets'] or record['parent'] == target:
                    raise JournalError('unproven parent')
            else:
                raise JournalError('missing explicit creation proof')
            if type(record['page']) is not bool or record['takeover'] not in ('active', 'paused', 'released'):
                raise JournalError('invalid takeover metadata')
        for target in scope['targets']:
            visited = set()
            while target is not None:
                if target in visited:
                    raise JournalError('cyclic ownership ancestry')
                visited.add(target)
                target = scope['targets'][target]['parent']
    return state


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise JournalError('duplicate journal key')
        value[key] = item
    return value

VERSION = 3


class JournalError(ValueError):
    """Invalid or unsafe journal: preserve resources and deny owned actions."""


def upgrade(state):
    validate(state)
    result = json.loads(json.dumps(state))
    if result['version'] == 1:
        result['version'] = VERSION
        for scope in result['scopes'].values():
            scope['unknown_creates'] = int(scope['guards']['mutation_pending'])
            for record in scope['targets'].values():
                record.update(disposable='protected', mutation_risk=True)
    return validate(result)


def new_state(*, fingerprint, browser_uuid, context_id):
    return {'version': VERSION, 'browser': {'fingerprint': fingerprint,
            'uuid': browser_uuid, 'profile': 'Default', 'context_id': context_id},
            'scopes': {}}


def ensure_scope(state, namespace):
    """Create metadata-only scope before write-ahead dispatch; owns nothing."""
    validate(state)
    if state['browser'] is None:
        raise JournalError('bootstrap intent is not ownership proof')
    _namespace(namespace)
    return state['scopes'].setdefault(namespace, {'targets': {}, 'guards': dict(GUARD_DEFAULTS), **({'unknown_creates': 0} if state['version'] == VERSION else {})})


def register_created(state, namespace, target_id, *, disposable='protected'):
    """Call only after this broker receives a confirmed createTarget result."""
    validate(state)
    if state['browser'] is None:
        raise JournalError('bootstrap intent is not ownership proof')
    _namespace(namespace)
    _identifier(target_id)
    if disposable not in ('blank', 'marker', 'protected'):
        raise JournalError('invalid disposable category')
    if any(target_id in s['targets'] for n, s in state['scopes'].items() if n != namespace):
        raise JournalError('target already belongs to another namespace')
    scope = state['scopes'].setdefault(namespace, {'targets': {}, 'guards': dict(GUARD_DEFAULTS), **({'unknown_creates': 0} if state['version'] == VERSION else {})})
    scope['targets'].setdefault(target_id, {'proof': 'created', 'parent': None,
                                           'page': True, 'takeover': 'active',
                                           **({'disposable': disposable, 'mutation_risk': False} if state['version'] == VERSION else {})})


def register_descendant(state, namespace, target_id, parent_id, *, proof, page):
    """Record an observed owned-opener/flattened-attach event, not discovery."""
    validate(state)
    if state['browser'] is None:
        raise JournalError('bootstrap intent is not ownership proof')
    _namespace(namespace)
    _identifier(target_id)
    _identifier(parent_id)
    if proof not in ('opener', 'attached') or type(page) is not bool:
        raise JournalError('invalid descendant proof')
    scope = state['scopes'].get(namespace)
    if scope is None or parent_id not in scope['targets'] or parent_id == target_id:
        raise JournalError('unknown parent')
    if any(target_id in s['targets'] for n, s in state['scopes'].items() if n != namespace):
        raise JournalError('target already belongs to another namespace')
    scope['targets'].setdefault(target_id, {'proof': proof, 'parent': parent_id,
                                           'page': page,
                                           'takeover': scope['targets'][parent_id]['takeover'],
                                           **({'disposable': 'protected', 'mutation_risk': True} if state['version'] == VERSION else {})})


def reserve_resource(state, namespace, delta):
    scope = ensure_scope(state, namespace)
    if state['version'] == VERSION:
        scope['unknown_creates'] += delta
        validate(state)


def mark_mutation_risk(state, namespace, target_id):
    validate(state)
    if state['version'] == VERSION:
        state['scopes'][namespace]['targets'][target_id]['mutation_risk'] = True


def set_takeover(state, namespace, target_id, status):
    validate(state)
    if status not in ('active', 'paused', 'released'):
        raise JournalError('invalid takeover state')
    try:
        record = state['scopes'][namespace]['targets'][target_id]
    except KeyError as error:
        raise JournalError('unknown target; cannot adopt') from error
    if record['takeover'] == 'released' and status != 'released':
        raise JournalError('released target cannot be reclaimed')
    record['takeover'] = status


def _validate_guards(guards):
    _keys(guards, GUARD_DEFAULTS)
    if guards['upload_status'] not in UPLOAD_STATES:
        raise JournalError('invalid upload status')
    if any(type(guards[k]) is not bool for k in GUARD_DEFAULTS if k != 'upload_status'):
        raise JournalError('guard must be boolean')


def set_guards(state, namespace, **changes):
    """Write ahead of dispatch; clear only on independently confirmed completion.

    Completion of upload/download must NOT clear unrelated uncertainty/preserve.
    After a crash, busy/pending remain blockers until explicit reconciliation;
    they are metadata, not revived runtime leases or mutation replay requests.
    """
    validate(state)
    if namespace not in state['scopes']:
        raise JournalError('unknown namespace')
    guards = dict(state['scopes'][namespace]['guards'], **changes)
    _validate_guards(guards)
    state['scopes'][namespace]['guards'] = guards


def recovery_plan(state, live_browser, live_targets, *, live_parents=None):
    """Pure plan, never attach/close. Live identity must be independently proven.

    Cleanup candidates are not authorization: integration must recheck identity,
    admission, takeover and activity immediately before each close, after idle.
    Nothing here restores leases, capabilities or flattened session bindings.
    """
    by_id = {}
    for info in live_targets:
        tid = info.get('targetId')
        _identifier(tid)
        if tid in by_id:
            raise JournalError('ambiguous live target IDs')
        by_id[tid] = info
    result = {'generation_matches': False, 'scopes': {},
              'preserve_targets': set(by_id), 'missing_targets': set(), 'state': None}
    if state is None:
        return result
    validate(state)
    if state['browser'] is None or live_browser != state['browser']:
        return result
    recovered = json.loads(json.dumps(state))
    result['generation_matches'] = True
    result['state'] = recovered
    live_parents = live_parents or {}
    for namespace, scope in recovered['scopes'].items():
        records = scope['targets']
        verified = set()
        # Fixed point: each child needs an exact live edge and a proven root.
        while True:
            added = set()
            for tid, record in records.items():
                info = by_id.get(tid, {})
                if (info.get('browserContextId') != live_browser['context_id']
                        or (info.get('type') == 'page') != record['page']
                        or info.get('type') not in ('page', 'iframe', 'worker', 'service_worker', 'shared_worker')):
                    continue
                parent = record['parent']
                if record['proof'] == 'created':
                    added.add(tid)
                elif parent in verified:
                    edge = info.get('openerId') if record['proof'] == 'opener' else live_parents.get(tid)
                    if edge == parent:
                        added.add(tid)
            if added <= verified:
                break
            verified |= added
        for tid, record in records.items():
            if tid not in by_id:
                result['missing_targets'].add(tid)
            if tid not in verified:
                record['takeover'] = 'released'
        # Revocation is inherited even if a crash interrupted tree persistence.
        while True:
            changed = False
            for record in records.values():
                parent = record['parent']
                if parent is None:
                    continue
                inherited = records[parent]['takeover']
                if (inherited == 'released' and record['takeover'] != 'released'
                        or inherited == 'paused' and record['takeover'] == 'active'):
                    record['takeover'] = inherited
                    changed = True
            if not changed:
                break
        takeover = {tid: r['takeover'] for tid, r in records.items()}
        owned = {tid for tid in verified if takeover[tid] != 'released'}
        parents = {tid: r['parent'] for tid, r in records.items() if r['parent'] is not None}
        def tree(root):
            descendants = {root}
            while True:
                children = {t for t, p in parents.items() if p in descendants}
                if children <= descendants:
                    return descendants
                descendants |= children
        cleanup = {t for t in owned if records[t]['page'] and takeover[t] == 'active'
                   and all(c in verified and takeover[c] == 'active' for c in tree(t))}
        # Unknown live descendants stay unowned; avoid collateral page closure.
        live_edges = {tid: info.get('openerId') for tid, info in by_id.items()
                      if info.get('openerId')}
        live_edges.update(live_parents)
        blocked = set()
        for tid in set(by_id) - verified:
            seen = set()
            parent = live_edges.get(tid)
            while parent is not None and parent not in seen:
                seen.add(parent)
                blocked.add(parent)
                parent = live_edges.get(parent)
        cleanup.difference_update(blocked)
        guards = scope['guards']
        preserve = (any(guards[k] for k in GUARD_DEFAULTS if k != 'upload_status')
                    or guards['upload_status'] in ('in_progress', 'uncertain')
                    or bool(blocked & owned))
        if preserve:
            cleanup.clear()
        result['scopes'][namespace] = {'owned': owned, 'cleanup_candidates': cleanup,
                                    'takeover': takeover, 'parents': parents,
                                    'page_targets': {t for t, r in records.items() if r['page']},
                                    'preserve': preserve, 'guards': dict(guards),
                                    'disposable': {t: r.get('disposable', 'protected') for t, r in records.items()},
                                    'mutation_risk': {t for t, r in records.items() if r.get('mutation_risk', True)}}
        result['preserve_targets'].difference_update(cleanup)
        for page in cleanup:
            result['preserve_targets'].difference_update(tree(page))
    return result


async def restore_takeover(scope_plan):
    """Build a fresh registry using public APIs; no old locks/sessions revived.

    Publish the registry only after this coroutine finishes, before admission or
    sweeps. Parent inheritance is already resolved by recovery_plan. Registering
    without a parent avoids released-parent inheritance overriding an explicit
    paused child; ancestry stays in SessionScope.parents.
    """
    from takeover import TakeoverRegistry
    registry = TakeoverRegistry()
    for target in scope_plan['takeover']:
        registry.register(target)
    for target, status in scope_plan['takeover'].items():
        if status == 'released':
            await registry.release(target)
        elif status == 'paused':
            await registry.pause(target)
    return registry


def _check_file(metadata):
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
        raise JournalError('journal must be an owned regular mode-0600 single-link file')


class StateJournal:
    """One serialized writer; relative paths allowed, symlink traversal forbidden.

    Parent must be a dedicated private directory. Only that last directory may
    be created; ancestors must exist and be non-writable by other users. No
    automatic chmod/repair of existing unsafe files. Orphan temporary files are
    ignored, never a recovery source. Errors are fail-closed, not an empty state.
    """
    def __init__(self, path):
        raw = Path(path).expanduser()
        if '..' in raw.parts or raw.name in ('', '.', '..'):
            raise JournalError('invalid journal path')
        self.path = Path(os.path.abspath(raw))

    def _directory(self, create=False):
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        parts = self.path.parent.parts[1:]
        try:
            for index, part in enumerate(parts):
                final = index == len(parts) - 1
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    if not (create and final):
                        raise
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                    # Normalize only the directory just created, never repair an
                    # existing entry. O_NOFOLLOW still guards the subsequent open.
                    os.chmod(part, 0o700, dir_fd=fd, follow_symlinks=False)
                    os.fsync(fd)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                metadata = os.fstat(fd)
                if final:
                    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                        raise JournalError('journal directory must be owned mode-0700')
                elif metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022:
                    raise JournalError('unsafe journal ancestor')
            if not parts:
                raise JournalError('private directory required')
            return fd
        except OSError as error:
            os.close(fd)
            raise JournalError('unsafe or inaccessible journal directory') from error
        except BaseException:
            os.close(fd)
            raise

    def _existing(self, directory):
        try:
            metadata = os.stat(self.path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
        _check_file(metadata)
        return metadata

    def save(self, state):
        validate(state)
        payload = json.dumps(state, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(payload) > MAX_BYTES:
            raise JournalError('journal exceeds size limit')
        directory = self._directory(create=True)
        name = '.ownership-' + secrets.token_hex(16)
        try:
            self._existing(directory)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self._existing(directory)
            os.replace(name, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        except OSError as error:
            raise JournalError('journal commit failed; preserve resources') from error
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)

    def archive_bootstrap(self, namespace):
        """Durably move only neutral intent; never delete proven ownership."""
        state = self.load()
        if (state is None or state.get('version') != 2 or state.get('browser') is not None
                or state.get('scopes') != {}
                or state.get('pendingBootstrap') != {'namespace': namespace, 'profile': 'Default'}):
            raise JournalError('neutral bootstrap intent required')
        directory = self._directory()
        try:
            self._existing(directory)
            name = 'ownership-aborted-' + secrets.token_hex(16) + '.json'
            os.rename(self.path.name, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        except OSError as error:
            raise JournalError('bootstrap archive failed; admission denied') from error
        finally:
            os.close(directory)

    def load(self):
        if not self.path.parent.exists():
            # Still validate ancestors before declaring the journal absent.
            try:
                directory = self._directory()
            except JournalError as error:
                if isinstance(error.__cause__, FileNotFoundError):
                    return None
                raise
        else:
            directory = self._directory()
        try:
            if self._existing(directory) is None:
                return None
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                _check_file(os.fstat(stream.fileno()))
                payload = stream.read(MAX_BYTES + 1)
                if len(payload) > MAX_BYTES:
                    raise JournalError('journal exceeds size limit')
                try:
                    state = json.loads(payload, object_pairs_hook=_unique_object)
                    return validate(state)
                except (ValueError, UnicodeError, RecursionError) as error:
                    raise JournalError('corrupt or invalid journal') from error
        except OSError as error:
            raise JournalError('journal read failed') from error
        finally:
            os.close(directory)
