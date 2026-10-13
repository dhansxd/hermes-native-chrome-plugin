"""Original Default launcher/discovery. Only invoked by admitted broker calls."""
import asyncio
import re
import secrets
from pathlib import Path

CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
ACTIVE_PORT = Path.home() / 'Library/Application Support/Google/Chrome/DevToolsActivePort'


async def launch_chrome(argv):
    process = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
    # Shared Chrome process must never be terminated by this integration.
    return process.pid


class NativeConnector:
    def __init__(self, *, active_port=ACTIVE_PORT, launcher=launch_chrome, marker_origin='http://127.0.0.1:19347', readiness_timeout=10, interval=.1, evidence_queue=None):
        if not re.fullmatch(r'http://127\.0\.0\.1:[0-9]+', marker_origin):
            raise ValueError('marker origin must be loopback HTTP')
        if not 1 <= int(marker_origin.rsplit(':', 1)[1]) <= 65535:
            raise ValueError('invalid marker port')
        self.active_port = Path(active_port)
        self.launcher = launcher
        self.marker_origin = marker_origin
        self.marker_url = None
        self.readiness_timeout = readiness_timeout
        self.interval = interval
        self.evidence_queue = evidence_queue
        self.pending_launch_endpoint = None

    async def __call__(self, previous=None):
        self.marker_url = self.marker_origin + '/marker/' + secrets.token_urlsafe(24)
        await self.launcher([CHROME, '--profile-directory=Default', '--new-window', self.marker_url])
        async def ready():
            while True:
                url = await self.discover_endpoint()
                if url != previous:
                    return url
                await asyncio.sleep(self.interval)
        url = await self.discover_endpoint() if previous is None else await asyncio.wait_for(ready(), self.readiness_timeout)
        self.pending_launch_endpoint = url
        return {'url': url, 'marker_url': self.marker_url}

    async def ensure_profile_context(self, command, *, endpoint, context_id):
        """Re-prove Default profile after idle retirement, without reconnecting.

        Call only under admission serialization and before scope creation. A
        previously proven context may survive its owned pages, but a native
        profile context can disappear when its final window closes. Discovery
        proves continued existence, never ownership of arbitrary pages. If it
        vanished, open one exact marker in Default and return only that marker
        as newly owned; the caller must transfer it into the next scope and
        journal the launch intent before invoking this helper.
        """
        async def prove():
            if await self.discover_endpoint() != endpoint:
                raise NativeProfileError('profile_marker')
            infos = (await command('Target.getTargets'))['targetInfos']
            if await self.discover_endpoint() != endpoint:
                raise NativeProfileError('profile_marker')
            if context_id and any(t.get('browserContextId') == context_id for t in infos):
                return {'context_id': context_id, 'targets': set()}
            marker_url = self.marker_origin + '/marker/' + secrets.token_urlsafe(24)
            self.marker_url = marker_url
            await self.launcher([CHROME, '--profile-directory=Default', '--new-window', marker_url])
            while True:
                if await self.discover_endpoint() != endpoint:
                    raise NativeProfileError('profile_marker')
                infos = (await command('Target.getTargets'))['targetInfos']
                if await self.discover_endpoint() != endpoint:
                    raise NativeProfileError('profile_marker')
                markers = [t for t in infos if t.get('url') == marker_url and t.get('type') == 'page']
                if len(markers) > 1 or (markers and not markers[0].get('browserContextId')):
                    raise NativeProfileError('profile_marker')
                if markers:
                    return {'context_id': markers[0]['browserContextId'], 'targets': {markers[0]['targetId']}}
                await asyncio.sleep(self.interval)
        try:
            return await asyncio.wait_for(prove(), self.readiness_timeout)
        except TimeoutError:
            # Launch may already have happened: this is not retryable readiness.
            raise NativeProfileError('profile_marker') from None

    async def fresh_endpoint(self, previous):
        """Launch only after the previous exact browser endpoint is proven gone.

        A consent timeout/403 or protocol failure is ambiguous, not browser death.
        No approval helper runs for this negative liveness probe.
        """
        from aiohttp import ClientSession, ClientTimeout, WSServerHandshakeError
        if not re.fullmatch(r'ws://127\.0\.0\.1:[0-9]+/devtools/browser/[A-Za-z0-9_-]+', previous or ''):
            raise ConnectionError('unverified previous browser endpoint')
        async with ClientSession(timeout=ClientTimeout(total=2)) as http:
            try:
                ws = await http.ws_connect(previous)
            except WSServerHandshakeError as error:
                if error.status not in {404, 410}:
                    raise ConnectionError('previous browser liveness ambiguous') from None
            except OSError as error:
                import errno
                if error.errno != errno.ECONNREFUSED:
                    raise ConnectionError('previous browser liveness ambiguous') from None
            except Exception:
                raise ConnectionError('previous browser liveness ambiguous') from None
            else:
                await ws.close()
                raise ConnectionError('previous browser still alive; fresh adoption denied')
        return await self(previous=previous)

    async def prove_previous_generation_absent(self, previous):
        from browser_identity import prove_previous_generation_absent
        return await prove_previous_generation_absent(previous, active_port=self.active_port)

    async def launch_after_absence(self, previous):
        """Caller MUST archive and fsync neutral intent before this launch.

        Repeat independent absence after the disk awaits. A retained journal
        UUID is only a readiness fence, never a source of an old WS address.
        Ownership still requires exact marker/context and new listener proof.
        """
        if await self.prove_previous_generation_absent(previous) is not True:
            raise NativeFailure('journal_generation_ambiguous')
        self.marker_url = self.marker_origin + '/marker/' + secrets.token_urlsafe(24)
        await self.launcher([CHROME, '--profile-directory=Default', '--new-window', self.marker_url])
        async def ready():
            while True:
                url = await self.discover_endpoint()
                if url.rsplit('/', 1)[1] != previous['uuid']:
                    self.pending_launch_endpoint = url
                    return {'url': url, 'marker_url': self.marker_url}
                await asyncio.sleep(self.interval)
        try:
            return await asyncio.wait_for(ready(), self.readiness_timeout)
        except TimeoutError:
            raise NativeFailure('journal_endpoint_unavailable') from None

    async def wait_endpoint_change(self, previous):
        """Read-only stale-UUID readiness, never repeat the launcher."""
        async def ready():
            while True:
                url = await self.discover_endpoint()
                if url != previous:
                    return url
                await asyncio.sleep(self.interval)
        try:
            return await asyncio.wait_for(ready(), self.readiness_timeout)
        except TimeoutError:
            raise NativeFailure('journal_endpoint_unavailable') from None

    def record_initial(self, phase, *, result=None, reason=None, started):
        # Exists before PendingAttachAuthority; never logs error text or identity.
        from browser_identity import ATTACH_PROOF_REASONS
        row = {'phase': phase, 'pending_state': 'not-started',
               'elapsed_ms': round(1000 * (asyncio.get_running_loop().time() - started), 1),
               'remaining_ms': 0}
        if result in {'failed', 'valid', 'changed'}:
            row['result'] = result
        if reason in ATTACH_PROOF_REASONS:
            row['reason'] = reason
        if self.evidence_queue is not None:
            try:
                self.evidence_queue.put_nowait(row)
            except Exception:
                pass

    async def connect_approved(self, http, url):
        from browser_identity import prove_attach_identity, AttachIdentityFailure
        async def reprove():
            return await prove_attach_identity({'url': url}, active_port=self.active_port)
        started = asyncio.get_running_loop().time()
        witness = None
        async def initial_proof():
            nonlocal witness
            for attempt in range(3):
                self.record_initial('attach_initial_proof_start', started=started)
                try:
                    current = await reprove()
                except Exception as error:
                    self.record_initial('attach_initial_proof_result', result='failed',
                        reason=getattr(error, 'reason', 'proof-unavailable'), started=started)
                    partial = error.readiness_proof if isinstance(error, AttachIdentityFailure) else None
                    if partial is None or error.reason != 'listener-executable-missing':
                        raise
                    # Construct only to validate witness shape; never use its authority.
                    PendingAttachAuthority(url, partial, reprove)
                    if witness is not None and witness != partial:
                        self.record_initial('attach_initial_proof_result', result='changed',
                            reason='readiness-changed', started=started)
                        raise NativeFailure('attach_authority') from None
                    witness = partial
                    if attempt == 2:
                        raise
                    await asyncio.sleep(self.interval)
                else:
                    if witness is not None and current != witness:
                        self.record_initial('attach_initial_proof_result', result='changed',
                            reason='readiness-changed', started=started)
                        raise NativeFailure('attach_authority')
                    self.record_initial('attach_initial_proof_result', result='valid', started=started)
                    return current
        try:
            async with asyncio.timeout(self.readiness_timeout):
                proof = await initial_proof()
        except Exception as error:
            if isinstance(error, TimeoutError):
                self.record_initial('attach_initial_proof_result', result='failed',
                                    reason='readiness-deadline', started=started)
            if url == self.pending_launch_endpoint or witness is not None:
                # Never send an unpolled negative upgrade to our unproven fresh
                # launch or witnessed readiness candidate: it can publish consent.
                raise NativeFailure('attach_authority') from None
            # A stale native file may still name a listening TCP port after its
            # browser UUID/process died. Failed identity is NOT attach authority,
            # but must not hide independent negative liveness from the broker's
            # trusted-runtime recovery path. Never run AX helpers or send CDP on
            # this probe; a live/denied/ambiguous endpoint stays fail-closed.
            from aiohttp import ClientConnectorError, WSServerHandshakeError
            import errno
            if (re.fullmatch(r'ws://127\.0\.0\.1:[0-9]+/devtools/browser/[A-Za-z0-9_-]+', url or '')
                    and 1 <= int(url.split(':')[2].split('/')[0]) <= 65535):
                try:
                    async with asyncio.timeout(2):
                        import base64
                        headers = {'Upgrade': 'websocket', 'Connection': 'Upgrade',
                                   'Sec-WebSocket-Version': '13',
                                   'Sec-WebSocket-Key': base64.b64encode(secrets.token_bytes(16)).decode()}
                        # ws_connect follows redirects. A setup-only negative
                        # probe must stay on the exact URL (including its port).
                        async with http.get('http' + url[2:], headers=headers,
                                            allow_redirects=False) as response:
                            if response.status in {404, 410}:
                                raise WSServerHandshakeError(response.request_info,
                                    response.history, status=response.status,
                                    message='exact browser endpoint unavailable')
                            response.close()  # Live/denied is not an admitted WS.
                except WSServerHandshakeError as error:
                    if error.status in {404, 410} and not error.history:
                        raise  # Redirect destinations never prove exact UUID death.
                except ClientConnectorError as error:
                    if error.os_error.errno == errno.ECONNREFUSED:
                        raise
                except Exception:
                    pass
            raise NativeFailure('attach_authority') from None
        authority = PendingAttachAuthority(url, proof, reprove, evidence_queue=self.evidence_queue)
        socket = await approved_connect(http, url, attach_authority=authority)
        if self.pending_launch_endpoint == url:
            self.pending_launch_endpoint = None
        return socket

    async def rediscover_endpoint(self):
        # Warm reconnect must not spend the cold-launch readiness budget.
        return await asyncio.wait_for(self.discover_endpoint(), .25)

    async def discover_endpoint(self):
        deadline = asyncio.get_running_loop().time() + self.readiness_timeout
        while True:
            try:
                lines = self.active_port.read_text().splitlines()
                if len(lines) != 2 or not lines[0].isdigit():
                    raise ValueError('invalid DevToolsActivePort')
                port = int(lines[0])
                if not 1 <= port <= 65535 or not re.fullmatch(r'/devtools/browser/[A-Za-z0-9_-]+', lines[1]):
                    raise ValueError('invalid loopback CDP endpoint')
                # Existence is not readiness: cold starts leave stale files.
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError('live DevToolsActivePort unavailable')
                _, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), min(.5, remaining))
                writer.close()
                await writer.wait_closed()
                return f'ws://127.0.0.1:{port}{lines[1]}'
            except (OSError, TimeoutError, ValueError) as error:
                if asyncio.get_running_loop().time() >= deadline:
                    if isinstance(error, ValueError):
                        raise NativeProfileError('profile_marker') from None
                    raise TimeoutError('live DevToolsActivePort unavailable') from None
                await asyncio.sleep(self.interval)


class NativeFailure(ConnectionError):
    """Public safe diagnostic; never include upstream exception text."""
    def __init__(self, code, *, retryable=False):
        self.code = code
        self.retryable = retryable
        super().__init__(code)


class NativeTimeout(NativeFailure, TimeoutError):
    pass


class NativeProfileError(NativeFailure, ValueError):
    pass


class PendingAttachAuthority:
    """One setup-only capability. No target/context ownership or replay rights."""
    def __init__(self, url, proof, reprove, *, evidence_queue=None):
        import math
        from browser_identity import verified_main_host
        host = proof.get('host', {})
        if (not re.fullmatch(r'ws://127\.0\.0\.1:[0-9]+/devtools/browser/[A-Za-z0-9_-]+', url or '')
                or not 1 <= int(url.split(':')[2].split('/')[0]) <= 65535
                or set(proof) != {'host', 'fingerprint', 'uuid', 'profile'}
                or proof.get('profile') != 'Default' or proof.get('uuid') != url.rsplit('/', 1)[1]
                or not re.fullmatch(r'[a-f0-9]{64}', proof.get('fingerprint', ''))
                or type(host.get('pid')) is not int or host['pid'] <= 0
                or not verified_main_host(host)
                or type(host.get('started')) not in {int, float} or not math.isfinite(host['started'])
                or host['started'] <= 0):
            raise NativeFailure('attach_authority')
        self.url = url
        from copy import deepcopy
        self.proof = deepcopy(proof)
        self.reprove = reprove
        self.used = False
        self.revoked = False
        self.activated = False
        self.owner = None
        self.until = 0
        self.connecting = None
        self.evidence_queue = evidence_queue
        self.started = None

    def begin(self, deadline):
        if self.used or self.revoked:
            raise NativeFailure('attach_authority')
        self.used = True
        self.owner = asyncio.current_task()
        self.started = asyncio.get_running_loop().time()
        self.until = self.started + deadline
        self.record('attach_begin')

    def pending(self):
        return (self.used and not self.revoked and self.owner is not None
                and not self.owner.cancelling() and not self.owner.done()
                and asyncio.get_running_loop().time() < self.until
                and (self.connecting is None or not self.connecting.done()))

    def pending_reason(self):
        if self.revoked: return 'revoked'
        if not self.used or self.owner is None: return 'not-started'
        if self.owner.cancelling(): return 'owner-cancelled'
        if self.owner.done(): return 'owner-done'
        if asyncio.get_running_loop().time() >= self.until: return 'deadline'
        if self.connecting is not None and self.connecting.done(): return 'setup-done'
        return 'pending'

    def record(self, phase, *, result=None, host_kind=None, reason=None, operation=None):
        """Opt-in, nonblocking, fixed-vocabulary evidence; no host identifiers."""
        phases = {'attach_begin', 'attach_revoked', 'reproof_start', 'reproof_result',
                  'preflight_start', 'preflight_done', 'approve_result', 'raise_result',
                  'upgrade_start', 'upgrade_denied', 'upgrade_result', 'connect_delivered',
                  'connect_deadline', 'connect_cancelled', 'ax_host_check', 'ax_spawn',
                  'ax_spawned', 'ax_script_submitted', 'ax_script_delivered', 'ax_result', 'ax_deadline',
                  'ax_cancelled', 'ax_reaped'}
        if self.evidence_queue is None or phase not in phases:
            return
        now = asyncio.get_running_loop().time()
        row = {'phase': phase, 'pending_state': self.pending_reason(),
               'elapsed_ms': round(1000 * (now - self.started), 1) if self.started is not None else 0,
               'remaining_ms': round(max(0, self.until - now) * 1000, 1)}
        if result in {'clicked', 'raised', 'not-found', 'stale-host', 'valid', 'changed',
                      'failed', 'success', 'denied', 'unexpected'}:
            row['result'] = result
        if host_kind in {'main', 'pwa'}:
            row['host_kind'] = host_kind
        if operation in {'approve', 'raise', 'probe'}:
            row['operation'] = operation
        from browser_identity import ATTACH_PROOF_REASONS
        if reason in ATTACH_PROOF_REASONS | {'host-invalid', 'pending-ended', 'helper-deadline', 'nonzero-exit',
                      'invalid-output', 'spawn-cancelled', 'cancelled'}:
            row['reason'] = reason
        try:
            self.evidence_queue.put_nowait(row)
        except Exception:
            pass  # Diagnostics must never affect consent or wait for a consumer.

    def revoke(self):
        self.revoked = True
        self.record('attach_revoked')

    async def validate(self):
        if not self.pending():
            if asyncio.get_running_loop().time() >= self.until:
                raise NativeTimeout('consent_expired')
            raise NativeFailure('attach_authority')
        self.record('reproof_start')
        try:
            current = await self.reprove()
        except Exception as error:
            self.record('reproof_result', result='failed',
                        reason=getattr(error, 'reason', 'proof-unavailable'))
            self.revoke()
            raise NativeFailure('attach_authority') from None
        self.record('reproof_result', result='valid' if current == self.proof else 'changed')
        if current != self.proof:
            self.revoke()
            raise NativeFailure('attach_authority')
        if not self.pending():
            if asyncio.get_running_loop().time() >= self.until:
                raise NativeTimeout('consent_expired')
            raise NativeFailure('attach_authority')
        host = self.proof['host']
        from browser_identity import verified_main_host
        if not verified_main_host(host):
            raise NativeFailure('attach_authority')
        from copy import deepcopy
        return deepcopy(host)


async def connect_scoped(handshake, approve, *, deadline=15, interval=.4,
                         attach_authority=None, approve_bound=None, raise_main=None,
                         recovery_after=1.2, recover_before_upgrade=False):
    # Chrome may reject the upgrade before its AX sheet is published. Approval
    # remains part of this original bounded setup, not admission/mutation replay.
    approved = asyncio.Event()
    preflight_done = asyncio.Event()
    if not recover_before_upgrade:
        preflight_done.set()
    denied = False
    started = asyncio.get_running_loop().time()
    if attach_authority:
        attach_authority.begin(deadline)
        if approve_bound is None or raise_main is None:
            from approval import approve_pending, raise_pending_main
            approve_bound = approve_bound or approve_pending
            raise_main = raise_main or raise_pending_main
    def record(phase, **fields):
        if attach_authority:
            attach_authority.record(phase, **fields)
    async def poll():
        await preflight_done.wait()
        while not approved.is_set():
            await asyncio.sleep(interval)
            try:
                if attach_authority:
                    host = await attach_authority.validate()
                    result = await approve_bound(host, attach_authority.pending)
                    record('approve_result', result=result)
                    if attach_authority.connecting.done():
                        await asyncio.Future()  # Setup completed; no further AX work.
                    if result == 'stale-host' or not attach_authority.pending():
                        attach_authority.revoke()
                        raise NativeFailure('attach_authority')
                    if (result == 'not-found' and not attach_authority.activated
                            and asyncio.get_running_loop().time() - started >= recovery_after):
                        host = await attach_authority.validate()
                        attach_authority.activated = True  # Reservation before any AX await.
                        raised = await raise_main(host, attach_authority.pending)
                        record('raise_result', result=raised,
                               reason='no-main-ax-window' if raised == 'not-found' else None)
                        if raised == 'stale-host':
                            attach_authority.revoke()
                            raise NativeFailure('attach_authority')
                else:
                    result = await asyncio.to_thread(approve)
            except NativeFailure:
                raise
            except Exception:
                raise NativeFailure('helper_ax') from None
            if result == 'clicked':
                approved.set()
        await asyncio.Future()  # No further dialog presses during setup retry.
    async def setup():
        nonlocal denied
        from aiohttp import WSServerHandshakeError
        if recover_before_upgrade and attach_authority:
            record('preflight_start')
            host = await attach_authority.validate()
            result = await approve_bound(host, attach_authority.pending)
            record('approve_result', result=result)
            if result == 'stale-host':
                raise NativeFailure('attach_authority')
            if result == 'not-found':
                host = await attach_authority.validate()
                attach_authority.activated = True
                raised = await raise_main(host, attach_authority.pending)
                record('raise_result', result=raised,
                       reason='no-main-ax-window' if raised == 'not-found' else None)
                if raised == 'stale-host':
                    raise NativeFailure('attach_authority')
            elif result == 'clicked':
                approved.set()
        record('preflight_done')
        preflight_done.set()
        for attempt in range(2):
            try:
                record('upgrade_start')
                socket = await handshake()
                record('upgrade_result', result='success')
                return socket
            except WSServerHandshakeError as error:
                if error.status not in {401, 403}:
                    raise  # Dead UUID statuses remain available to recovery.
                denied = True
                record('upgrade_denied', result='denied')
                if error.status == 401 or attempt == 1:
                    raise NativeFailure('ws_denied') from None
                await approved.wait()
                if attach_authority:
                    await attach_authority.validate()
                # Only an exact validated dialog press allows one WS setup retry.
    polling = asyncio.create_task(poll())
    connecting = asyncio.create_task(setup())
    if attach_authority:
        attach_authority.connecting = connecting
    delivered = False
    try:
        done, _ = await asyncio.wait({connecting, polling}, timeout=deadline,
                                     return_when=asyncio.FIRST_COMPLETED)
        if connecting in done:
            result = await connecting
            if attach_authority and attach_authority.revoked:
                raise NativeFailure('attach_authority')
            delivered = True
            record('connect_delivered')
            return result
        if polling in done:
            return await polling
        record('connect_deadline')
        if denied:
            raise NativeFailure('ws_denied')
        raise NativeTimeout('consent_expired')
    except asyncio.CancelledError:
        record('connect_cancelled')
        raise
    finally:
        if attach_authority:
            attach_authority.revoke()
        for task in (polling, connecting):
            if not task.done():
                task.cancel()
        await asyncio.gather(polling, connecting, return_exceptions=True)
        if not delivered and not connecting.cancelled() and connecting.exception() is None:
            socket = connecting.result()
            if hasattr(socket, 'close'):
                await socket.close()


async def approved_connect(http, url, *, attach_authority=None):
    from aiohttp import ClientWSTimeout
    if attach_authority is None or attach_authority.url != url:
        raise NativeFailure('attach_authority')
    async def handshake():
        await attach_authority.validate()
        return await http.ws_connect(url, timeout=ClientWSTimeout(ws_close=5))
    return await connect_scoped(handshake, None, attach_authority=attach_authority, recover_before_upgrade=True)
