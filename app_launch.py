"""Trusted app-first selection over the existing broker transport; no replay.

Exact context/catalog/display proof grants runtime authority, never creation
ownership or independent window app-ID attestation.
"""
import asyncio
import hashlib
import time
from app_router import VerifiedApp


def manifest_app_id(manifest_id):
    # Chromium hashes manifest bytes, then crx_file::id_util hashes that digest.
    digest = hashlib.sha256(manifest_id.encode()).digest()
    return ''.join(chr(ord('a') + int(c, 16)) for c in hashlib.sha256(digest).hexdigest()[:32])


class AppRouteError(PermissionError):
    """Only static phase/reason codes cross the control boundary."""
    PHASES = frozenset({'selection', 'baseline', 'existing_probe', 'launch',
                        'discovery', 'fresh_probe', 'refresh', 'binding'})

    def __init__(self, phase, *, launch_attempted=False, reason='failed'):
        self.phase = phase if phase in self.PHASES else 'selection'
        self.launch_attempted = bool(launch_attempted)
        self.reason = reason if reason in {'failed', 'generation', 'revoked', 'catalog',
            'identity', 'ambiguous', 'unproven', 'timeout', 'reserved'} else 'failed'
        super().__init__(f'app route {self.phase}: {self.reason}; no replay')

    def payload(self):
        return {'error': 'app_route_failed', 'status': 'tool_error',
                'phase': self.phase, 'reason': self.reason,
                'launch_attempted': self.launch_attempted, 'retryable': False}


class AppLauncher:
    def __init__(self, catalog, launch, *, timeout=3):
        self.catalog, self.launch, self.timeout = catalog, launch, timeout
        self.lock = asyncio.Lock()

    async def select(self, transport, url, *, recheck, preferred_target=None,
                     reserved_targets=()):
        """Select proof-qualified app targets, not independent window app-ID proof.

        Existing-window ambiguity is resolved only within the exact resolved
        registrar app/scope/profile plus compatible display-mode proof: prefer
        an already-bound target, otherwise choose the smallest target ID.
        reserved_targets is the broker's snapshot of other task authority;
        reservation overrides preference and all-reserved refuses without launch.
        Neither input bypasses proof. The broker must hold its task lease lock
        through selection and binding and recheck reservations before admission.
        Fresh post-launch ambiguity still fails closed, with no action replay.
        """
        state = {'phase': 'selection', 'launch_attempted': False}
        try:
            async with self.lock:
                return await self._select(transport, url, recheck=recheck, state=state,
                                          preferred_target=preferred_target,
                                          reserved_targets=frozenset(reserved_targets))
        except AppRouteError:
            raise
        except asyncio.CancelledError as error:
            # Cancellation must propagate, but its exact launch boundary survives.
            error.launch_attempted = state['launch_attempted']
            error.phase = state['phase']
            raise
        except Exception:
            raise AppRouteError(**state) from None

    async def _select(self, transport, url, *, recheck, state, preferred_target,
                      reserved_targets):
        def fail(reason):
            return AppRouteError(**state, reason=reason)

        recheck()
        app = self.catalog.resolve(url, profile='Default')
        if app is None:
            return None  # Safe fallback only before launch.
        if (not isinstance(app, VerifiedApp) or app.profile != 'Default'
                or not app.contains(url)
                or app.display_mode not in (None, 'minimal-ui', 'standalone', 'window-controls-overlay')
                or manifest_app_id(app.manifest_id) != app.app_id
                or not transport.context_id or not self.catalog.revalidate(app)):
            raise fail('unproven')
        generation, context = transport.upstream_url, transport.context_id

        def check():
            try:
                recheck()
            except PermissionError:
                raise fail('revoked') from None
            if transport.upstream_url != generation or transport.context_id != context:
                raise fail('generation')
            if not self.catalog.revalidate(app):
                raise fail('catalog')

        def eligible(info):
            return (info.get('type') == 'page' and info.get('browserContextId') == context
                    and app.contains(info.get('url'))
                    and self.catalog.resolve(info.get('url'), profile='Default') == app)

        async def prove(target):
            check()
            attached = await transport.command('Target.attachToTarget', {'targetId': target, 'flatten': True})
            sid = attached['sessionId']
            try:
                check()
                result = await transport.command('Runtime.evaluate', {
                    'expression': "(() => { const modes = {}; for (const mode of ['browser', 'minimal-ui', 'standalone', 'window-controls-overlay']) modes[mode] = matchMedia('(display-mode: ' + mode + ')').matches; return modes; })()",
                    'returnByValue': True}, sid)
                check()
                modes = result.get('result', {}).get('value')
                if not isinstance(modes, dict) or result.get('exceptionDetails'):
                    raise fail('unproven')
                if any(type(modes.get(mode)) is not bool for mode in
                       ('browser', 'minimal-ui', 'standalone', 'window-controls-overlay')):
                    raise fail('unproven')
                app_modes = [mode for mode in ('minimal-ui', 'standalone', 'window-controls-overlay')
                             if modes[mode]]
                compatible = ('minimal-ui',) if app.display_mode == 'minimal-ui' else (
                    'standalone', 'window-controls-overlay')
                proven = not modes['browser'] and len(app_modes) == 1 and app_modes[0] in compatible
                # Only an unequivocal ordinary browser tab is skippable. An
                # unknown/contradictory app window must not cause a duplicate.
                mismatch = not proven and (bool(app_modes) or not modes['browser'])
                exact = (await transport.command('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
                check()
                if exact.get('targetId') != target or not eligible(exact):
                    raise fail('identity')
                if mismatch:
                    raise fail('unproven')
                return proven
            finally:
                await transport.command('Target.detachFromTarget', {'sessionId': sid})
                check()

        state['phase'] = 'baseline'
        before = (await transport.command('Target.getTargets')).get('targetInfos', [])
        check()
        baseline = {i['targetId'] for i in before}
        state['phase'] = 'existing_probe'
        existing = []
        for info in before:
            if eligible(info) and await prove(info['targetId']):
                existing.append(info['targetId'])
        check()
        if existing:
            available = [target for target in existing if target not in reserved_targets]
            if not available:
                raise fail('reserved')  # Never duplicate-launch to evade task authority.
            # Helper intent authorizes reuse of this exact registrar/scope/profile
            # class, not an arbitrary same-origin tab. Stable target order avoids
            # guessing recency (CDP exposes no reliable last-active timestamp).
            # The broker still grants exclusive task authority before attachment.
            target = preferred_target if preferred_target in available else min(available)
            return {'target_id': target, 'app_id': app.app_id, 'created_owned': False}
        state.update(phase='launch', launch_attempted=True)
        await self.launch(app)  # Exactly once; failure is uncertain, never fallback.
        check()
        deadline = time.monotonic() + self.timeout
        while True:
            state['phase'] = 'discovery'
            check()
            infos = (await transport.command('Target.getTargets')).get('targetInfos', [])
            check()
            candidates = [i for i in infos if i.get('targetId') not in baseline and eligible(i)]
            if len(candidates) > 1:
                raise fail('ambiguous')
            if len(candidates) == 1:
                state['phase'] = 'fresh_probe'
                target = candidates[0]['targetId']
                if await prove(target):
                    return {'target_id': target, 'app_id': app.app_id, 'created_owned': False}
                # A new page may precede display-mode settling. Read-only retry.
            if time.monotonic() >= deadline:
                raise fail('timeout')
            await asyncio.sleep(.05)
