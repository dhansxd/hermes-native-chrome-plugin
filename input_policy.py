"""Opt-in focus preparation for public CDP Input commands; no import side effects.

Integration (not installed by this module): retain Broker.forward's authorization
checks. Replace only its existing Input.* bringToFront block with an early return:

    if method.startswith('Input.'):
        return await dispatch_input(self, data, state, mode=configured_input_mode)

Keep broker.command as the injected boundary (never forward recursively), and
keep Page.setWebLifecycleState blocked. Choose mode explicitly before starting a
lease: 'emulate' sends Emulation.setFocusEmulationEnabled(enabled=True) on each
verified mapped page session; 'foreground' uses Page.bringToFront instead; 'deny'
sends nothing. Unknown configuration fails closed. No automatic fallback exists,
not even when emulation is unsupported: switch to foreground only for a NEW,
explicitly authorized operation after diagnosing the previous outcome. Never
replay a failed, timed-out, cancelled, disconnected, or silently dropped Input.

Public schema: https://github.com/ChromeDevTools/devtools-protocol/blob/master/json/browser_protocol.json
setWebLifecycleState transitions frozen/active lifecycle, NOT focus. Focus
emulation is experimental and simulates a focused/active page; neither its ACK
nor an Input ACK guarantees DOM delivery or nonforeground behavior on native
macOS. It does not select an editable element, unblock dialogs, or unfreeze a
page. Native driver fill_input cold starts/background tabs require live evidence.

No cache or automatic disable/cleanup is used: a failed cleanup after Input could
hide an already completed mutation. Emulation may persist for the session/page
and alter focus/visibility events. Keep mode fixed per lease; investigate explicit
reset only as a separate lifecycle operation with fresh ownership checks. This
policy deliberately rejects workers/iframes/tab containers, checks scope after
every await, and never logs payloads. Checks cannot undo in-flight mutations or
detect revoke-and-restore (ABA) without a broker-owned monotonic scope epoch.
Concurrent leases/state mutation require broker-level serialization/epochs; this
module adds no global lock, launcher, configuration, GUI, or process control.
"""

from copy import deepcopy


async def dispatch_input(broker, data, state, *, mode, send=None):
    """Send one Input command to a mapped page; caller supplies explicit mode."""
    if mode not in ('emulate', 'foreground', 'deny'):
        raise ValueError('explicit input policy must be emulate, foreground, or deny')
    method = data.get('method')
    if not isinstance(method, str) or not method.startswith('Input.') or method == 'Input.':
        raise ValueError('input policy accepts only Input commands')
    if mode == 'deny':
        raise PermissionError('input disabled by explicit policy')
    sid = data.get('sessionId')
    upstream_sid = state.get(sid)
    target = broker.session_targets.get(sid)
    if (not broker.leases or not sid or not upstream_sid or not target
            or target not in broker.targets
            or (broker.vault_target is not None and broker.vault_target != target)):
        raise PermissionError('input requires admitted exact owned target/session')
    params = deepcopy(dict(data.get('params', {})))
    if any(key in params for key in ('targetId', 'sessionId', 'browserContextId')):
        raise ValueError('Input parameters cannot override the mapped route')
    send = send or broker.command
    epoch = getattr(broker, 'epoch', None)
    admitted = dict(broker.leases)
    vault_scope = broker.vault_target

    def recheck():
        if (getattr(broker, 'epoch', None) != epoch or broker.leases != admitted or state.get(sid) != upstream_sid
                or broker.session_targets.get(sid) != target or target not in broker.targets
                or broker.vault_target != vault_scope):
            raise PermissionError('input admission or exact target scope changed; no replay')

    info = (await send('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
    recheck()
    if info.get('targetId') != target or info.get('type') != 'page':
        raise PermissionError('input focus policy requires a verified mapped page target')
    if mode == 'emulate':
        await send('Emulation.setFocusEmulationEnabled', {'enabled': True}, upstream_sid)
    else:
        await send('Page.bringToFront', {}, upstream_sid)
    recheck()
    result = await send(method, params, upstream_sid)
    recheck()
    return result
