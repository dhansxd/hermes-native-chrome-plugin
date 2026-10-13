"""Fresh read-only registrar proof; never retain surrounding account metadata."""
import asyncio
import time

FILTERED_REGISTRAR = """(() => {
  const element = document.querySelector('web-app-internals-app')?.shadowRoot?.querySelector('#json');
  if (!element || !element.textContent) return null;
  const raw = JSON.parse(element.textContent);
  const details = raw.InstalledWebApps && raw.InstalledWebApps.Details;
  if (!Array.isArray(details)) return null;
  const fields = ['manifest_id','scope','install_state','user_display_mode','display_mode',
    'is_uninstalling','is_from_sync_and_pending_installation'];
  return {profile:'Default', apps:details.map(item => {
    const app = {app_id:item['!app_id']};
    for (const field of fields) if (field in item) app[field] = item[field];
    return app;
  })};
})()"""

async def refresh(catalog, transport, *, recheck, timeout=3):
    from app_launch import AppRouteError
    try:
        return await _refresh(catalog, transport, recheck=recheck, timeout=timeout)
    except asyncio.CancelledError as error:
        error.launch_attempted = False
        error.phase = 'refresh'
        raise
    except AppRouteError:
        raise
    except Exception:
        raise AppRouteError('refresh') from None


async def _refresh(catalog, transport, *, recheck, timeout):
    if not transport.context_id or catalog.profile != 'Default':
        raise PermissionError('registrar profile context unproven')
    generation, context = transport.upstream_url, transport.context_id
    def check():
        recheck()
        if transport.upstream_url != generation or transport.context_id != context:
            raise PermissionError('registrar generation/context changed')
    check()
    created = await transport.command('Target.createTarget', {
        'url': 'about:blank', 'browserContextId': context, 'background': True})
    target = created['targetId']
    try:
        check()
        attached = await transport.command('Target.attachToTarget', {'targetId': target, 'flatten': True})
        sid = attached['sessionId']
        check()
        await transport.command('Page.navigate', {'url': 'chrome://web-app-internals/'}, sid)
        check()
        deadline = time.monotonic() + timeout
        while True:
            check()
            info = (await transport.command('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
            check()
            if (info.get('targetId') != target or info.get('type') != 'page'
                    or info.get('browserContextId') != context):
                raise PermissionError('registrar exact target proof lost')
            if info.get('url') == 'chrome://web-app-internals/':
                result = await transport.command('Runtime.evaluate', {'expression': FILTERED_REGISTRAR, 'returnByValue': True}, sid)
                value = result.get('result', {}).get('value')
                if isinstance(value, dict) and not result.get('exceptionDetails'):
                    check()
                    return catalog.ingest_filtered(value, profile_verified=True)
            if time.monotonic() >= deadline:
                raise PermissionError('registrar readback unavailable')
            await asyncio.sleep(.05)
    finally:
        # Only the exact target this reader created; no manual-window cleanup.
        if transport.upstream_url == generation:
            await transport.command('Target.closeTarget', {'targetId': target})
