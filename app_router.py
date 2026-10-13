"""Opt-in backend-only PWA conversion; never remap a harness target or replay code.

Catalog injection: resolve(url, profile='Default') -> VerifiedApp | None and
revalidate(app) -> bool. Only independent registrar-verified entries qualify.
The capability gate is runtime-only and bound to the proven browser generation.
"""
import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, unquote


def origin(url):
    try:
        if not isinstance(url, str) or '\\' in url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
            return None
        p = urlsplit(url)
        if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password:
            return None
        return p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class VerifiedApp:
    app_id: str
    manifest_id: str
    scope: str
    profile: str
    display_mode: str | None = None

    def contains(self, url):
        if not origin(self.scope) or origin(url) != origin(self.scope):
            return False
        path, prefix = urlsplit(url).path or '/', urlsplit(self.scope).path or '/'
        for candidate in (path, prefix):
            if '%2f' in candidate.lower() or '%5c' in candidate.lower():
                return False
            if any(part in {'.', '..'} for part in unquote(candidate).split('/')):
                return False
        return path == prefix or path.startswith(prefix if prefix.endswith('/') else prefix + '/')


class CatalogAdapter:
    """Keep catalog-owned snapshot freshness separate from routing policy."""
    def __init__(self, catalog):
        self.catalog = catalog
        self.records = {}

    def resolve(self, url, *, profile):
        record = self.catalog.match(url)
        if (record is None or record.profile != profile or not record.manifest_id
                or not record.scope or not self.catalog.revalidate(record)):
            return None
        app = VerifiedApp(record.app_id, record.manifest_id, record.scope, record.profile,
                          getattr(record, 'display_mode', None))
        self.records[app] = record
        return app

    def revalidate(self, app):
        record = self.records.get(app)
        return record is not None and self.catalog.revalidate(record)


class AppFirstRouter:
    def __init__(self, catalog, *, commit_timeout=1):
        self.catalog = catalog
        self.commit_timeout = commit_timeout
        self.gate = None
        self.last_outcome = 'disabled'

    def arm(self, *, browser_uuid, context_id, identity_preserved):
        """Trusted backend calls only after live exact-target conversion proof."""
        if not browser_uuid or not context_id or identity_preserved is not True:
            raise PermissionError('live in-place PWA identity proof required')
        self.gate = (browser_uuid, context_id)

    def ready(self, scope):
        endpoint = scope.transport.upstream_url or ''
        return self.gate == (endpoint.rsplit('/', 1)[-1], scope.context_id)

    async def navigate(self, scope, target, params, upstream_sid, send, recheck):
        """Send Page.navigate exactly once, optionally convert that same page."""
        app = None
        if (self.ready(scope) and scope.vault_target is None
                and not hasattr(scope, 'borrowed_target_id')
                and target in scope.page_targets and target not in scope.parents
                and scope.disposable.get(target) == 'blank'
                and set(params) == {'url'}):
            selected = self.catalog.resolve(params['url'], profile='Default')
            if (isinstance(selected, VerifiedApp) and selected.profile == 'Default'
                    and selected.app_id and origin(selected.manifest_id)
                    and selected.contains(params['url']) and self.catalog.revalidate(selected)):
                info = (await send('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
                if self.exact_page(info, target, scope.context_id) and info.get('url') == 'about:blank':
                    app = selected
        result = await send('Page.navigate', params, upstream_sid)
        if app is None or result.get('errorText') or result.get('isDownload') or not result.get('loaderId'):
            return result
        try:
            await self.convert(scope, target, app, result, upstream_sid, send, recheck)
        except BaseException as error:
            # The navigation already happened. Returning an error here makes
            # installed new_tab's reuse branch create/navigate a second tab.
            # Retain uncertainty and disable routing; never imply app success.
            scope.preserve = True
            self.gate = None
            self.last_outcome = 'conversion_uncertain'
            await scope.takeover.pause(target)
            if not isinstance(error, Exception):
                raise
        return result

    async def convert(self, scope, target, app, result, upstream_sid, send, recheck):
        deadline = time.monotonic() + self.commit_timeout
        while True:
            tree = await send('Page.getFrameTree', {}, upstream_sid)
            frame = tree.get('frameTree', {}).get('frame', {})
            if frame.get('id') == result.get('frameId') and frame.get('loaderId') == result['loaderId']:
                break
            if time.monotonic() >= deadline:
                return result  # Ordinary tab, never replay failed/slow navigation.
            await asyncio.sleep(.05)
            recheck()
        if not app.contains(frame.get('url')) or not self.catalog.revalidate(app):
            return result  # Redirect/auth/uninstall are never relocated or replayed.
        before = (await send('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
        if not self.exact_page(before, target, scope.context_id) or not app.contains(before.get('url')):
            return result
        recheck()
        if not self.ready(scope) or not self.catalog.revalidate(app):
            return result
        current = (await send('Page.getFrameTree', {}, upstream_sid)).get('frameTree', {}).get('frame', {})
        if (current.get('id') != result.get('frameId') or current.get('loaderId') != result['loaderId']
                or not app.contains(current.get('url'))):
            return result
        recheck()
        if not self.ready(scope) or not self.catalog.revalidate(app):
            return result
        await send('PWA.openCurrentPageInApp', {'manifestId': app.manifest_id}, upstream_sid)
        after = (await send('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
        if not self.exact_page(after, target, scope.context_id) or not app.contains(after.get('url')):
            scope.preserve = True
            raise PermissionError('in-place PWA identity/context changed; no replay')
        self.last_outcome = 'converted'

    @staticmethod
    def exact_page(info, target, context):
        return (info.get('targetId') == target and info.get('type') == 'page'
                and info.get('browserContextId') == context)
