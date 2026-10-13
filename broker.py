"""Loopback CDP transport and capability-scoped task routing; no import side effects."""
import asyncio
import json
import secrets
import time
import plugin_identity
import harness_cleanup
from takeover import TakeoverRegistry
from input_policy import dispatch_input
from native import NativeFailure
import state_journal as ownership
from aiohttp import web, ClientSession, ClientWSTimeout, WSMsgType, WSServerHandshakeError, ClientConnectorError


class ResourceLimit(RuntimeError):
    code = 'resource_limit'


class InitialTransportNotReady(ConnectionError):
    """Initial launcher/connect failed before any ownership or mutation."""


class Broker:
    def __init__(self, connector, *, control_token, idle_seconds=60, ws_connector=None, marker_timeout=5):
        self.connector = connector
        self.ws_connector = ws_connector
        self.control_token = control_token
        self.idle_seconds = idle_seconds
        self.marker_timeout = marker_timeout
        self.namespace = None
        self.capability = None
        self.leases = {}
        self.targets = set()
        self.upstream = None
        self.http = None
        self.sequence = 0
        self.last_activity = time.monotonic()
        self.lock = asyncio.Lock()
        self.pending = {}
        self.clients = {}
        self.client_capabilities = {}
        self.reader = None
        self.context_id = None
        self.janitor = None
        self.preserve = False
        self.admission_retryable = False
        self.last_error = None
        self.downloads = set()
        self.upstream_url = None
        self.session_targets = {}
        self.vault_target = None
        self.closing = False

    def app(self):
        app = web.Application()
        app.router.add_get('/json/version', self.discovery)
        app.router.add_post('/control/acquire', self.acquire)
        app.router.add_get('/devtools/browser/{capability}', self.socket)
        app.router.add_post('/control/release', self.release)
        app.router.add_post('/control/bind-vault', self.bind_vault)
        app.router.add_post('/control/preserve', self.mark_preserve)
        app.router.add_get('/health', self.health)
        app.on_startup.append(self.start_janitor)
        # Close capability sockets while their receive handlers still run.
        # on_cleanup is too late: aiohttp has already canceled WS handlers,
        # leaving the installed CDP client's reader parked on an orphan socket.
        # Its dedicated-target finalizer then sends a close with no reply path.
        app.on_shutdown.append(self.shutdown)
        app.on_cleanup.append(self.shutdown)
        return app

    async def command(self, method, params=None, session_id=None):
        if self.closing:
            raise ConnectionError('broker shutting down; no replay')
        self.sequence += 1
        ident = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[ident] = future
        message = {'id': ident, 'method': method, 'params': params or {}}
        if session_id:
            message['sessionId'] = session_id
        try:
            await self.upstream.send_json(message)
            data = await asyncio.wait_for(future, 10)
            if 'error' in data:
                error = RuntimeError('upstream command rejected; outcome may be uncertain')
                error.code = 'cdp_rejected'
                raise error
            return data.get('result', {})
        finally:
            self.pending.pop(ident, None)

    async def read_upstream(self):
        try:
            async for msg in self.upstream:
                if msg.type != WSMsgType.TEXT:
                    continue
                data = json.loads(msg.data)
                if 'id' in data:
                    future = self.pending.get(data['id'])
                    if future and not future.done():
                        future.set_result(data)
                    continue
                await self.event(data)
        finally:
            if self.pending and self.targets:
                self.preserve = True
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError('CDP disconnected; outcome uncertain, not replayed'))
            # A reconnect never resumes old flattened sessions or capabilities.
            self.session_targets.clear()
            # A bound vault lease must fail closed until release, never reopen all targets.
            if self.vault_target is not None:
                self.vault_target = '__disconnected__'
            for ws, state in list(self.clients.items()):
                state.clear()
                await ws.close(code=1012, message=b'upstream disconnected; no replay')

    async def event(self, data):
        params = data.get('params', {})
        info = params.get('targetInfo', {})
        if info.get('openerId') in self.targets:
            self.targets.add(info['targetId'])
        method = data.get('method')
        if method in {'Page.downloadWillBegin', 'Browser.downloadWillBegin'} and params.get('guid'):
            self.downloads.add(params['guid'])
        if method in {'Page.downloadProgress', 'Browser.downloadProgress'} and params.get('state') in {'completed', 'canceled'}:
            self.downloads.discard(params.get('guid'))
            # Completion restarts idle time, but never clears takeover/uncertainty preservation.
            self.last_activity = time.monotonic()
        for ws, state in list(self.clients.items()):
            reverse = {up: local for local, up in state.items()}
            sid = data.get('sessionId')
            if sid and sid not in reverse:
                continue
            if self.vault_target is not None:
                if sid and not any(up == sid and self.session_targets.get(local) == self.vault_target for local, up in state.items()):
                    continue
                if info.get('targetId', params.get('targetId', self.vault_target)) != self.vault_target:
                    continue
            child_owned = method == 'Target.attachedToTarget' and sid in reverse
            if method.startswith('Target.') and not child_owned and info.get('targetId', params.get('targetId')) not in self.targets:
                continue
            if not sid and not method.startswith('Target.'):
                continue
            event = dict(data)
            event['params'] = dict(params)
            if sid:
                event['sessionId'] = reverse[sid]
            if method == 'Target.attachedToTarget':
                local = secrets.token_urlsafe(16)
                state[local] = params['sessionId']
                self.session_targets[local] = info['targetId']
                event['params']['sessionId'] = local
                self.targets.add(info['targetId'])
            if method == 'Target.detachedFromTarget' and params.get('sessionId'):
                if params['sessionId'] not in reverse:
                    continue
                event['params']['sessionId'] = reverse[params['sessionId']]
            if not ws.closed:
                await ws.send_json(event)

    async def acquire(self, request):
        # Retryable only before an initial ownership/mutation boundary. Existing
        # generations still require the audited reconnect checks and latch loss.
        self.admission_retryable = self.namespace is None and not self.targets
        try:
            return await self._acquire(request)
        except web.HTTPException:
            raise
        except Exception as error:
            # Permission/identity/protocol rejection is not launcher readiness.
            import errno
            code = ('ws_denied' if error.status in {401, 403} else 'upstream_uncertain') if isinstance(error, WSServerHandshakeError) else getattr(error, 'code', None)
            benign = code in {'consent_expired', 'helper_ax'} or (code is None and isinstance(error, TimeoutError)) or (
                isinstance(error, OSError) and error.errno == errno.ECONNREFUSED)
            self.admission_retryable = self.admission_retryable and benign
            await self.disconnect()
            if self.targets:
                self.preserve = True
            self.last_error = code or ('startup' if self.admission_retryable else 'upstream_uncertain')
            return web.json_response({'status': 'tool_error', 'error': self.last_error, 'retryable': self.admission_retryable}, status=503)

    async def _acquire(self, request):
        if request.headers.get('Authorization') != 'Bearer ' + self.control_token:
            raise web.HTTPUnauthorized()
        data = await request.json()
        async with self.lock:
            if self.leases:
                return web.json_response({'error': 'overlapping calls unavailable in single-namespace preview'}, status=409)
            disconnected = self.upstream is None or self.upstream.closed or (self.reader and self.reader.done())
            if not disconnected and self.namespace is not None and data['namespace'] != self.namespace:
                return web.json_response({'error': 'single namespace already reserved; named isolation unavailable'}, status=409)
            if disconnected:
                reconnect = self.namespace is not None
                await self.disconnect()
                self.http = ClientSession()
                fresh = False
                if reconnect and hasattr(self.connector, 'discover_endpoint'):
                    try:
                        discover = getattr(self.connector, 'rediscover_endpoint', self.connector.discover_endpoint)
                        endpoint = await discover()
                    except (OSError, TimeoutError):
                        if not hasattr(self.connector, 'fresh_endpoint'):
                            raise
                        endpoint = await self.connector.fresh_endpoint(self.upstream_url)
                        fresh = True
                else:
                    endpoint = await self.connector()
                url = endpoint['url'] if isinstance(endpoint, dict) else endpoint
                if reconnect and url != self.upstream_url and not fresh:
                    if not hasattr(self.connector, 'fresh_endpoint'):
                        raise NativeFailure('profile_marker')
                    endpoint = await self.connector.fresh_endpoint(self.upstream_url)
                    url = endpoint['url']
                    fresh = True
                if fresh:
                    if url == self.upstream_url or not isinstance(endpoint, dict) or not endpoint.get('marker_url'):
                        raise NativeFailure('profile_marker')
                    # The connector proves replacement before any old ownership is retired.
                    self.targets.clear()
                    self.session_targets.clear()
                    self.context_id = self.vault_target = self.namespace = self.capability = None
                    self.downloads.clear()
                    self.preserve = False
                    reconnect = False
                try:
                    if self.ws_connector:
                        self.upstream = await self.ws_connector(self.http, url)
                    else:
                        self.upstream = await self.http.ws_connect(url, timeout=ClientWSTimeout(ws_close=5))
                except (WSServerHandshakeError, ClientConnectorError):
                    if not reconnect or not hasattr(self.connector, 'fresh_endpoint'):
                        raise
                    # Stale files can still name a dead UUID on a live TCP port.
                    # The connector independently proves the exact old WS dead.
                    endpoint = await self.connector.fresh_endpoint(self.upstream_url)
                    url = endpoint['url']
                    if url == self.upstream_url or not endpoint.get('marker_url'):
                        raise NativeFailure('profile_marker')
                    self.targets.clear()
                    self.session_targets.clear()
                    self.context_id = self.vault_target = self.namespace = self.capability = None
                    self.downloads.clear()
                    self.preserve = False
                    reconnect = False
                    if self.ws_connector:
                        self.upstream = await self.ws_connector(self.http, url)
                    else:
                        self.upstream = await self.http.ws_connect(url, timeout=ClientWSTimeout(ws_close=5))
                # A connected endpoint can now yield ownership or uncertain
                # creation. No subsequent failure is benign launcher readiness.
                self.admission_retryable = False
                self.reader = asyncio.create_task(self.read_upstream())
                if reconnect:
                    infos = (await self.command('Target.getTargets'))['targetInfos']
                    owned = {t['targetId']: t for t in infos if t['targetId'] in self.targets}
                    if set(owned) != self.targets or (self.context_id and any(t.get('browserContextId') != self.context_id for t in owned.values())):
                        raise NativeFailure('owned_target_lost')
                    if data['namespace'] != self.namespace:
                        return web.json_response({'error': 'single namespace reserved; no cross-task adoption'}, status=409)
                else:
                    params = {'url': 'about:blank', 'newWindow': True}
                    if isinstance(endpoint, dict):
                        deadline = asyncio.get_running_loop().time() + self.marker_timeout
                        while True:
                            infos = (await self.command('Target.getTargets'))['targetInfos']
                            markers = [t for t in infos if t.get('url') == endpoint['marker_url'] and t.get('type') == 'page']
                            if len(markers) > 1 or (markers and not markers[0].get('browserContextId')):
                                raise NativeFailure('profile_marker')
                            if markers:
                                break
                            if asyncio.get_running_loop().time() >= deadline:
                                raise NativeFailure('profile_marker')
                            await asyncio.sleep(.05)
                        self.context_id = markers[0]['browserContextId']
                        self.targets.add(markers[0]['targetId'])
                        params['browserContextId'] = self.context_id
                    result = await self.command('Target.createTarget', params)
                    self.targets.add(result['targetId'])
                    self.namespace = data['namespace']
                    self.upstream_url = url
                self.capability = secrets.token_urlsafe(32)
            lease = secrets.token_urlsafe(24)
            self.leases[lease] = self.namespace
            return web.json_response({'lease': lease})

    async def discovery(self, request):
        if self.namespace is None:
            raise web.HTTPServiceUnavailable(text='no admitted lease')
        return web.json_response({'Browser': 'Native-Chrome-Broker', 'Protocol-Version': '1.3',
            'webSocketDebuggerUrl': f'ws://{request.host}/devtools/browser/{self.capability}'})

    async def socket(self, request):
        if not self.leases:
            raise web.HTTPServiceUnavailable(text='no active admission')
        if request.match_info['capability'] not in {self.capability, getattr(self, 'vault_capability', None)}:
            raise web.HTTPForbidden()
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        state = self.clients[ws] = {}
        self.client_capabilities[ws] = request.match_info['capability']
        try:
            async for message in ws:
                if message.type != WSMsgType.TEXT:
                    continue
                data = json.loads(message.data)
                response = {'id': data.get('id')}
                if data.get('sessionId'):
                    response['sessionId'] = data['sessionId']
                try:
                    response['result'] = await self.forward(data, state)
                except Exception as error:
                    response['error'] = {'code': -32000, 'message': 'CDP rejected or disconnected; do not replay mutations',
                        'data': {'error': getattr(error, 'code', 'upstream_uncertain')}}
                if ws.closed:
                    break
                try:
                    await ws.send_json(response)
                except ConnectionError:
                    break
        finally:
            self.clients.pop(ws, None)
            self.client_capabilities.pop(ws, None)
        return ws

    async def forward(self, data, state):
        if not self.leases:
            raise PermissionError('no active admission')
        method = data['method']
        if method.startswith('PWA.'):
            raise PermissionError('PWA operations are backend-only')
        if method.startswith('Browser.') and method not in {'Browser.getVersion'}:
            raise PermissionError('global browser operation blocked')
        if method.startswith('Target.') and method not in {'Target.getTargets', 'Target.getTargetInfo', 'Target.attachToTarget', 'Target.detachFromTarget', 'Target.createTarget', 'Target.closeTarget', 'Target.activateTarget', 'Target.setDiscoverTargets', 'Target.setAutoAttach'}:
            raise PermissionError('unapproved target domain operation')
        params = dict(data.get('params', {}))
        if method in {'Page.setDownloadBehavior', 'Page.setWebLifecycleState'}:
            raise PermissionError('shared download/lifecycle mutation blocked')
        if 'sessionId' in params:
            if params['sessionId'] not in state:
                raise PermissionError('unowned nested session')
            params['sessionId'] = state[params['sessionId']]
        sid = data.get('sessionId')
        upstream_sid = state.get(sid) if sid else None
        if sid and upstream_sid is None:
            raise PermissionError('unowned session')
        if method in {'Browser.close', 'Browser.crash', 'Page.crash', 'Target.disposeBrowserContext', 'Target.createBrowserContext', 'Target.sendMessageToTarget'}:
            raise PermissionError('destructive or legacy operation blocked')
        for key in ('targetId',):
            if key in params and params[key] not in self.targets:
                raise PermissionError('unowned target')
        if self.vault_target is not None:
            if sid and self.session_targets.get(sid) != self.vault_target:
                raise PermissionError('session outside exact vault target')
            if 'sessionId' in data.get('params', {}) and self.session_targets.get(data['params']['sessionId']) != self.vault_target:
                raise PermissionError('nested session outside exact vault target')
            if params.get('targetId', self.vault_target) != self.vault_target:
                raise PermissionError('target outside exact vault target')
            if method == 'Target.setAutoAttach' and not sid:
                raise PermissionError('unscoped vault autoattach')
            if method in {'Target.createTarget', 'Target.closeTarget', 'Target.activateTarget'}:
                raise PermissionError('vault target selection is immutable')
        if method == 'Target.getTargets':
            result = await self.command(method)
            return {'targetInfos': [t for t in result.get('targetInfos', []) if t['targetId'] in self.targets and (self.vault_target is None or t['targetId'] == self.vault_target)]}
        if method == 'Target.attachToTarget':
            if not params.get('flatten'):
                raise PermissionError('only flattened sessions supported')
            result = await self.command(method, params)
            local = secrets.token_urlsafe(16)
            state[local] = result['sessionId']
            self.session_targets[local] = params['targetId']
            return {'sessionId': local}
        if method == 'Target.createTarget':
            params.pop('browserContextId', None)
            if self.context_id:
                params['browserContextId'] = self.context_id
            result = await self.command(method, params)
            self.targets.add(result['targetId'])
            return result
        if not sid and method not in {'Browser.getVersion', 'Browser.getBrowserCommandLine', 'Target.getTargetInfo', 'Target.activateTarget', 'Target.closeTarget', 'Target.setDiscoverTargets'}:
            raise PermissionError('unscoped browser command')
        if method == 'Target.getTargetInfo' and not params.get('targetId'):
            raise PermissionError('ambiguous target')
        if method == 'Target.setDiscoverTargets':
            params['filter'] = [{'type': 'page'}, {'exclude': True}]
        if method.startswith('Input.'):
            target = self.session_targets.get(sid)
            if target not in self.targets:
                raise PermissionError('input requires exact owned target binding')
            admitted = set(self.leases)
            # Native headed key dispatch can silently drop input before activation.
            # Activate this flattened session first, never replay an Input mutation.
            # This may foreground Chrome; do not cache focus across user interaction.
            await self.command('Page.bringToFront', {}, upstream_sid)
            if (not admitted.intersection(self.leases) or state.get(sid) != upstream_sid
                    or self.session_targets.get(sid) != target or target not in self.targets
                    or (self.vault_target is not None and target != self.vault_target)):
                raise PermissionError('input admission or exact target binding changed')
        return await self.command(method, params, upstream_sid)

    async def health(self, request):
        ready = self.upstream is not None and not self.upstream.closed and self.reader is not None and not self.reader.done()
        eligible = bool(ready and self.namespace is not None and not (self.leases or self.pending or self.downloads or self.preserve))
        remaining = max(0, self.idle_seconds - (time.monotonic() - self.last_activity)) if eligible else None
        return web.json_response({'service': plugin_identity.plugin_id(), 'state': 'ready' if ready else 'disconnected',
            'active': len(self.leases), 'owned': len(self.targets), 'preserve': self.preserve,
            'pending': len(self.pending), 'downloads': len(self.downloads), 'clients': len(self.clients),
            'idle_eligible': eligible, 'idle_remaining_seconds': remaining})

    async def mark_preserve(self, request):
        if request.headers.get('Authorization') != 'Bearer ' + self.control_token:
            raise web.HTTPUnauthorized()
        self.preserve = True
        return web.json_response({'preserved': True})

    async def bind_vault(self, request):
        if request.headers.get('Authorization') != 'Bearer ' + self.control_token:
            raise web.HTTPUnauthorized()
        data = await request.json()
        async with self.lock:
            target, sid = data.get('target_id'), data.get('session_id')
            if data.get('lease') not in self.leases or self.vault_target is not None:
                raise web.HTTPForbidden()
            if target not in self.targets or self.session_targets.get(sid) != target:
                raise web.HTTPForbidden()
            if not any(sid in state for state in self.clients.values()):
                raise web.HTTPForbidden()
            self.vault_target = target
        return web.json_response({'bound': True})

    async def release(self, request):
        if request.headers.get('Authorization') != 'Bearer ' + self.control_token:
            raise web.HTTPUnauthorized()
        data = await request.json()
        async with self.lock:
            if data.get('lease') not in self.leases:
                raise web.HTTPNotFound()
            self.leases.pop(data['lease'])
            self.vault_target = None
            self.last_activity = time.monotonic()
        return web.json_response({'released': True})

    async def start_janitor(self, app):
        async def run():
            while True:
                await asyncio.sleep(1)
                await self.sweep()
        self.janitor = asyncio.create_task(run())

    async def sweep(self, now=None):
        async with self.lock:
            if self.namespace is None or self.leases or self.pending or self.downloads or self.preserve:
                return
            if (time.monotonic() if now is None else now) - self.last_activity < self.idle_seconds:
                return
            try:
                for target in tuple(self.targets):
                    await self.command('Target.closeTarget', {'targetId': target})
            except Exception:
                self.preserve = True
                return
            await self.disconnect()
            self.targets.clear()
            self.session_targets.clear()
            self.context_id = self.vault_target = self.upstream_url = None
            self.namespace = self.capability = None

    async def disconnect(self):
        for future in tuple(self.pending.values()):
            if not future.done():
                future.set_exception(ConnectionError('CDP retired; outcome uncertain, not replayed'))
        for ws in list(self.clients):
            await ws.close(code=1012, message=b'capability retired; no replay')
        if self.upstream is not None:
            try:
                # A peer executing an unanswered command may never consume CLOSE.
                # aiohttp closes its transport when this close is canceled.
                await asyncio.wait_for(self.upstream.close(), 1)
            except TimeoutError:
                pass
        if self.reader is not None:
            await self.reader
        if self.http is not None:
            await self.http.close()
        self.upstream = self.http = self.reader = None

    async def shutdown(self, app):
        self.closing = True
        if hasattr(self, 'transport'):
            self.transport.closing = True
        if self.janitor:
            self.janitor.cancel()
            try:
                await self.janitor
            except asyncio.CancelledError:
                pass
        await self.disconnect()


class RoutingTransport(Broker):
    async def event(self, data):
        await self.router.event(data)

    async def read_upstream(self):
        try:
            await super().read_upstream()
        finally:
            for scope in tuple(self.router.scopes.values()):
                # Every outstanding flattened selection is revoked. Conservatively
                # preserve owned resources after loss, including uncertain actions.
                scope.epoch += 1
                scope.provenance_sessions.clear()
                scope.session_targets.clear()
                # Loss alone is not mutation evidence. Sticky preservation and
                # transfer guards remain; meaningful sends install risk first.
                scope.preserve = scope.preserve or bool(scope.mutations_inflight or scope.uploads or scope.downloads)
                for guard in scope.uploads.values():
                    guard['state'] = 'uncertain'
                if scope.vault_target is not None:
                    scope.vault_target = '__disconnected__'
                for ws, state in tuple(scope.clients.items()):
                    state.clear()
                    await ws.close(code=1012, message=b'upstream disconnected; no replay')


class SessionScope(Broker):
    """Independent ownership/admission state; commands share one Chrome transport."""
    def __init__(self, transport, namespace, **kwargs):
        super().__init__(transport.connector, **kwargs)
        self.transport = transport
        self.namespace = namespace
        self.durable_namespace = namespace
        self.context_id = transport.context_id
        self.capability = secrets.token_urlsafe(32)
        self.vault_capability = None
        self.takeover = TakeoverRegistry()
        self.parents = {}
        self.page_targets = set()
        self.provenance_sessions = {}
        self.revoked_sessions = {}
        self.epoch = 0
        self.input_mode = 'emulate'
        # Guard is installed before any awaited preparation/selection. No file
        # paths, request bodies, headers or URLs are retained.
        self.uploads = {}
        self.upload_quiet_seconds = 2
        self.recovery_guards = {}
        self.mutations_inflight = 0
        self.disposable = {}
        self.mutation_risk = set()
        self.disposable_cleanup = None
        self.preamble_cleanup = None  # Exact authenticated active-lease close fence.

    async def command(self, method, params=None, session_id=None):
        if self.transport.closing:
            raise ConnectionError('broker shutting down; no replay')
        router = self.transport.router
        if method == 'Target.createTarget':
            router.reserve_create(self.durable_namespace)
        risky = method not in {'Target.getTargets', 'Target.getTargetInfo', 'Browser.getVersion',
            'Target.createTarget', 'Target.closeTarget', 'Target.attachToTarget', 'Target.detachFromTarget',
            'Target.setDiscoverTargets', 'Target.setAutoAttach', 'Target.activateTarget',
            'Runtime.enable', 'Page.enable', 'Network.enable', 'DOM.enable'}
        bound = self.provenance_sessions.get(session_id)
        risk_target = self.page(bound) if bound else None
        external = getattr(self, 'external_app_targets', set()) | getattr(self, 'external_descendants', set())
        if risk_target in external or (params or {}).get('targetId') in external:
            # Runtime-only verified lineage, never durable created ownership.
            target = risk_target or (params or {}).get('targetId')
            if method in {'Target.closeTarget', 'Page.close'} and target in getattr(self, 'external_app_targets', set()):
                raise PermissionError('external app has no close ownership')
            epoch, leases = self.epoch, dict(self.leases)
            if router.journal is not None:
                await router.check_generation()
            if method in {'Target.closeTarget', 'Page.close'}:
                infos = (await self.transport.command('Target.getTargets')).get('targetInfos', [])
                by_id = {i['targetId']: i for i in infos}
                tree = {t for t in self.targets if self.page(t) == target}
                pending_children = {target}
                for _ in infos:
                    children = {i['targetId'] for i in infos if i.get('openerId') in pending_children}
                    if children <= pending_children:
                        break
                    pending_children |= children
                if (self.preserve or self.uploads or self.downloads or self.transport.pending
                        or any(self.recovery_guards.get(k) for k in ('uncertain', 'mutation_pending', 'busy', 'downloads_pending'))
                        or self.recovery_guards.get('upload_status') in {'in_progress', 'uncertain'}
                        or not pending_children <= tree
                        or any(not self.takeover.is_active(t) for t in tree)
                        or any(by_id.get(t, {}).get('browserContextId') != self.context_id for t in tree)
                        or by_id.get(target, {}).get('openerId') != self.parents.get(target)
                        or self.parents.get(target) not in self.targets
                        or not self.takeover.is_active(self.parents.get(target))):
                    raise PermissionError('external child close safety unproven')
                if router.journal is not None:
                    await router.check_generation()
                if (self.preserve or self.uploads or self.downloads or self.transport.pending
                        or any(self.recovery_guards.get(k) for k in ('uncertain', 'mutation_pending', 'busy', 'downloads_pending'))
                        or self.recovery_guards.get('upload_status') in {'in_progress', 'uncertain'}
                        or any(t not in self.targets or not self.takeover.is_active(t) for t in tree)
                        or self.parents.get(target) not in self.targets
                        or not self.takeover.is_active(self.parents.get(target))):
                    raise PermissionError('external child close safety revoked')
            if (router.transport_blocked or epoch != self.epoch or leases != self.leases or not self.leases
                    or target not in self.targets or not self.takeover.is_active(target)
                    or (session_id and self.provenance_sessions.get(session_id) != bound)):
                raise PermissionError('external app admission or binding revoked')
            return await self.transport.command(method, params, session_id)
        # Exact installed title mark/unmark and observation-only Network.disable
        # on a pristine broker-created blank are setup, not meaningful effects.
        # Never generalize Runtime/Emulation or clear an existing durable risk bit.
        marker = "if(!document.title.startsWith('🐴'))document.title='🐴 '+document.title"
        unmark = "if(document.title.startsWith('🐴 '))document.title=document.title.slice(3)"
        cosmetic = (method == 'Runtime.evaluate' and params in ({'expression': marker}, {'expression': unmark}))
        setup_disable = method == 'Network.disable' and (params or {}) == {}
        if (risky and (cosmetic or setup_disable)
                and risk_target in self.targets and self.disposable.get(risk_target) == 'blank'
                and risk_target not in self.mutation_risk):
            epoch, leases = self.epoch, dict(self.leases)
            info = (await self.transport.command('Target.getTargetInfo', {'targetId': risk_target})).get('targetInfo', {})
            if epoch != self.epoch or leases != self.leases or self.provenance_sessions.get(session_id) != bound:
                raise PermissionError('blank preparation binding revoked')
            if (info.get('targetId') == risk_target and info.get('type') == 'page'
                    and info.get('url') == 'about:blank' and info.get('browserContextId') == self.context_id):
                risky = False
        if risky:
            self.mutation_risk.update({risk_target} if risk_target else self.targets)
        if router.journal is None:
            result = await self.transport.command(method, params, session_id)
            if method == 'Target.createTarget':
                router.confirm_create(self.durable_namespace, result['targetId'])
                self.disposable[result['targetId']] = 'blank' if (params or {}).get('url') == 'about:blank' else 'protected'
            elif method == 'Target.closeTarget' and result.get('success') is True:
                router.resource_targets.get(self.durable_namespace, set()).discard((params or {}).get('targetId'))
            return result
        epoch, leases = self.epoch, dict(self.leases)
        await router.check_generation()
        readonly = method in {'Target.getTargets', 'Target.getTargetInfo', 'Browser.getVersion'}
        safe_close = method == 'Target.closeTarget' and self.disposable_cleanup == (params or {}).get('targetId') and self.safe_disposable(self.disposable_cleanup)
        if not readonly and not safe_close and (self.recovery_guards.get('mutation_pending') or self.recovery_guards.get('uncertain')):
            raise PermissionError('crash uncertainty requires explicit reconciliation')
        close_tree = {t for t in self.targets if self.page(t) == (params or {}).get('targetId')} if method == 'Target.closeTarget' else set()
        if close_tree:
            infos = (await self.transport.command('Target.getTargets')).get('targetInfos', [])
            await router.check_generation()
            structural = json.loads(json.dumps(router.journal_state))
            for metadata in structural['scopes'].values():
                metadata['guards'] = dict(ownership.GUARD_DEFAULTS)
            live_edges = {tid: self.parents[tid] for tid in self.provenance_sessions.values() if tid in self.parents}
            plan = ownership.recovery_plan(structural, structural['browser'], infos, live_parents=live_edges)
            if (params or {}).get('targetId') not in plan['scopes'][self.durable_namespace]['cleanup_candidates']:
                self.preserve = True
                await router.journal_commit(lambda state: ownership.set_guards(state, self.durable_namespace, preserve=True))
                raise PermissionError('live descendant/context ownership unproven')
        if not readonly:
            self.mutations_inflight += 1
            previous_pending = self.recovery_guards.get('mutation_pending', False)
            def intent(state):
                if method == 'Target.createTarget':
                    ownership.reserve_resource(state, self.durable_namespace, 1)
                ownership.set_guards(state, self.durable_namespace, mutation_pending=True)
                if risky:
                    for t in ({risk_target} if risk_target else self.targets):
                        ownership.mark_mutation_risk(state, self.durable_namespace, t)
                for t in close_tree:
                    ownership.set_takeover(state, self.durable_namespace, t, 'paused')
            await router.journal_commit(intent)
        try:
            await router.check_generation()
            if safe_close:
                info = (await self.transport.command('Target.getTargetInfo', {'targetId': self.disposable_cleanup})).get('targetInfo', {})
                expected = 'about:blank' if self.disposable.get(self.disposable_cleanup) == 'blank' else (router.live_endpoint or {}).get('marker_url')
                await router.check_generation()
                if not expected or info.get('url') != expected or info.get('browserContextId') != self.context_id:
                    raise PermissionError('disposable page changed during journal commit')
            if epoch != self.epoch or leases != self.leases:
                raise PermissionError('admission revoked during write ahead')
            if method == 'Target.closeTarget' and (
                    (self.preserve and not safe_close) or self.downloads or self.uploads or self.transport.pending
                    or (safe_close and not self.safe_disposable(self.disposable_cleanup))
                    or (not leases and self.leases)
                    or any(not self.takeover.is_active(t) for t in close_tree)):
                raise PermissionError('close revoked or activity changed during journal commit')
            result = await self.transport.command(method, params, session_id)
            if method == 'Target.closeTarget' and result.get('success') is not True:
                raise ConnectionError('close unconfirmed; preserve')
            await router.check_generation()
            if not readonly:
                def complete(state):
                    if method == 'Target.createTarget':
                        ownership.reserve_resource(state, self.durable_namespace, -1)
                        ownership.register_created(state, self.durable_namespace, result['targetId'],
                            disposable='blank' if (params or {}).get('url') == 'about:blank' else 'protected')
                    for t in close_tree:
                        ownership.set_takeover(state, self.durable_namespace, t, 'released')
                    ownership.set_guards(state, self.durable_namespace, mutation_pending=previous_pending or self.mutations_inflight > 1)
                await router.journal_commit(complete)
            if method == 'Target.createTarget':
                router.confirm_create(self.durable_namespace, result['targetId'])
                self.disposable[result['targetId']] = 'blank' if (params or {}).get('url') == 'about:blank' else 'protected'
            elif method == 'Target.closeTarget':
                router.resource_targets.get(self.durable_namespace, set()).difference_update(close_tree)
            return result
        except BaseException:
            self.preserve = self.preserve or not readonly
            if not readonly:
                self.recovery_guards.update(mutation_pending=True, uncertain=True)
            if not readonly and not router.transport_blocked:
                await router.journal_commit(lambda state: ownership.set_guards(state, self.durable_namespace, uncertain=True, preserve=True))
            raise
        finally:
            if not readonly:
                self.mutations_inflight -= 1

    def safe_disposable(self, target):
        tree = {t for t in self.targets if self.page(t) == target}
        return bool(target in self.targets and self.disposable.get(target) in {'blank', 'marker'}
                    and not tree.intersection(self.mutation_risk) and not self.uploads and not self.downloads
                    and not self.recovery_guards.get('downloads_pending')
                    and self.recovery_guards.get('upload_status') not in {'in_progress', 'uncertain'}
                    and (not self.leases or self.safe_preamble(target))
                    and self.mutations_inflight <= (1 if self.disposable_cleanup == target else 0)
                    and all(self.takeover.is_active(t) for t in tree))

    def safe_preamble(self, target):
        fence = self.preamble_cleanup
        if not fence or fence[0] != target:
            return False
        _, lease, selected, sid = fence
        return bool(self.leases.keys() == {lease} and selected != target
                    and selected in self.targets and self.takeover.is_active(selected)
                    and self.session_targets.get(sid) == selected
                    and any(sid in state for state in self.clients.values())
                    and not any(self.recovery_guards.get(k) for k in ('uncertain', 'mutation_pending', 'busy'))
                    and not self.transport.router.resource_unknown.get(self.durable_namespace, 0))

    async def disconnect(self):
        for ws in list(self.clients):
            await ws.close(code=1012, message=b'capability retired; no replay')

    async def sweep(self, now=None):
        async with self.lock:
            # Actual quiet time confirms event settling; test/idle clock overrides
            # must never manufacture completion. Start a new idle deadline.
            for target, guard in tuple(self.uploads.items()):
                if guard['state'] == 'settling' and time.monotonic() - guard['finished_at'] >= self.upload_quiet_seconds:
                    router = self.transport.router
                    if router.journal is not None:
                        await router.journal_commit(lambda state: ownership.set_guards(state, self.durable_namespace, upload_status='in_progress' if len(self.uploads) > 1 else 'complete'))
                    self.uploads.pop(target)
                    self.last_activity = time.monotonic()
                    return
            if self.leases or self.transport.pending or self.downloads or self.uploads:
                return
            if (time.monotonic() if now is None else now) - self.last_activity < self.idle_seconds:
                return
            try:
                for target in tuple(self.targets):
                    # Descendants are closed with their owning page, never via a
                    # separate iframe close that could mask page uncertainty.
                    if target not in self.page_targets:
                        continue
                    if target in (getattr(self, 'external_app_targets', set()) | getattr(self, 'external_descendants', set())):
                        continue  # Runtime authority permits explicit child close only.
                    disposable_only = self.preserve or any(self.recovery_guards.get(k) for k in ('uncertain', 'mutation_pending', 'busy'))
                    if disposable_only and not self.safe_disposable(target):
                        continue
                    if any(self.page(t) == target and not self.takeover.is_active(t)
                           for t in self.takeover.snapshot() if t != target):
                        continue
                    async def close(target=target):
                        if disposable_only:
                            info = (await self.command('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
                            expected = 'about:blank' if self.disposable.get(target) == 'blank' else (self.transport.router.live_endpoint or {}).get('marker_url')
                            if (not expected or info.get('url') != expected or info.get('browserContextId') != self.context_id
                                    or not self.safe_disposable(target)):
                                raise PermissionError('disposable target changed; preserve')
                        self.disposable_cleanup = target if disposable_only else None
                        try:
                            result = await self.command('Target.closeTarget', {'targetId': target})
                            if result.get('success') is not True:
                                raise ConnectionError('close not confirmed; preserve')
                        finally:
                            self.disposable_cleanup = None
                    if await self.takeover.close_if_active(target, close):
                        tree = {t for t in self.targets if self.page(t) == target}
                        for t in tree:
                            if t != target:
                                await self.takeover.release(t)
                        self.targets.difference_update(tree)
            except asyncio.CancelledError:
                self.preserve = True
                raise
            except Exception:
                self.preserve = True
                return
            if not self.targets:
                self.epoch += 1
                await self.disconnect()
                self.session_targets.clear()
                self.namespace = None
                self.capability = None

    async def event(self, data):
        method = data.get('method', '')
        params = data.get('params', {})
        info = params.get('targetInfo', {})
        sid = data.get('sessionId')
        opener = info.get('openerId')
        if opener in self.takeover.snapshot():
            if await self.persist_descendant(info, opener, 'opener') is not False:
                self.own(info['targetId'], opener, page=info.get('type') == 'page')
        # Resolve provenance before publishing, including flattened OOPIFs.
        parent = self.provenance_sessions.get(sid) if sid else None
        if method == 'Target.attachedToTarget' and parent:
            if await self.persist_descendant(info, parent, 'attached') is False:
                return
            self.own(info['targetId'], parent, page=info.get('type') == 'page')
            self.provenance_sessions[params['sessionId']] = info['targetId']
        tid = info.get('targetId', params.get('targetId', parent))
        self.observe_upload(method, params, parent)
        guards_changed = False
        if method in {'Page.downloadWillBegin', 'Browser.downloadWillBegin'} and params.get('guid') and (parent or method == 'Browser.downloadWillBegin'):
            # Unscoped Browser download provenance is ambiguous: conservatively
            # guard every scope, never publish global download data to clients.
            self.downloads.add(params['guid'])
            guards_changed = True
        if method in {'Page.downloadProgress', 'Browser.downloadProgress'} and params.get('guid') in self.downloads and params.get('state') in {'completed', 'canceled'}:
            self.downloads.discard(params['guid'])
            self.last_activity = time.monotonic()
            guards_changed = True
        if guards_changed and self.transport.router.journal is not None:
            await self.transport.router.journal_commit(lambda state: ownership.set_guards(state, self.durable_namespace, downloads_pending=bool(self.downloads)))
        if not self.leases:
            return
        if tid and (not self.takeover.is_active(tid) or not self.takeover.is_active(self.page(tid))):
            return
        for ws, state in tuple(self.clients.items()):
            reverse = {up: local for local, up in state.items()}
            if sid and sid not in reverse:
                continue
            mapped = self.session_targets.get(reverse.get(sid))
            if mapped and (not self.takeover.is_active(mapped) or not self.takeover.is_active(self.page(mapped))):
                continue
            if self.vault_target is not None and (mapped != self.vault_target if sid else tid != self.vault_target):
                continue
            if method.startswith('Target.') and tid not in self.targets:
                continue
            if not sid and not method.startswith('Target.'):
                continue
            event = dict(data)
            event['params'] = dict(params)
            if sid:
                event['sessionId'] = reverse[sid]
            if method == 'Target.attachedToTarget':
                local = secrets.token_urlsafe(16)
                state[local] = params['sessionId']
                self.session_targets[local] = tid
                self.provenance_sessions[params['sessionId']] = tid
                event['params']['sessionId'] = local
            if method == 'Target.detachedFromTarget':
                child = reverse.get(params.get('sessionId'))
                if not child:
                    continue
                event['params']['sessionId'] = child
                state.pop(child, None)
                self.session_targets.pop(child, None)
            if not ws.closed:
                await ws.send_json(event)

    def observe_upload(self, method, params, parent):
        if not parent:
            return
        guard = self.uploads.get(self.page(parent))
        if guard is None or guard['state'] == 'preparing':
            return
        key = params.get('requestId')
        if method == 'Network.requestWillBeSent' and key:
            request = params.get('request', {})
            if request.get('method', '').upper() not in {'POST', 'PUT', 'PATCH'}:
                return
            guard['pending'].add(key)
            guard['state'] = 'transferring'
            headers = {k.lower(): str(v).lower() for k, v in request.get('headers', {}).items()}
            whole = request.get('hasPostData') and headers.get('content-type', '').startswith('multipart/form-data')
            guard['requests'] = guard.get('requests', 0) + 1
            guard['ambiguous'] = guard.get('ambiguous', False) or guard['requests'] > 1 or any(
                'range' in k or 'upload' in k or 'resumable' in k for k in headers)
            guard['whole'] = bool(whole) and not guard['ambiguous']
        elif key in guard['pending'] and method == 'Network.responseReceived':
            response = params.get('response', {})
            status = response.get('status', 0)
            # Location/session/range metadata describes an initial handshake or
            # chunk, not a final uploaded object. Retain no header values.
            if any(k.lower() == 'location' or 'range' in k.lower() or 'upload' in k.lower() or 'resumable' in k.lower()
                   for k in response.get('headers', {})):
                guard['ambiguous'] = True
                guard['whole'] = False
            guard['success'] = status in {200, 201, 204}
        elif key in guard['pending'] and method == 'Network.loadingFinished':
            guard['pending'].discard(key)
            if not guard['pending'] and guard.get('whole') and guard.get('success'):
                guard['state'] = 'settling'
                guard['finished_at'] = time.monotonic()
            else:
                guard['state'] = 'uncertain'
        elif key in guard['pending'] and method == 'Network.loadingFailed':
            guard['pending'].discard(key)
            guard['state'] = 'uncertain'

    async def grant_external_descendant(self, info, parent, proof):
        """Fresh browser provenance grants runtime routing, not creation ownership."""
        router = self.transport.router
        target = info.get('targetId')
        external = getattr(self, 'external_app_targets', set()) | getattr(self, 'external_descendants', set())
        epoch, leases = self.epoch, dict(self.leases)
        if (not leases or parent not in external or parent not in self.targets
                or not self.takeover.is_active(parent) or not self.takeover.is_active(self.page(parent))
                or not target or target == parent or info.get('browserContextId') != self.context_id
                or (proof == 'opener' and info.get('openerId') != parent)
                or (info.get('type') == 'page' and info.get('openerId') != parent)):
            return False
        if router.journal is not None:
            await router.check_generation()
        if (router.transport_blocked or self.transport.closing or epoch != self.epoch
                or leases != self.leases or not self.leases or parent not in self.targets
                or not self.takeover.is_active(parent) or not self.takeover.is_active(self.page(parent))
                or any(target in s.takeover.snapshot() for s in (*router.scopes.values(), *router.retired.values()) if s is not self)):
            return False
        if target in self.takeover.snapshot() and target not in getattr(self, 'external_descendants', set()):
            return False
        self.own(target, parent, page=info.get('type') == 'page')
        self.external_descendants = getattr(self, 'external_descendants', set()) | {target}
        return target in self.targets and self.takeover.is_active(target)

    async def persist_descendant(self, info, parent, proof):
        router = self.transport.router
        if parent in (getattr(self, 'external_app_targets', set()) | getattr(self, 'external_descendants', set())):
            return await self.grant_external_descendant(info, parent, proof)
        if router.journal is not None:
            await router.check_generation()
            if info.get('browserContextId') != self.context_id:
                self.preserve = True
                await router.journal_commit(lambda state: ownership.set_guards(state, self.durable_namespace, preserve=True))
                raise PermissionError('unverified descendant context')
            await router.journal_commit(lambda state: ownership.register_descendant(
                state, self.durable_namespace, info['targetId'], parent, proof=proof, page=info.get('type') == 'page'))

    def own(self, target, parent=None, *, page=True):
        self.takeover.register(target, parent_id=parent)
        if page:
            self.page_targets.add(target)
        if parent:
            self.parents[target] = parent
        if self.takeover.snapshot()[target] != 'released':
            self.targets.add(target)

    def page(self, target):
        seen = set()
        while target in self.parents and target not in self.page_targets:
            if target in seen:
                raise PermissionError('invalid lineage')
            seen.add(target)
            target = self.parents[target]
        return target

    async def apply_takeover(self, target, action):
        if action == 'resume' and self.takeover.snapshot().get(target) == 'released':
            raise PermissionError('released target cannot be reclaimed')
        # Iframes/workers have no independent page authority or cleanup route.
        if action != 'resume':
            target = self.page(target)
        tree = {target}
        if action != 'resume':
            while True:
                children = {t for t, parent in self.parents.items() if parent in tree}
                if children <= tree:
                    break
                tree |= children
        self.epoch += 1
        router = self.transport.router
        tasks = []
        if action != 'resume':
            tasks = [asyncio.create_task(getattr(self.takeover, action)(t)) for t in tree]
            # Runtime revocation blocks new sends while durable revocation is
            # committing. No ACK/drain publication precedes the disk boundary.
            await asyncio.sleep(0)
        durable_tree = tree - (getattr(self, 'external_app_targets', set()) | getattr(self, 'external_descendants', set()))
        if router.journal is not None and durable_tree:
            status = {'pause': 'paused', 'release': 'released', 'resume': 'active'}[action]
            await router.journal_commit(lambda state: [ownership.set_takeover(state, self.durable_namespace, t, 'released' if self.takeover.snapshot()[t] == 'released' else status) for t in durable_tree])
        if action == 'resume':
            tasks = [asyncio.create_task(self.takeover.resume(t)) for t in tree]
        await asyncio.sleep(0)
        for state in self.clients.values():
            for sid in tuple(state):
                if self.session_targets.get(sid) in tree:
                    # Tombstones classify preparation only; never restore a map.
                    self.revoked_sessions[sid] = self.session_targets[sid]
                    state.pop(sid, None)
                    self.session_targets.pop(sid, None)
        if self.vault_target in tree:
            self.vault_target = '__taken_over__'
            revoked = self.vault_capability
            self.vault_capability = None
            for ws, capability in tuple(self.client_capabilities.items()):
                if capability == revoked:
                    await ws.close(code=1008, message=b'vault target revoked')
        await asyncio.gather(*tasks)
        if action == 'release':
            self.targets.difference_update(tree)

    async def forward(self, data, state):
        method = data['method']
        if method.startswith('PWA.'):
            raise PermissionError('PWA operations are backend-only')
        params = dict(data.get('params', {}))
        sid = data.get('sessionId')
        nested = params.get('sessionId')
        if not self.leases:
            raise PermissionError('no active admission')
        if method.startswith('Browser.') and method != 'Browser.getVersion':
            raise PermissionError('global browser operation blocked')
        allowed = {'Target.getTargets', 'Target.getTargetInfo', 'Target.attachToTarget',
                   'Target.detachFromTarget', 'Target.createTarget', 'Target.closeTarget',
                   'Target.activateTarget', 'Target.setDiscoverTargets', 'Target.setAutoAttach'}
        if method.startswith('Target.') and method not in allowed:
            raise PermissionError('unapproved target operation')
        if method in {'Page.crash', 'Page.setDownloadBehavior', 'Page.setWebLifecycleState'}:
            raise PermissionError('shared/destructive mutation blocked')
        routes = []
        bindings = {}
        for local in (sid, nested):
            if local:
                if local not in state or local not in self.session_targets:
                    raise PermissionError('unknown session')
                target = self.session_targets[local]
                routes.append(target)
                bindings[local] = (state[local], target)
        if 'targetId' in params:
            routes.append(params['targetId'])
        if any(t not in self.targets or not self.takeover.is_active(t) for t in routes):
            raise PermissionError('target not active owned')
        pages = {self.page(t) for t in routes}
        if len(pages) > 1:
            raise PermissionError('conflicting target routes')
        target = next(iter(pages), None)
        if target and not self.takeover.is_active(target):
            raise PermissionError('page not active')
        vault = self.vault_target
        if vault is not None:
            if any(t != vault for t in routes) or method in {'Target.createTarget', 'Target.closeTarget', 'Target.activateTarget'}:
                raise PermissionError('outside immutable vault target')
        if method == 'Target.setAutoAttach' and not sid:
            raise PermissionError('browser autoattach is unscoped')
        epoch = self.epoch
        leases = dict(self.leases)
        def recheck():
            if epoch != self.epoch or leases != self.leases or not self.leases or self.vault_target != vault:
                raise PermissionError('admission changed; no replay')
            for local, (up, tid) in bindings.items():
                if state.get(local) != up or self.session_targets.get(local) != tid or tid not in self.targets or not self.takeover.is_active(tid):
                    raise PermissionError('session revoked')
            if any(t not in self.targets or not self.takeover.is_active(t) for t in routes):
                raise PermissionError('target revoked')
        async def send(method, params=None, upstream_sid=None):
            async def once():
                recheck()
                try:
                    result = await self.command(method, params, upstream_sid)
                except ResourceLimit:
                    raise
                except BaseException:
                    # A CDP rejection/timeout/cancellation cannot prove that a
                    # mutation had no effect. Never replay or idle-close it.
                    if method not in {'Target.getTargets', 'Target.getTargetInfo', 'Browser.getVersion'}:
                        self.preserve = True
                    raise
                recheck()
                return result
            if target:
                return await self.takeover.dispatch(target, once)
            return await once()
        upstream_sid = state.get(sid) if sid else None
        if nested:
            params['sessionId'] = state[nested]
        if method == 'Target.getTargets':
            result = await send(method)
            # Fresh upstream opener/context metadata, never arbitrary manual adoption.
            for info in result.get('targetInfos', []):
                if info.get('openerId'):
                    await self.grant_external_descendant(info, info['openerId'], 'opener')
                    recheck()
            return {'targetInfos': [t for t in result.get('targetInfos', []) if t['targetId'] in self.targets and self.takeover.is_active(t['targetId']) and self.takeover.is_active(self.page(t['targetId'])) and (vault is None or t['targetId'] == vault)]}
        if method == 'Target.createTarget':
            params.pop('browserContextId', None)
            if self.context_id:
                params['browserContextId'] = self.context_id
            result = await send(method, params)
            self.disposable[result['targetId']] = 'blank' if params.get('url') == 'about:blank' else 'protected'
            self.own(result['targetId'])
            return result
        if method == 'Target.attachToTarget':
            if not params.get('flatten') or not target:
                raise PermissionError('exact flattened target required')
            result = await send(method, params)
            local = secrets.token_urlsafe(16)
            state[local] = result['sessionId']
            self.session_targets[local] = params['targetId']
            self.provenance_sessions[result['sessionId']] = params['targetId']
            return {'sessionId': local}
        if method == 'Target.closeTarget':
            if target in getattr(self, 'external_app_targets', set()):
                raise PermissionError('external app has no close ownership')
            if target in self.uploads:
                raise PermissionError('upload guard active; explicit resolution required')
            if params.get('targetId') not in self.page_targets:
                raise PermissionError('close requires owned page')
            if any(self.page(t) == target and not self.takeover.is_active(t)
                   for t in self.takeover.snapshot() if t != target):
                raise PermissionError('page has preserved descendant')
            async def close_once():
                recheck()
                result = await self.command(method, params, upstream_sid)
                if result.get('success') is not True:
                    raise ConnectionError('close unconfirmed; no replay')
            try:
                closed = await self.takeover.close_if_active(target, close_once)
            except BaseException:
                self.preserve = True
                raise
            if not closed:
                raise PermissionError('close revoked')
            tree = {t for t in self.targets if self.page(t) == target}
            for t in tree:
                if t != target:
                    await self.takeover.release(t)
            self.targets.difference_update(tree)
            for client_state in self.clients.values():
                for local in tuple(client_state):
                    if self.session_targets.get(local) in tree:
                        client_state.pop(local, None)
                        self.session_targets.pop(local, None)
            return {'success': True}
        if method == 'Target.getTargetInfo' and not params.get('targetId'):
            raise PermissionError('ambiguous target')
        if not target and method not in {'Browser.getVersion', 'Target.setDiscoverTargets'}:
            raise PermissionError('unscoped operation')
        if method == 'Target.setDiscoverTargets':
            params['filter'] = [{'type': 'page'}, {'exclude': True}]
        if method in {'Network.disable', 'Page.disable'} and target in self.uploads:
            raise PermissionError('upload observation must remain enabled')
        if method == 'DOM.setFileInputFiles' and params.get('files'):
            if not target:
                raise PermissionError('file selection requires owned page')
            if target in self.uploads:
                raise PermissionError('unresolved upload; selection not replayed')
            self.uploads[target] = {'state': 'preparing', 'pending': set()}
            router = self.transport.router
            if router.journal is not None:
                await router.journal_commit(lambda state: ownership.set_guards(state, self.durable_namespace, upload_status='in_progress'))
            try:
                await send('Network.enable', {}, upstream_sid)
                await send('Page.enable', {}, upstream_sid)
                self.uploads[target]['state'] = 'awaiting_traffic'
                return await send(method, params, upstream_sid)
            except BaseException:
                self.uploads[target]['state'] = 'uncertain'
                raise
        if method.startswith('Input.'):
            return await dispatch_input(self, data, state, mode=self.input_mode, send=send)
        policy = getattr(self.transport.router, 'app_router', None)
        if method == 'Page.navigate' and policy is not None and sid and self.session_targets.get(sid) == target:
            return await policy.navigate(self, target, params, upstream_sid, send, recheck)
        return await send(method, params, upstream_sid)


class BorrowedScope(SessionScope):
    """Runtime-only authority over one explicitly approved existing page.

    Membership in targets is routing authority, never creation provenance.
    No cleanup, descendant adoption or ownership-journal writes are permitted.
    """
    def __init__(self, transport, namespace, target, **kwargs):
        super().__init__(transport, namespace, **kwargs)
        self.borrowed_target_id = target
        self.own(target)

    async def command(self, method, params=None, session_id=None):
        if method in {'Target.createTarget', 'Target.closeTarget'}:
            raise PermissionError('borrowed page cannot be created or closed')
        return await self.transport.command(method, params, session_id)

    async def forward(self, data, state):
        if data['method'] in {'Target.createTarget', 'Target.closeTarget', 'Target.setAutoAttach', 'DOM.setFileInputFiles', 'Page.close'}:
            raise PermissionError('borrowed scope does not grant resource ownership')
        return await super().forward(data, state)

    async def event(self, data):
        params = data.get('params', {})
        info = params.get('targetInfo', {})
        if info.get('targetId') not in {None, self.borrowed_target_id} or data.get('method') == 'Target.attachedToTarget':
            return
        # Publish only exact mapped-page events, without journal/descendant work.
        for ws, state in tuple(self.clients.items()):
            reverse = {up: local for local, up in state.items()}
            sid = data.get('sessionId')
            if not self.leases or (sid and sid not in reverse):
                continue
            if not self.takeover.is_active(self.borrowed_target_id):
                continue
            if not sid and (not data.get('method', '').startswith('Target.') or info.get('targetId', params.get('targetId')) != self.borrowed_target_id):
                continue
            event = dict(data)
            if sid:
                event['sessionId'] = reverse[sid]
            if not ws.closed:
                await ws.send_json(event)

    async def sweep(self, now=None):
        return  # User-owned target: never idle close or silently retire routing.

    async def apply_takeover(self, target, action):
        if action != 'release' or target != self.borrowed_target_id:
            raise PermissionError('borrowed authority is release-only')
        self.epoch += 1
        await self.takeover.release(target)
        self.targets.clear()
        self.session_targets.clear()
        self.vault_target = '__released__'
        self.vault_capability = None
        for state in self.clients.values():
            state.clear()
        await self.disconnect()


class SessionBroker:
    """Capability routing, never a mutable 'current task' or an environment switch.

    Legacy Broker remains the audited transport/profile identity implementation.
    Only its private bootstrap lease may own the profile marker/window. Each
    task owns independent targets, session maps, leases and preservation guards.
    Root discovery is deliberately denied outside an exact, exclusive vault
    binding: the native supervisor resolves that fixed root URL without task ID.
    """
    def __init__(self, connector, *, control_token, idle_seconds=60, ws_connector=None, marker_timeout=5, journal=None, max_owned_per_scope=16, max_owned_per_generation=64, app_router=None):
        if min(max_owned_per_scope, max_owned_per_generation) < 1:
            raise ValueError('resource caps must be positive')
        self.app_router = app_router  # Opt-in, inert until exact live capability proof.
        self.app_launcher = None
        self.max_owned_per_scope = max_owned_per_scope
        self.max_owned_per_generation = max_owned_per_generation
        self.resource_targets = {}
        self.resource_unknown = {}
        self.journal = journal
        self.journal_state = None
        self.journal_lock = asyncio.Lock()
        self.journal_loaded = False
        self.live_endpoint = None
        self.connector = connector
        self.control_token = control_token
        self.idle_seconds = idle_seconds
        self.transport = RoutingTransport(connector, control_token=control_token,
                                idle_seconds=idle_seconds, ws_connector=ws_connector,
                                marker_timeout=marker_timeout)
        self.transport.router = self
        self.transport_blocked = False
        self.blocked_error = None
        self.failure_stage = None
        self.scopes = {}
        self.retired = {}
        self.draining = False
        self.drain_id = None  # Runtime-only proof of a completed quiet drain.
        self.soft_stop = False
        self.harness_registry = {}  # Runtime-only exact generation capabilities.
        self.harness_pending = {}  # Unknown admission outcomes block quiet stop.
        self.borrowed_namespaces = set()  # Runtime tombstones: no creation fallback.
        self.leases = {}
        self.lock = asyncio.Lock()
        self.janitor = None

    def app(self):
        app = web.Application()
        app.router.add_post('/control/acquire', self.acquire)
        app.router.add_post('/control/release', self.release)
        app.router.add_post('/control/detach', self.detach)
        app.router.add_post('/control/activate', self.activate)
        app.router.add_post('/control/verify-driver', self.verify_driver)
        app.router.add_post('/control/prepare-harness', self.prepare_harness)
        app.router.add_post('/control/begin-harness', self.begin_harness)
        app.router.add_post('/control/register-harness', self.register_harness)
        app.router.add_post('/control/driver-capacity', self.driver_capacity)
        app.router.add_post('/control/cleanup-disposable', self.cleanup_disposable)
        app.router.add_post('/control/cleanup-preamble', self.cleanup_preamble)
        app.router.add_post('/control/app-route', self.app_route)
        app.router.add_post('/control/list-existing', self.list_existing)
        app.router.add_post('/control/borrow-existing', self.borrow_existing)
        app.router.add_post('/control/takeover', self.takeover_control)
        app.router.add_post('/control/takeover-status', self.takeover_status)
        app.router.add_post('/control/input-mode', self.configure_input)
        app.router.add_post('/control/upload-status', self.upload_status)
        app.router.add_post('/control/upload-resolve', self.upload_resolve)
        app.router.add_post('/control/reconcile', self.reconcile)
        app.router.add_post('/control/abort-bootstrap', self.abort_bootstrap)
        app.router.add_post('/control/bind-vault', self.bind_vault)
        app.router.add_post('/control/preserve', self.mark_preserve)
        app.router.add_get('/json/version', self.discovery)
        app.router.add_get('/sessions/{capability}/json/version', self.discovery)
        app.router.add_get('/devtools/browser/{capability}', self.socket)
        app.router.add_get('/health', self.health)
        app.on_startup.append(self.start_janitor)
        # Close capability sockets while their receive handlers still run.
        # on_cleanup is too late: aiohttp has already canceled WS handlers,
        # leaving the installed CDP client's reader parked on an orphan socket.
        # Its dedicated-target finalizer then sends a close with no reply path.
        app.on_shutdown.append(self.cleanup_transports)
        app.on_cleanup.append(self.cleanup_transports)
        return app

    async def cleanup_transports(self, app):
        if not self.soft_stop:
            return await self.shutdown(app)
        # Graceful lifecycle exit is transport-only. No sweep, target/context
        # destruction, ownership commit, or uncertainty/resource clearing.
        if self.janitor:
            self.janitor.cancel()
            await asyncio.gather(self.janitor, return_exceptions=True)
        for scope in (*tuple(self.scopes.values()), *tuple(self.retired.values())):
            await scope.disconnect()
        await self.transport.disconnect()

    def harness_scope(self, request, data):
        scope, kind = self.leases.get(data.get('lease'), (None, None))
        if (self.draining or scope is None or kind != 'browser'
                or data.get('name') != plugin_identity.daemon_name(scope.durable_namespace)
                or data.get('endpoint') != f'ws://{request.host}/devtools/browser/{scope.capability}'):
            raise web.HTTPForbidden()
        return scope

    async def load_harness_inventory(self):
        if getattr(self, 'harness_inventory_failed', False):
            raise ownership.JournalError('harness inventory blocked')
        if self.journal is None:
            return
        if not hasattr(self, 'harness_inventory'):
            home = getattr(self, 'profile_home', self.journal.path.parent.parent)
            self.harness_inventory_journal = harness_cleanup.InventoryJournal(
                self.journal.path.with_name('harness-inventory.json'), home)
            self.harness_inventory = await asyncio.to_thread(self.harness_inventory_journal.load)
            for name, pending in self.harness_inventory['pending'].items():
                self.harness_pending.setdefault(name, dict(pending))

    async def commit_harness_inventory(self, change):
        if self.journal is None:
            return
        await self.load_harness_inventory()
        candidate = json.loads(json.dumps(self.harness_inventory))
        change(candidate)
        writer = asyncio.create_task(asyncio.to_thread(self.harness_inventory_journal.save, candidate))
        try:
            await asyncio.shield(writer)
        except asyncio.CancelledError:
            self.harness_inventory_failed = True
            while not writer.done():
                try:
                    await asyncio.shield(writer)
                except asyncio.CancelledError:
                    continue
            writer.result()
            raise
        except Exception:
            self.harness_inventory_failed = True
            raise
        self.harness_inventory = candidate

    async def prepare_harness(self, request):
        """Setup-only exact-generation retirement before any child reservation."""
        self.authorize(request)
        data = await request.json()
        async with self.lock:
            scope = self.harness_scope(request, data)
            try:
                await self.load_harness_inventory()
                name = data['name']
                record = self.harness_registry.get(name)
                saved = getattr(self, 'harness_inventory', {}).get('records', {}).get(name)
                if saved is not None:
                    trusted = await asyncio.to_thread(self.journal.load)
                    ownership.validate(trusted)
                    if (not trusted.get('browser') or scope.durable_namespace not in trusted['scopes']
                            or saved['namespace_hash'] != harness_cleanup.namespace_hash(scope.durable_namespace)):
                        raise PermissionError('broker namespace unproven')
                    meta = trusted['scopes'][scope.durable_namespace]
                    guards = meta['guards']
                    if (meta.get('unknown_creates', 0) or any(guards[k] for k in ('mutation_pending', 'uncertain', 'downloads_pending'))
                            or guards['upload_status'] in ('in_progress', 'uncertain')):
                        raise PermissionError('broker activity unresolved')
                    verified = await asyncio.to_thread(harness_cleanup.revive, name, saved, scope.durable_namespace,
                        ipc=getattr(self, 'harness_ipc', None))
                    if record is None:
                        record = verified
                if record is None:
                    if name in self.harness_pending:
                        raise PermissionError('unknown harness preparation')
                    return web.json_response({'prepared': True, 'retired': False})
                if (set(self.leases) != {data['lease']} or set(scope.leases) != {data['lease']}
                        or self.transport.pending or scope.mutations_inflight or scope.downloads or scope.uploads
                        or any(scope.recovery_guards.get(k) for k in ('uncertain', 'mutation_pending', 'downloads_pending'))
                        or scope.recovery_guards.get('upload_status') in ('in_progress', 'uncertain')):
                    raise PermissionError('other activity prevents retirement')
                ipc = getattr(self, 'harness_ipc', None)
                if ipc is None:
                    from browser_harness import _ipc as ipc
                retired = harness_cleanup.exited(record)
                if name in self.harness_pending:
                    # Only the unchanged live registered generation proves that
                    # failed preparation did not create a different child.
                    if retired:
                        raise PermissionError('unknown preparation may have created another generation')
                    if saved is not None:
                        await asyncio.to_thread(harness_cleanup.revive, name, saved, scope.durable_namespace, ipc=ipc)
                    else:
                        process = harness_cleanup.process_identity(record['pid'])
                        if any(process[k] != record[k] for k in process) or harness_cleanup.socket_identity(ipc.sock_addr(name)) != record['socket']:
                            raise PermissionError('prior generation changed')
                if not retired:
                    status = await asyncio.to_thread(harness_cleanup.request, ipc, name, {'meta': 'connection_status'})
                    disconnected = isinstance(status, dict) and status.get('error') in {'cdp_disconnected', 'not_attached'}
                    if not disconnected and record.get('endpoint') == data['endpoint']:
                        if name in self.harness_pending:
                            raise PermissionError('unknown preparation outcome')
                        return web.json_response({'prepared': True, 'retired': False})
                    if not disconnected:
                        await scope.disconnect()
                        deadline = time.monotonic() + 2
                        while time.monotonic() < deadline:
                            status = await asyncio.to_thread(harness_cleanup.request, ipc, name, {'meta': 'connection_status'})
                            if isinstance(status, dict) and status.get('error') in {'cdp_disconnected', 'not_attached'}:
                                disconnected = True
                                break
                            await asyncio.sleep(.02)
                    if not disconnected:
                        raise PermissionError('old transport disconnect unproven')
                    # Exact IPC retirement independently revalidates process/socket.
                    await asyncio.to_thread(harness_cleanup.retire, record, ipc=ipc, timeout=5)
                await self.commit_harness_inventory(lambda state: (state['records'].pop(name, None), state['pending'].pop(name, None)))
                self.harness_registry.pop(name, None)
                self.harness_pending.pop(name, None)
                return web.json_response({'prepared': True, 'retired': True})
            except Exception:
                return web.json_response({'error': 'stale_driver'}, status=409)

    async def begin_harness(self, request):
        self.authorize(request)
        data = await request.json()
        async with self.lock:
            scope = self.harness_scope(request, data)
            name = data['name']
            try:
                await self.load_harness_inventory()
            except Exception:
                return web.json_response({'error': 'harness_inventory'}, status=409)
            if name in self.harness_pending:
                return web.json_response({'error': 'harness_unverified'}, status=409)
            try:
                await self.commit_harness_inventory(lambda state: state['pending'].update(
                    {name: {'namespace_hash': harness_cleanup.namespace_hash(scope.durable_namespace)}}))
            except Exception:
                return web.json_response({'error': 'harness_inventory'}, status=409)
            attempt = secrets.token_urlsafe(24)
            self.harness_pending[name] = {'attempt': attempt, 'namespace': scope.durable_namespace,
                'endpoint': data['endpoint'], 'lease': data['lease']}
        return web.json_response({'attempt': attempt})

    async def register_harness(self, request):
        self.authorize(request)
        data = await request.json()
        async with self.lock:
            scope = self.harness_scope(request, data)
            pending = self.harness_pending.get(data['name'])
            if (pending is None or pending['attempt'] != data.get('attempt')
                    or pending['lease'] != data['lease'] or pending['endpoint'] != data['endpoint']):
                raise web.HTTPForbidden()
            verification = await self.verify_driver(request)
            if verification.status != 200 or json.loads(verification.body).get('verified') is not True:
                raise web.HTTPForbidden()
            try:
                record = await asyncio.to_thread(harness_cleanup.capture, data['name'], data['endpoint'],
                    data.get('target_id'), data.get('session_id'), ipc=getattr(self, 'harness_ipc', None))
            except Exception:
                raise web.HTTPForbidden() from None
            if record != data.get('record'):
                raise web.HTTPForbidden()
            # Awaited IPC may race target revocation; lease/selection must still prove.
            self.harness_scope(request, data)
            verification = await self.verify_driver(request)
            if verification.status != 200 or json.loads(verification.body).get('verified') is not True:
                raise web.HTTPForbidden()
            prior = self.harness_registry.get(data['name'])
            if prior is not None and any(prior[k] != record[k] for k in ('pid', 'process_ctime', 'process_uid', 'socket')):
                if not harness_cleanup.exited(prior):
                    return web.json_response({'error': 'harness_generation_conflict'}, status=409)
            durable = harness_cleanup.durable_record(record, scope.durable_namespace)
            await self.commit_harness_inventory(lambda state: (state['records'].update({data['name']: durable}),
                state['pending'].pop(data['name'], None)))
            self.harness_registry[data['name']] = record
            self.harness_pending.pop(data['name'])
        return web.json_response({'registered': True})

    async def cleanup_harnesses(self, *, timeout=5):
        # Caller holds the drain fence and has disconnected downstream first.
        # Keep authority on every failure, including timeout and cancellation.
        deadline = time.monotonic() + max(0, timeout)
        blocked = []
        try:
            await self.load_harness_inventory()
            if self.harness_pending:
                return ['harness_unverified']
            if self.journal is not None and self.harness_inventory['records']:
                trusted = await asyncio.to_thread(self.journal.load)
                ownership.validate(trusted)
                if not trusted.get('browser'):
                    raise PermissionError('broker journal unproven')
                if any(meta.get('unknown_creates', 0)
                       or any(meta['guards'][k] for k in ('busy', 'mutation_pending', 'uncertain', 'downloads_pending'))
                       or meta['guards']['upload_status'] in ('in_progress', 'uncertain')
                       for meta in trusted['scopes'].values()):
                    raise PermissionError('broker journal activity unresolved')
                for name, saved in self.harness_inventory['records'].items():
                    matches = [n for n in trusted['scopes'] if plugin_identity.daemon_name(n) == name
                        and harness_cleanup.namespace_hash(n) == saved['namespace_hash']]
                    if len(matches) != 1:
                        raise PermissionError('broker namespace unproven')
                    meta = trusted['scopes'][matches[0]]
                    guards = meta['guards']
                    if (meta.get('unknown_creates', 0) or any(guards[k] for k in ('busy', 'mutation_pending', 'uncertain', 'downloads_pending'))
                            or guards['upload_status'] in ('in_progress', 'uncertain')):
                        raise PermissionError('broker journal activity unresolved')
                    if name not in self.harness_registry:
                        revived = await asyncio.to_thread(harness_cleanup.revive, name, saved, matches[0],
                            ipc=getattr(self, 'harness_ipc', None))
                        if not harness_cleanup.exited(revived):
                            ipc = getattr(self, 'harness_ipc', None)
                            if ipc is None:
                                from browser_harness import _ipc as ipc
                            status = await asyncio.to_thread(harness_cleanup.request, ipc, name, {'meta': 'connection_status'})
                            if not isinstance(status, dict) or status.get('error') not in {'cdp_disconnected', 'not_attached'}:
                                raise PermissionError('original transport disconnect unproven')
                        self.harness_registry[name] = revived
        except Exception:
            return ['harness_inventory']
        for name, record in tuple(self.harness_registry.items()):
            try:
                await asyncio.to_thread(harness_cleanup.retire, record,
                    timeout=max(0, deadline - time.monotonic()), ipc=getattr(self, 'harness_ipc', None))
            except Exception:
                blocked.append('harness_cleanup')
            else:
                try:
                    await self.commit_harness_inventory(lambda state: state['records'].pop(name, None))
                except Exception:
                    blocked.append('harness_inventory')
                    continue
                if self.harness_registry.get(name) is record:
                    self.harness_registry.pop(name)
        if self.harness_pending:
            blocked.append('harness_unverified')
        return sorted(set(blocked))

    async def activate(self, request):
        self.authorize(request)
        async with self.lock:
            if self.draining:
                if self.drain_blockers():
                    return web.json_response({'error': 'drain_pending'}, status=409)
                for scope in self.scopes.values():
                    scope.capability = secrets.token_urlsafe(32)
                self.draining = False
        return web.json_response({'status': 'active'})

    def drain_blockers(self):
        scopes = (*self.scopes.values(), *self.retired.values())
        blockers = []
        if self.leases or any(s.leases for s in scopes):
            blockers.append('active_calls')
        if (self.transport.pending or self.journal_lock.locked()
                or any(s.mutations_inflight or s.lock.locked() or s.recovery_guards.get('busy')
                       or s.recovery_guards.get('mutation_pending') for s in scopes)):
            blockers.append('pending_operations')
        if any(s.recovery_guards.get('uncertain') for s in scopes):
            blockers.append('uncertainty')
        if any(s.downloads or s.uploads or s.recovery_guards.get('downloads_pending')
               or s.recovery_guards.get('upload_status') in {'in_progress', 'uncertain'} for s in scopes):
            blockers.append('transfers')
        return blockers

    async def detach(self, request):
        self.authorize(request)
        data = await request.json()
        timeout = data.get('timeout', 5)
        if type(timeout) not in {int, float} or not 0 <= timeout <= 10:
            raise web.HTTPBadRequest()
        self.drain_id = None
        self.draining = True  # No new admission, but admitted work retains authority.
        deadline = time.monotonic() + timeout
        while True:
            if not self.lock.locked():
                async with self.lock:
                    try:
                        await self.load_harness_inventory()
                    except Exception:
                        return web.json_response({'status': 'blocked', 'blockers': ['harness_inventory']})
                    blockers = self.drain_blockers()
                    if not blockers:
                        for scope in (*self.scopes.values(), *self.retired.values()):
                            scope.epoch += 1
                            scope.capability = scope.vault_capability = None
                            scope.vault_target = None
                            scope.provenance_sessions.clear()
                            scope.session_targets.clear()
                        # Close only quiescent downstream capability sockets.
                        # Never wait indefinitely on an installed client handshake.
                        sockets = [ws for scope in (*self.scopes.values(), *self.retired.values())
                                   for ws in tuple(scope.clients)]
                        try:
                            await asyncio.wait_for(asyncio.gather(*(ws.close(code=1012, message=b'capability retired; no replay')
                                                                  for ws in sockets)), .25)
                        except (TimeoutError, OSError):
                            return web.json_response({'status': 'blocked', 'blockers': ['clients']})
                        # Keep the transport and metadata; never close Chrome or
                        # erase ownership/transfer uncertainty to claim success.
                        blockers = await self.cleanup_harnesses(timeout=5)
                        if blockers:
                            return web.json_response({'status': 'blocked', 'blockers': blockers})
                        self.drain_id = secrets.token_urlsafe(32)
                        return web.json_response({'status': 'detached', 'blockers': [],
                            'drain_id': self.drain_id,
                            'stop_required': getattr(self, 'lifecycle_stop_supported', False)})
            else:
                blockers = ['pending_operations']
            if time.monotonic() >= deadline:
                return web.json_response({'status': 'blocked', 'blockers': blockers})
            await asyncio.sleep(min(.05, max(0, deadline - time.monotonic())))

    def authorize(self, request):
        if request.headers.get('Authorization') != 'Bearer ' + self.control_token:
            raise web.HTTPUnauthorized()

    @staticmethod
    def exact_origin(url):
        from urllib.parse import urlsplit
        try:
            p = urlsplit(url)
            if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password:
                return None
            port = p.port or (443 if p.scheme == 'https' else 80)
            return (p.scheme, p.hostname, port)
        except (TypeError, ValueError):
            return None

    @classmethod
    def valid_control_origin(cls, origin):
        from urllib.parse import urlsplit
        if not cls.exact_origin(origin):
            return False
        p = urlsplit(origin)
        return p.path in {'', '/'} and not p.query and not p.fragment

    async def list_existing(self, request):
        self.authorize(request)
        data = await request.json()
        origin = data.get('expected_origin')
        if not self.valid_control_origin(origin):
            raise web.HTTPBadRequest()
        async with self.lock:
            await self.ensure_transport(data.get('namespace', '__existing_discovery__'))
            if self.transport_blocked or not self.transport.context_id:
                raise web.HTTPConflict(text='profile context unproven')
            infos = (await self.transport.command('Target.getTargets')).get('targetInfos', [])
            # Exact requested origin only; never return titles or private URLs.
            targets = [{'target_id': t['targetId'], 'context_id': self.transport.context_id}
                for t in infos if t.get('type') == 'page'
                and t.get('browserContextId') == self.transport.context_id
                and self.exact_origin(t.get('url')) == self.exact_origin(origin)]
            return web.json_response({'targets': targets})

    async def borrow_existing(self, request):
        self.authorize(request)
        data = await request.json()
        if (any(not isinstance(data.get(k), str) or not data[k] for k in ('namespace', 'target_id', 'context_id', 'expected_origin'))
                or len(data['namespace']) > 1024 or not self.valid_control_origin(data['expected_origin'])):
            raise web.HTTPBadRequest()
        async with self.lock:
            if data['namespace'] in self.scopes or data['namespace'] in self.retired or self.leases:
                raise web.HTTPConflict(text='namespace unavailable')
            await self.ensure_transport(data['namespace'])
            if self.transport_blocked or data['context_id'] != self.transport.context_id:
                raise web.HTTPForbidden()
            if self.journal is not None:
                await self.check_generation()
            info = (await self.transport.command('Target.getTargetInfo', {'targetId': data['target_id']})).get('targetInfo', {})
            if (info.get('targetId') != data['target_id'] or info.get('type') != 'page'
                    or info.get('browserContextId') != data['context_id']
                    or self.exact_origin(info.get('url')) != self.exact_origin(data['expected_origin'])
                    or any(data['target_id'] in s.takeover.snapshot() for s in (*self.scopes.values(), *self.retired.values()))
                    or data['target_id'] in self.transport.targets):
                raise web.HTTPForbidden()
            scope = BorrowedScope(self.transport, data['namespace'], data['target_id'],
                control_token=self.control_token, idle_seconds=self.idle_seconds)
            self.scopes[data['namespace']] = scope
            self.borrowed_namespaces.add(data['namespace'])
        return web.json_response({'borrowed': True, 'target_id': data['target_id'], 'closed': False})

    def check_resource_budget(self, namespace):
        counts = {n: len(ids) + self.resource_unknown.get(n, 0) for n, ids in self.resource_targets.items()}
        for n, count in self.resource_unknown.items():
            counts.setdefault(n, count)
        if counts.get(namespace, 0) >= self.max_owned_per_scope or sum(counts.values()) >= self.max_owned_per_generation:
            raise ResourceLimit('retained target budget exhausted; explicit resolution required')

    def reserve_create(self, namespace):
        self.check_resource_budget(namespace)
        self.resource_unknown[namespace] = self.resource_unknown.get(namespace, 0) + 1

    def confirm_create(self, namespace, target):
        self.resource_unknown[namespace] -= 1
        self.resource_targets.setdefault(namespace, set()).add(target)

    async def upload_status(self, request):
        self.authorize(request)
        data = await request.json()
        scope = self.scopes.get(data.get('namespace')) if isinstance(data.get('namespace'), str) else None
        if scope is None:
            raise web.HTTPNotFound()
        return web.json_response({'uploads': {target: {'state': guard['state'], 'pending': len(guard['pending'])}
            for target, guard in scope.uploads.items()}})

    async def upload_resolve(self, request):
        self.authorize(request)
        data = await request.json()
        if not isinstance(data.get('namespace'), str) or not isinstance(data.get('target_id'), str) or data.get('outcome') not in {'completed', 'canceled'}:
            raise web.HTTPBadRequest()
        async with self.lock:
            scope = self.scopes.get(data['namespace'])
            if scope is None or data['target_id'] not in scope.uploads:
                raise web.HTTPNotFound()
            guard = scope.uploads[data['target_id']]
            disconnected = self.transport.upstream is None or self.transport.upstream.closed or not self.transport.reader or self.transport.reader.done()
            if scope.leases or (guard['pending'] and not disconnected) or guard['state'] == 'preparing':
                raise web.HTTPConflict(text='upload still active')
            if self.journal is not None:
                remaining = len(scope.uploads) > 1
                await self.journal_commit(lambda state: ownership.set_guards(state, scope.namespace, upload_status=('in_progress' if remaining else {'completed': 'complete', 'canceled': 'canceled'}[data['outcome']])))
            scope.uploads.pop(data['target_id'])
            scope.last_activity = time.monotonic()
        return web.json_response({'resolved': True, 'outcome': data['outcome']})

    async def abort_bootstrap(self, request):
        """Explicit abandonment only; unknown launcher windows remain untouched."""
        self.authorize(request)
        data = await request.json()
        if (not isinstance(data.get('namespace'), str) or not data['namespace']
                or data.get('acknowledge_unknown_launch') is not True):
            raise web.HTTPBadRequest()
        async with self.lock:
            t = self.transport
            if (self.journal is None or self.scopes or self.retired or self.leases
                    or t.targets or t.pending or t.leases or t.clients):
                return web.json_response({'error': 'bootstrap_abort_refused'}, status=409)
            async with self.journal_lock:
                try:
                    state = await asyncio.to_thread(self.journal.load)
                    if (state is None or state.get('version') != 2 or state.get('browser') is not None
                            or state.get('scopes') != {} or state.get('pendingBootstrap') != {
                                'namespace': data['namespace'], 'profile': 'Default'}):
                        return web.json_response({'error': 'bootstrap_abort_refused'}, status=409)
                    writer = asyncio.create_task(asyncio.to_thread(self.journal.archive_bootstrap, data['namespace']))
                    try:
                        await asyncio.shield(writer)
                    except asyncio.CancelledError:
                        while not writer.done():
                            try:
                                await asyncio.shield(writer)
                            except asyncio.CancelledError:
                                continue
                        writer.result()
                        self.transport_blocked = True
                        raise
                except (ownership.JournalError, OSError):
                    self.transport_blocked = True
                    self.blocked_error = 'journal_commit_failed'
                    return web.json_response({'error': 'journal_commit_failed'}, status=503)
                await t.disconnect()  # Only this broker's socket; no CDP commands.
                self.journal_state = None
                self.journal_loaded = True
                self.live_endpoint = None
                t.upstream_url = t.context_id = None
                self.transport_blocked = False
                self.blocked_error = self.failure_stage = None
        return web.json_response({'aborted': True, 'archived': True, 'closed': False, 'adopted': False})

    async def reconcile(self, request):
        """Explicit uncertainty acknowledgement; no mutation replay or adoption."""
        self.authorize(request)
        data = await request.json()
        if not isinstance(data.get('namespace'), str) or data.get('acknowledge_uncertain') is not True:
            raise web.HTTPBadRequest()
        async with self.lock:
            scope = self.scopes.get(data['namespace']) or self.retired.get(data['namespace'])
            if self.journal is None or scope is None:
                raise web.HTTPNotFound()
            if scope.leases or scope.mutations_inflight or self.transport.pending:
                raise web.HTTPConflict(text='scope not quiescent')
            await self.check_generation()
            await self.journal_commit(lambda state: ownership.set_guards(state, data['namespace'], busy=False, mutation_pending=False, uncertain=False))
            scope.recovery_guards.update(busy=False, mutation_pending=False, uncertain=False)
            scope.epoch += 1
        return web.json_response({'reconciled': True, 'replayed': False})

    async def configure_input(self, request):
        self.authorize(request)
        data = await request.json()
        if not isinstance(data.get('namespace'), str) or data.get('mode') not in ('emulate', 'foreground', 'deny'):
            raise web.HTTPBadRequest()
        async with self.lock:
            scope = self.scopes.get(data['namespace'])
            if scope is None:
                raise web.HTTPNotFound()
            if scope.leases or self.transport.pending:
                raise web.HTTPConflict(text='input mode fixed during admission')
            scope.epoch += 1
            scope.input_mode = data['mode']
        return web.json_response({'input_mode': scope.input_mode})

    async def takeover_status(self, request):
        self.authorize(request)
        data = await request.json()
        scope = (self.scopes.get(data.get('namespace')) or self.retired.get(data.get('namespace'))) if isinstance(data.get('namespace'), str) else None
        if scope is None:
            raise web.HTTPNotFound()
        return web.json_response({'targets': scope.takeover.snapshot()})

    async def takeover_control(self, request):
        self.authorize(request)
        data = await request.json()
        if (not isinstance(data.get('namespace'), str) or not isinstance(data.get('target_id'), str)
                or data.get('action') not in ('pause', 'release', 'resume')):
            raise web.HTTPBadRequest()
        scope = self.scopes.get(data['namespace']) or self.retired.get(data['namespace'])
        if scope is None or data['target_id'] not in scope.takeover.snapshot():
            raise web.HTTPNotFound()
        try:
            await scope.apply_takeover(data['target_id'], data['action'])
        except PermissionError:
            return web.json_response({'error': 'takeover_conflict'}, status=409)
        return web.json_response({'targets': scope.takeover.snapshot(), 'quiescent': True})

    def vault_scopes(self):
        return [scope for scope, kind in self.leases.values() if kind == 'vault']

    async def acquire(self, request):
        self.authorize(request)
        data = await request.json()
        if self.draining:
            return web.json_response({'error': 'detached'}, status=409)
        namespace = data.get('namespace')
        kind = data.get('kind', 'browser')
        if not isinstance(namespace, str) or not namespace or len(namespace) > 1024 or kind not in {'browser', 'vault'}:
            raise web.HTTPBadRequest()
        async with self.lock:
            if self.draining:
                return web.json_response({'error': 'detached'}, status=409)
            # An unscoped native supervisor cannot distinguish simultaneous root
            # callers. Vault root provisioning must not overlap browser dispatch.
            if self.vault_scopes() or (kind == 'vault' and self.leases):
                return web.json_response({'error': 'lease_conflict', 'reason': 'vault_requires_exclusive_admission'}, status=409)
            scope = self.scopes.get(namespace)
            if scope and scope.leases:
                return web.json_response({'error': 'lease_conflict', 'reason': 'session_in_use'}, status=409)
            try:
                if self.transport_blocked:
                    raise NativeFailure(self.blocked_error or 'upstream_uncertain')
                self.failure_stage = 'transport'
                await self.ensure_transport(namespace)
                scope = self.scopes.get(namespace)
                if namespace in self.borrowed_namespaces and not isinstance(scope, BorrowedScope):
                    raise web.HTTPForbidden(text='borrowed route retired; explicit reconfiguration required')
                if isinstance(scope, BorrowedScope):
                    if not scope.targets or not scope.takeover.is_active(scope.borrowed_target_id):
                        raise web.HTTPForbidden()
                    info = (await self.transport.command('Target.getTargetInfo', {'targetId': scope.borrowed_target_id})).get('targetInfo', {})
                    if info.get('browserContextId') != scope.context_id or info.get('type') != 'page':
                        raise NativeFailure('owned_target_lost')
                    lease = secrets.token_urlsafe(24)
                    scope.epoch += 1
                    scope.leases[lease] = namespace
                    self.leases[lease] = (scope, kind)
                    if kind == 'vault':
                        scope.vault_capability = secrets.token_urlsafe(32)
                    return web.json_response({'lease': lease, 'borrowed_target_id': scope.borrowed_target_id,
                        'endpoint': f'ws://{request.host}/devtools/browser/{scope.capability}',
                        'discovery': f'http://{request.host}/sessions/{scope.capability}/json/version'})
                self.failure_stage = 'profile_reproof'
                await self.ensure_idle_profile(namespace)
                self.failure_stage = 'scope_create'
                scope = self.scopes.get(namespace)
                if (scope is None and not self.transport.targets) or (scope is not None and not any(
                        t in scope.page_targets and scope.takeover.is_active(t) for t in scope.targets)):
                    self.check_resource_budget(namespace)
                if self.journal is not None:
                    await self.journal_commit(lambda state: (ownership.ensure_scope(state, namespace), ownership.set_guards(state, namespace, busy=True)))
                if scope is None:
                    scope = SessionScope(self.transport, namespace, control_token=self.control_token,
                                         idle_seconds=self.idle_seconds)
                    retired = self.retired.pop(namespace, None)
                    if retired:
                        scope.takeover = retired.takeover
                        scope.parents = retired.parents
                        scope.page_targets = retired.page_targets
                        scope.provenance_sessions = retired.provenance_sessions
                        scope.input_mode = retired.input_mode
                    if self.transport.targets:
                        # Bootstrap pages are proven owned, not invisible immortal
                        # resources. Transfer them once into the first task's idle
                        # lifecycle; normal discovery still excludes manual pages.
                        for target in tuple(self.transport.targets):
                            if self.journal is not None:
                                await self.journal_commit(lambda state, target=target: ownership.register_created(state, namespace, target))
                            scope.own(target)
                            self.resource_targets.setdefault(namespace, set()).add(target)
                        self.transport.targets.clear()
                    else:
                        result = await scope.command('Target.createTarget', {
                            'url': 'about:blank', 'newWindow': True,
                            **({'browserContextId': scope.context_id} if scope.context_id else {})})
                        scope.own(result['targetId'])
                    self.scopes[namespace] = scope
                if not any(t in scope.page_targets and scope.takeover.is_active(t) for t in scope.targets):
                    result = await scope.command('Target.createTarget', {
                        'url': 'about:blank', 'newWindow': True,
                        **({'browserContextId': scope.context_id} if scope.context_id else {})})
                    scope.own(result['targetId'])
                lease = secrets.token_urlsafe(24)
                scope.epoch += 1
                scope.leases[lease] = namespace
                self.leases[lease] = (scope, kind)
                if kind == 'vault':
                    scope.vault_capability = secrets.token_urlsafe(32)
                return web.json_response({'lease': lease,
                    'endpoint': f'ws://{request.host}/devtools/browser/{scope.capability}',
                    'discovery': f'http://{request.host}/sessions/{scope.capability}/json/version'})
            except web.HTTPException:
                raise
            except Exception as error:
                if getattr(error, 'code', None) == 'cdp_rejected' and self.failure_stage == 'scope_create':
                    error.code = 'scope_create_rejected'
                if not isinstance(error, (InitialTransportNotReady, ResourceLimit)):
                    self.transport_blocked = True
                    self.blocked_error = getattr(error, 'code', 'upstream_uncertain')
                if scope and scope.targets and not isinstance(error, ResourceLimit):
                    scope.preserve = True
                code = getattr(error, 'code', 'upstream_uncertain')
                return web.json_response({'status': 'tool_error', 'error': code,
                    'stage': self.failure_stage, 'retryable': isinstance(error, InitialTransportNotReady)}, status=503)

    async def ensure_idle_profile(self, namespace):
        t = self.transport
        if t.targets or any(s.targets for s in self.scopes.values()):
            return
        helper = getattr(t.connector, 'ensure_profile_context', None)
        if helper is None:
            return
        self.reserve_create(namespace)
        if self.journal is not None:
            await self.check_generation()
            await self.journal_commit(lambda state: (ownership.ensure_scope(state, namespace),
                ownership.reserve_resource(state, namespace, 1),
                ownership.set_guards(state, namespace, busy=True, mutation_pending=True)))
        proof = await helper(t.command, endpoint=t.upstream_url, context_id=t.context_id)
        if len(proof['targets']) > 1:
            raise NativeFailure('profile_marker')
        self.resource_unknown[namespace] -= 1
        self.resource_targets.setdefault(namespace, set()).update(proof['targets'])
        if self.journal is not None:
            identity = await self.connector.browser_identity(self.live_endpoint, proof['context_id'])
            old = self.journal_state['browser']
            if any(identity[k] != old[k] for k in ('fingerprint', 'uuid', 'profile')):
                raise ownership.JournalError('reproof changed browser generation')
            def confirmed(state):
                ownership.reserve_resource(state, namespace, -1)
                if identity['context_id'] != state['browser']['context_id']:
                    for metadata in state['scopes'].values():
                        for record in metadata['targets'].values():
                            record['takeover'] = 'released'
                    state['browser'] = identity
                for marker in proof['targets']:
                    ownership.register_created(state, namespace, marker, disposable='marker')
                ownership.set_guards(state, namespace, mutation_pending=False)
            await self.journal_commit(confirmed)
        t.context_id = proof['context_id']
        t.targets.update(proof['targets'])

    async def check_generation(self):
        if self.transport_blocked:
            raise ownership.JournalError('ownership journal blocked')
        current = await self.connector.browser_identity(self.live_endpoint, self.transport.context_id)
        if current != self.journal_state['browser']:
            self.transport_blocked = True
            for scope in self.scopes.values():
                scope.preserve = True
                scope.epoch += 1
            raise ownership.JournalError('live generation changed; no replay')

    async def journal_commit(self, change):
        if self.journal is None:
            return
        async with self.journal_lock:
            try:
                if self.transport_blocked:
                    raise ownership.JournalError('journal admission blocked')
                candidate = json.loads(json.dumps(self.journal_state))
                change(candidate)
                writer = asyncio.create_task(asyncio.to_thread(self.journal.save, candidate))
                try:
                    await asyncio.shield(writer)
                except asyncio.CancelledError:
                    # The disk thread cannot be canceled. Keep the lock until its
                    # atomic commit finishes; otherwise an older snapshot wins.
                    while not writer.done():
                        try:
                            await asyncio.shield(writer)
                        except asyncio.CancelledError:
                            continue
                    writer.result()
                    raise
                self.journal_state = candidate
            except BaseException as error:
                self.transport_blocked = True
                self.blocked_error = 'journal_commit_failed'
                if isinstance(error, Exception):
                    error.code = 'journal_commit_failed'
                for scope in self.scopes.values():
                    scope.preserve = True
                    scope.epoch += 1
                raise

    async def archive_generation(self, state):
        archive = ownership.StateJournal(self.journal.path.with_name('ownership-' + secrets.token_hex(16) + '.json'))
        async with self.journal_lock:
            writer = asyncio.create_task(asyncio.to_thread(archive.save, state))
            try:
                await asyncio.shield(writer)
            except asyncio.CancelledError:
                while not writer.done():
                    try:
                        await asyncio.shield(writer)
                    except asyncio.CancelledError:
                        continue
                writer.result()
                self.transport_blocked = True
                raise
            except (ownership.JournalError, OSError):
                self.transport_blocked = True
                raise NativeFailure('journal_commit_failed') from None

    async def durable_transport(self, namespace):
        t = self.transport
        if t.upstream is not None and not t.upstream.closed and t.reader and not t.reader.done():
            return
        if not self.journal_loaded:
            try:
                self.journal_state = await asyncio.to_thread(self.journal.load)
                if self.journal_state is not None:
                    self.journal_state = ownership.upgrade(self.journal_state)
            except (ownership.JournalError, OSError):
                raise NativeFailure('journal_invalid') from None
            self.journal_loaded = True
        await t.disconnect()
        initial_launch_intent = False
        combined_previous = None
        if self.journal_state is not None and (
                self.journal_state.get('pendingBootstrap') is not None
                or self.journal_state['browser']['context_id'] == '__unproven_Default__'):
            raise NativeFailure('journal_bootstrap_pending')
        if self.journal_state is None and hasattr(self.connector, 'discover_endpoint'):
            # A cold browser has no identity yet. Persist intent only, never a
            # fabricated fingerprint/context. Any interrupted launch stays denied.
            self.journal_state = {'version': 2, 'browser': None, 'scopes': {},
                'pendingBootstrap': {'namespace': namespace, 'profile': 'Default'}}
            await self.journal_commit(lambda state: None)
            initial_launch_intent = True
        runtime_previous = t.upstream_url
        fresh = False
        async def fresh_transport():
            nonlocal fresh
            # Journal UUID alone contains no port and cannot authorize relaunch.
            # Only the independently proven endpoint retained by this runtime is
            # eligible; fresh_endpoint itself must prove its exact old WS dead.
            nonlocal initial_launch_intent, combined_previous
            if runtime_previous and hasattr(self.connector, 'fresh_endpoint'):
                fresh = True
                return await self.connector.fresh_endpoint(runtime_previous)
            absent = getattr(self.connector, 'prove_previous_generation_absent', None)
            launch = getattr(self.connector, 'launch_after_absence', None)
            previous = self.journal_state and self.journal_state.get('browser')
            if not previous or absent is None or launch is None:
                raise NativeFailure('journal_endpoint_unavailable')
            if await absent(previous) is not True:
                raise NativeFailure('journal_generation_ambiguous')
            # Combined cold: archive exact old metadata, then publish neutral
            # launch intent. Neither journal UUID nor discovery grants ownership.
            await self.archive_generation(self.journal_state)
            neutral = {'version': 2, 'browser': None, 'scopes': {},
                'pendingBootstrap': {'namespace': namespace, 'profile': 'Default'}}
            await self.journal_commit(lambda state: (state.clear(), state.update(neutral)))
            initial_launch_intent = fresh = True
            combined_previous = previous
            self.resource_targets.clear()
            self.resource_unknown.clear()
            return await launch(previous)
        if self.journal_state is not None and not initial_launch_intent and hasattr(self.connector, 'rediscover_endpoint'):
            try:
                discovered = await self.connector.rediscover_endpoint()
            except (OSError, TimeoutError):
                endpoint = await fresh_transport()
            else:
                if runtime_previous and discovered != runtime_previous:
                    endpoint = await fresh_transport()
                else:
                    previous = self.journal_state['browser']
                    endpoint = {'url': discovered, 'context_id': previous['context_id']}
                    if not runtime_previous and discovered.rsplit('/', 1)[-1] != previous['uuid']:
                        # A user may already have reopened Chrome. Independently
                        # prove a stable different Default process AND UUID before
                        # archiving; context is not trusted until our exact marker.
                        candidate = await self.connector.browser_identity(endpoint, previous['context_id'])
                        if (candidate['profile'] != 'Default' or candidate['uuid'] == previous['uuid']
                                or candidate['fingerprint'] == previous['fingerprint']
                                or candidate != await self.connector.browser_identity(endpoint, previous['context_id'])):
                            raise NativeFailure('journal_generation_ambiguous')
                        await self.archive_generation(self.journal_state)
                        neutral = {'version': 2, 'browser': None, 'scopes': {},
                            'pendingBootstrap': {'namespace': namespace, 'profile': 'Default'}}
                        await self.journal_commit(lambda state: (state.clear(), state.update(neutral)))
                        if (await self.connector.discover_endpoint() != discovered
                                or candidate != await self.connector.browser_identity(endpoint, previous['context_id'])):
                            raise NativeFailure('journal_generation_ambiguous')
                        initial_launch_intent = fresh = True
                        combined_previous = previous
                        endpoint = await self.connector()  # One Default marker, no PWA navigation.
                        if endpoint.get('url') != discovered:
                            raise NativeFailure('journal_generation_ambiguous')
                        self.resource_targets.clear()
                        self.resource_unknown.clear()
        else:
            try:
                endpoint = await self.connector()
            except BaseException as error:
                if initial_launch_intent and isinstance(error, Exception):
                    raise NativeFailure('journal_bootstrap_pending') from None
                raise
        if not isinstance(endpoint, dict):
            raise ownership.JournalError('independent browser identity required')
        t.http = ClientSession()
        try:
            t.upstream = (await t.ws_connector(t.http, endpoint['url']) if t.ws_connector
                          else await t.http.ws_connect(endpoint['url'], timeout=ClientWSTimeout(ws_close=5)))
        except (WSServerHandshakeError, ClientConnectorError) as error:
            dead_path = isinstance(error, WSServerHandshakeError) and error.status in {404, 410}
            if initial_launch_intent or fresh:
                if not dead_path or not hasattr(self.connector, 'wait_endpoint_change'):
                    raise NativeFailure('ws_denied' if isinstance(error, WSServerHandshakeError) and error.status in {401, 403} else 'journal_endpoint_unavailable') from None
                # TCP listening is not UUID readiness. Read native file only;
                # never adopt HTTP discovery or repeat the original launcher.
                endpoint['url'] = await self.connector.wait_endpoint_change(endpoint['url'])
            else:
                if not dead_path and not isinstance(error, ClientConnectorError):
                    raise NativeFailure('ws_denied') from None
                endpoint = await fresh_transport()
            # fresh_endpoint independently probes old liveness; this is only WS
            # setup, and no downstream CDP mutation has been sent or replayed.
            try:
                t.upstream = (await t.ws_connector(t.http, endpoint['url']) if t.ws_connector
                              else await t.http.ws_connect(endpoint['url'], timeout=ClientWSTimeout(ws_close=5)))
            except (WSServerHandshakeError, ClientConnectorError) as retry_error:
                denied = isinstance(retry_error, WSServerHandshakeError) and retry_error.status in {401, 403}
                raise NativeFailure('ws_denied' if denied else 'journal_endpoint_unavailable') from None
        t.reader = asyncio.create_task(t.read_upstream())
        infos = (await t.command('Target.getTargets')).get('targetInfos', [])
        context = endpoint.get('context_id')
        if not context or initial_launch_intent:
            deadline = asyncio.get_running_loop().time() + t.marker_timeout
            while True:
                markers = [i for i in infos if i.get('type') == 'page' and i.get('url') == endpoint.get('marker_url')]
                if len(markers) > 1 or (markers and not markers[0].get('browserContextId')):
                    raise NativeFailure('profile_marker')
                if markers:
                    break
                if not endpoint.get('marker_url') or asyncio.get_running_loop().time() >= deadline:
                    raise NativeFailure('profile_marker')
                await asyncio.sleep(.05)
                infos = (await t.command('Target.getTargets')).get('targetInfos', [])
            context = markers[0]['browserContextId']
        identity = await self.connector.browser_identity(endpoint, context)
        if identity['context_id'] != context:
            raise NativeFailure('profile_marker')
        if combined_previous and (identity['uuid'] == combined_previous['uuid'] or identity['profile'] != 'Default'):
            raise NativeFailure('journal_generation_ambiguous')
        if initial_launch_intent:
            markers = [i for i in infos if endpoint.get('marker_url') and i.get('url') == endpoint['marker_url'] and i.get('type') == 'page' and i.get('browserContextId') == context]
            if len(markers) != 1:
                raise NativeFailure('profile_marker')
            self.journal_state = ownership.new_state(fingerprint=identity['fingerprint'],
                browser_uuid=identity['uuid'], context_id=context)
            ownership.register_created(self.journal_state, namespace, markers[0]['targetId'], disposable='marker')
            ownership.set_guards(self.journal_state, namespace, busy=False, mutation_pending=False)
        elif self.journal_state and self.journal_state['browser']['context_id'] == '__unproven_Default__':
            raise ownership.JournalError('interrupted initial launch requires explicit reconciliation')
        plan = ownership.recovery_plan(self.journal_state, identity, infos)
        if self.journal_state is not None and not plan['generation_matches']:
            # Only a freshly launched exact marker and independent identity can
            # admit a replacement. Mere endpoint change never authorizes it.
            markers = [i for i in infos if endpoint.get('marker_url') and i.get('url') == endpoint['marker_url'] and i.get('type') == 'page']
            if len(markers) != 1 or markers[0].get('browserContextId') != context:
                raise ownership.JournalError('generation changed without Default launcher proof')
            if identity != await self.connector.browser_identity(endpoint, context):
                raise ownership.JournalError('generation changed during recovery')
            await self.archive_generation(self.journal_state)
            for scope in tuple(self.scopes.values()):
                scope.epoch += 1
                scope.preserve = True
                scope.leases.clear()
                await scope.disconnect()
            self.scopes.clear()
            self.retired.clear()
            self.leases.clear()
            self.journal_state = None
            plan = ownership.recovery_plan(None, identity, infos)
        if self.journal_state is None:
            self.journal_state = ownership.new_state(fingerprint=identity['fingerprint'], browser_uuid=identity['uuid'], context_id=context)
        else:
            self.journal_state = plan['state']
            structural = json.loads(json.dumps(plan['state']))
            for metadata in structural['scopes'].values():
                metadata['guards'] = dict(ownership.GUARD_DEFAULTS)
            structural_plan = ownership.recovery_plan(structural, identity, infos)
            for namespace, recovered in plan['scopes'].items():
                if structural_plan['scopes'][namespace]['preserve']:
                    ownership.set_guards(self.journal_state, namespace, preserve=True)
                    recovered['guards']['preserve'] = True
        if identity != await self.connector.browser_identity(endpoint, context):
            raise NativeFailure('profile_marker')
        await self.journal_commit(lambda state: None)
        if identity != await self.connector.browser_identity(endpoint, context):
            raise ownership.JournalError('browser changed during durable recovery commit')
        # Count retained live records, including released/manual-transferred IDs.
        # They consume generation budget without regaining cleanup authority.
        self.resource_targets = {n: set(meta['targets']).intersection({i['targetId'] for i in infos})
            for n, meta in self.journal_state['scopes'].items()}
        self.resource_unknown = {n: meta.get('unknown_creates', int(meta['guards']['mutation_pending']))
            for n, meta in self.journal_state['scopes'].items()}
        t.context_id = context
        t.upstream_url = endpoint['url']
        self.live_endpoint = endpoint
        if endpoint.get('marker_url') and not initial_launch_intent:
            confirmed_markers = [i for i in infos if i.get('type') == 'page' and i.get('url') == endpoint['marker_url'] and i.get('browserContextId') == context]
            if len(confirmed_markers) != 1:
                raise NativeFailure('profile_marker')
            t.targets.add(confirmed_markers[0]['targetId'])
        for old_scope in tuple(self.scopes.values()):
            old_scope.epoch += 1
            old_scope.leases.clear()
            await old_scope.disconnect()
        self.scopes.clear()
        self.retired.clear()
        self.leases.clear()
        for namespace, recovered in plan['scopes'].items():
            scope = SessionScope(t, namespace, control_token=self.control_token, idle_seconds=self.idle_seconds)
            scope.targets = recovered['owned']
            scope.disposable = recovered['disposable']
            scope.mutation_risk = recovered['mutation_risk']
            self.resource_targets.setdefault(namespace, set()).update(recovered['owned'])
            scope.parents = recovered['parents']
            scope.page_targets = recovered['page_targets']
            scope.preserve = recovered['preserve']
            scope.recovery_guards = dict(recovered['guards'])
            if recovered['guards']['upload_status'] in ('in_progress', 'uncertain'):
                scope.uploads = {t: {'state': 'uncertain', 'pending': set()} for t in scope.targets & scope.page_targets}
                scope.preserve = any(recovered['guards'][k] for k in ownership.GUARD_DEFAULTS if k != 'upload_status')
            scope.takeover = await ownership.restore_takeover(recovered)
            (self.scopes if scope.targets else self.retired)[namespace] = scope

    async def ensure_transport(self, namespace=None):
        if self.draining:
            raise web.HTTPConflict(text='detached')
        if self.journal is not None:
            return await self.durable_transport(namespace)
        t = self.transport
        ready = t.upstream is not None and not t.upstream.closed and t.reader and not t.reader.done()
        if ready:
            return
        # Bootstrap admission uses the existing marker/identity recovery checks.
        # No request/code is replayed after a dropped mutation.
        t.leases.clear()
        class Admission:
            headers = {'Authorization': 'Bearer ' + t.control_token}
            async def json(self):
                return {'namespace': '__profile_transport__'}
        previous = t.upstream_url
        response = await t.acquire(Admission())
        if response.status != 200:
            if t.admission_retryable and not self.scopes and not self.retired and not self.leases:
                error = InitialTransportNotReady('initial setup not ready')
                error.code = t.last_error or 'startup'
                raise error
            raise NativeFailure(t.last_error or 'upstream_uncertain')
        if previous and previous != t.upstream_url:
            self.resource_targets.clear()
            self.resource_unknown.clear()
            # Legacy handshake already proved fresh UUID + exact profile marker.
            # Retire only proxy selections, preserving every old Chrome resource.
            for scope in tuple(self.scopes.values()):
                scope.epoch += 1
                scope.preserve = True
                await scope.disconnect()
                scope.leases.clear()
            self.scopes.clear()
            self.retired.clear()
            self.leases.clear()
        if self.scopes:
            infos = (await t.command('Target.getTargets')).get('targetInfos', [])
            by_id = {info['targetId']: info for info in infos}
            for scope in self.scopes.values():
                if not scope.targets <= by_id.keys() or any(
                    scope.context_id and by_id[tid].get('browserContextId') != scope.context_id
                    for tid in scope.targets):
                    scope.preserve = True
                    raise NativeFailure('owned_target_lost')

    async def event(self, data):
        for scope in (*tuple(self.scopes.values()), *tuple(self.retired.values())):
            await scope.event(data)

    async def discovery(self, request):
        capability = request.match_info.get('capability')
        if capability:
            scope = next((s for s in self.scopes.values() if s.capability == capability), None)
            if scope is None:
                raise web.HTTPForbidden()
        else:
            scopes = self.vault_scopes()
            if len(scopes) != 1 or not scopes[0].vault_capability or not scopes[0].takeover.is_active(scopes[0].vault_target):
                raise web.HTTPServiceUnavailable(text='root discovery requires exact vault binding')
            scope = scopes[0]
        if not scope.leases:
            raise web.HTTPServiceUnavailable(text='no active admission')
        selected = scope.capability if capability else scope.vault_capability
        return web.json_response({'Browser': 'Native-Chrome-Broker', 'Protocol-Version': '1.3',
            'webSocketDebuggerUrl': f'ws://{request.host}/devtools/browser/{selected}'})

    async def socket(self, request):
        scope = next((s for s in self.scopes.values()
                      if request.match_info['capability'] in {s.capability, s.vault_capability}), None)
        if scope is None:
            raise web.HTTPForbidden()
        return await scope.socket(request)

    async def app_route(self, request):
        self.authorize(request)
        data = await request.json()
        async with self.lock:
            scope, kind = self.leases.get(data.get('lease'), (None, None))
            if scope is None or kind != 'browser' or scope.vault_target is not None:
                raise web.HTTPForbidden()
            if not isinstance(data.get('url'), str):
                raise web.HTTPBadRequest()
            if self.app_launcher is None:
                return web.json_response({'fallback': True})
            from app_launch import AppRouteError
            epoch, leases = scope.epoch, dict(scope.leases)
            route_phase = 'refresh'
            result = None
            def recheck():
                if (self.transport_blocked or epoch != scope.epoch or leases != scope.leases
                        or self.leases.get(data['lease']) != (scope, kind)):
                    raise PermissionError('app admission revoked')
            try:
                prior = getattr(scope, 'external_app_ids', {})
                if prior:
                    prepare = getattr(self.app_launcher, 'refresh', None)
                    if prepare:
                        await prepare(self.transport, recheck=recheck)
                    selected = self.app_launcher.catalog.resolve(data['url'], profile='Default')
                    matching = [target for target, app_id in prior.items() if selected and selected.app_id == app_id
                        and target in scope.targets and scope.takeover.is_active(target)]
                    if len(matching) == 1:
                        target = matching[0]
                        info = (await self.transport.command('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
                        recheck()
                        if (info.get('targetId') == target and info.get('type') == 'page'
                                and info.get('browserContextId') == scope.context_id and selected.contains(info.get('url'))):
                            return web.json_response({'target_id': target, 'app_id': selected.app_id, 'created_owned': False})
                        raise PermissionError('prior app binding lost')
                route_phase = 'selection'
                import inspect
                options = {'recheck': recheck}
                if 'reserved_targets' in inspect.signature(self.app_launcher.select).parameters:
                    options['reserved_targets'] = {t for s in (*self.scopes.values(), *self.retired.values())
                        if s is not scope for t in s.takeover.snapshot()}
                result = await self.app_launcher.select(self.transport, data['url'], **options)
                route_phase = 'binding'
                recheck()
                if result is None:
                    return web.json_response({'fallback': True})
                target = result['target_id']
                if any(target in s.takeover.snapshot() for s in (*self.scopes.values(), *self.retired.values())):
                    raise AppRouteError('binding', reason='reserved')
                # Runtime authority only: exact external target guard, not a
                # scope-wide durable creation/preservation claim.
                recheck()
                scope.own(target)
                scope.external_app_targets = getattr(scope, 'external_app_targets', set()) | {target}
                scope.external_app_ids = {**getattr(scope, 'external_app_ids', {}), target: result['app_id']}
                return web.json_response(result)
            except asyncio.CancelledError as error:
                if getattr(error, 'launch_attempted', route_phase == 'selection'):
                    scope.preserve = True
                raise
            except Exception as error:
                typed = error if isinstance(error, AppRouteError) else AppRouteError(
                    route_phase, launch_attempted=route_phase == 'selection')
                if typed.launch_attempted:
                    scope.preserve = True
                    if self.journal is not None:
                        await self.journal_commit(lambda state: ownership.set_guards(
                            state, scope.namespace, preserve=True))
                return web.json_response(typed.payload(), status=503)

    async def cleanup_preamble(self, request):
        """Reclaim only exact unused pristine created blank after driver rebind."""
        self.authorize(request)
        data = await request.json()
        target, sid = data.get('target_id'), data.get('session_id')
        selected, selected_sid = data.get('selected_target_id'), data.get('selected_session_id')
        async with self.lock:
            scope, kind = self.leases.get(data.get('lease'), (None, None))
            if scope is None or kind != 'browser':
                raise web.HTTPForbidden()
            async with scope.lock:
                record = (self.journal_state or {}).get('scopes', {}).get(scope.durable_namespace, {}).get('targets', {}).get(target, {})
                scope.preamble_cleanup = (target, data['lease'], selected, selected_sid)
                try:
                    if (self.journal is None or record.get('proof') != 'created'
                            or record.get('takeover') != 'active' or record.get('mutation_risk', True)
                            or record.get('disposable') != 'blank' or target in getattr(scope, 'external_app_targets', set())
                            or scope.session_targets.get(sid) != target
                            or not any(sid in state for state in scope.clients.values())
                            or {t for t in scope.targets if scope.page(t) == target} != {target}
                            or not scope.safe_disposable(target) or self.transport.pending or self.transport_blocked):
                        return web.json_response({'closed': False, 'error': 'preamble_cleanup_unproven'}, status=409)
                    await self.check_generation()
                    info = (await scope.command('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
                    if (info.get('targetId') != target or info.get('type') != 'page'
                            or info.get('url') != 'about:blank' or info.get('openerId')
                            or info.get('browserContextId') != scope.context_id or not scope.safe_disposable(target)):
                        return web.json_response({'closed': False, 'error': 'preamble_cleanup_unproven'}, status=409)
                    scope.disposable_cleanup = target
                    async def close():
                        await scope.command('Target.closeTarget', {'targetId': target})
                    if not await scope.takeover.close_if_active(target, close):
                        return web.json_response({'closed': False, 'error': 'preamble_cleanup_revoked'}, status=409)
                    # A confirmed close alone is insufficient to forget provenance.
                    # Verify exact absence; retain runtime takeover tombstone against
                    # late events, but no growing durable records for gone blanks.
                    infos = (await self.transport.command('Target.getTargets')).get('targetInfos', [])
                    await self.check_generation()
                    if target not in {i.get('targetId') for i in infos}:
                        def forget_closed(state):
                            records = state['scopes'][scope.durable_namespace]['targets']
                            record = records.get(target, {})
                            if (record.get('takeover') == 'released' and record.get('proof') == 'created'
                                    and not record.get('mutation_risk', True)
                                    and not any(r.get('parent') == target for r in records.values())):
                                records.pop(target, None)
                        await self.journal_commit(forget_closed)
                    scope.targets.discard(target)
                    scope.page_targets.discard(target)
                    scope.disposable.pop(target, None)
                    for state in scope.clients.values():
                        for old_sid in tuple(state):
                            if scope.session_targets.get(old_sid) == target:
                                state.pop(old_sid, None)
                                scope.session_targets.pop(old_sid, None)
                                scope.provenance_sessions.pop(old_sid, None)
                    scope.epoch += 1
                finally:
                    scope.disposable_cleanup = None
                    scope.preamble_cleanup = None
        return web.json_response({'closed': True, 'target_id': target, 'replayed': False})

    async def cleanup_disposable(self, request):
        """Exact authenticated cleanup, never erase old risk or transfer guards."""
        self.authorize(request)
        data = await request.json()
        namespace, target = data.get('namespace'), data.get('target_id')
        if not isinstance(namespace, str) or not isinstance(target, str):
            raise web.HTTPBadRequest()
        async with self.lock:
            scope = self.scopes.get(namespace) or self.retired.get(namespace)
            if scope is None:
                raise web.HTTPNotFound()
            async with scope.lock:
                record = (self.journal_state or {}).get('scopes', {}).get(namespace, {}).get('targets', {}).get(target, {})
                if (self.journal is None or record.get('proof') != 'created'
                        or record.get('takeover') != 'active' or record.get('mutation_risk', True)
                        or target in getattr(scope, 'external_app_targets', set())
                        or not scope.safe_disposable(target) or self.transport.pending
                        or scope.recovery_guards.get('upload_status') in {'in_progress', 'uncertain'}):
                    return web.json_response({'error': 'disposable_cleanup_unproven'}, status=409)
                expected = 'about:blank' if scope.disposable.get(target) == 'blank' else (self.live_endpoint or {}).get('marker_url')
                await self.check_generation()
                info = (await scope.command('Target.getTargetInfo', {'targetId': target})).get('targetInfo', {})
                if (not expected or info.get('targetId') != target or info.get('type') != 'page'
                        or info.get('url') != expected or info.get('browserContextId') != scope.context_id):
                    return web.json_response({'error': 'disposable_cleanup_unproven'}, status=409)
                scope.disposable_cleanup = target
                try:
                    async def close():
                        result = await scope.command('Target.closeTarget', {'targetId': target})
                        if result.get('success') is not True:
                            raise ConnectionError('disposable close unconfirmed')
                    if not await scope.takeover.close_if_active(target, close):
                        return web.json_response({'error': 'disposable_cleanup_revoked'}, status=409)
                    scope.targets.discard(target)
                    for state in scope.clients.values():
                        for sid in tuple(state):
                            if scope.session_targets.get(sid) == target:
                                state.pop(sid, None)
                                scope.session_targets.pop(sid, None)
                    scope.epoch += 1
                finally:
                    scope.disposable_cleanup = None
        return web.json_response({'closed': True, 'target_id': target, 'replayed': False})

    async def driver_capacity(self, request):
        """Authenticated pre-start quota check; final create still reserves atomically."""
        self.authorize(request)
        data = await request.json()
        async with self.lock:
            scope, kind = self.leases.get(data.get('lease'), (None, None))
            if scope is None or kind != 'browser':
                raise web.HTTPForbidden()
            try:
                self.check_resource_budget(scope.durable_namespace)
            except ResourceLimit:
                return web.json_response({'error': 'resource_limit', 'retryable': False}, status=503)
        return web.json_response({'available': True})

    async def verify_driver(self, request):
        self.authorize(request)
        data = await request.json()
        scope, _ = self.leases.get(data.get('lease'), (None, None))
        target, sid = data.get('target_id'), data.get('session_id')
        if (scope is not None and target in scope.targets and scope.takeover.is_active(target)
                and scope.takeover.is_active(scope.page(target)) and scope.revoked_sessions.get(sid) == target):
            return web.json_response({'error': 'fresh_attach_required'}, status=403)
        if (scope is None or target not in scope.targets or not scope.takeover.is_active(target) or scope.session_targets.get(sid) != target
                or not any(sid in state for state in scope.clients.values())):
            raise web.HTTPForbidden()
        return web.json_response({'verified': True})

    async def bind_vault(self, request):
        self.authorize(request)
        data = await request.json()
        scope, kind = self.leases.get(data.get('lease'), (None, None))
        if scope is None or kind != 'vault':
            raise web.HTTPForbidden()
        if not scope.takeover.is_active(data.get('target_id')):
            raise web.HTTPForbidden()
        result = await scope.bind_vault(request)
        scope.epoch += 1
        return result

    async def release(self, request):
        self.authorize(request)
        data = await request.json()
        async with self.lock:
            admission = self.leases.pop(data.get('lease'), None)
            if admission is None:
                raise web.HTTPNotFound()
            scope, kind = admission
            scope.epoch += 1
            scope.leases.pop(data['lease'], None)
            revoked = scope.vault_capability
            scope.vault_capability = None
            for ws, capability in tuple(scope.client_capabilities.items()):
                if revoked and capability == revoked:
                    await ws.close(code=1008, message=b'vault lease released')
            scope.vault_target = None
            scope.last_activity = time.monotonic()
            if self.journal is not None and not isinstance(scope, BorrowedScope):
                await self.journal_commit(lambda state: ownership.set_guards(state, scope.namespace, busy=scope.recovery_guards.get('busy', False)))
        return web.json_response({'released': True})

    async def mark_preserve(self, request):
        self.authorize(request)
        data = await request.json()
        admission = self.leases.get(data.get('lease'))
        if admission is None:
            raise web.HTTPForbidden()
        admission[0].preserve = True
        if self.journal is not None:
            await self.journal_commit(lambda state: ownership.set_guards(state, admission[0].namespace, preserve=True))
        return web.json_response({'preserved': True})

    async def health(self, request):
        t = self.transport
        ready = t.upstream is not None and not t.upstream.closed and t.reader and not t.reader.done()
        resource_scopes = {n: {'retained': len(self.resource_targets.get(n, set())),
            'unknown_creates': self.resource_unknown.get(n, 0),
            'limited': len(self.resource_targets.get(n, set())) + self.resource_unknown.get(n, 0) >= self.max_owned_per_scope}
            for n in self.resource_targets.keys() | self.resource_unknown.keys()}
        return web.json_response({'service': plugin_identity.plugin_id(),
            'state': 'ready' if ready else 'disconnected', 'active': len(self.leases),
            'sessions': len(self.scopes), 'owned': sum(len(s.targets) for s in self.scopes.values() if not isinstance(s, BorrowedScope)),
            'borrowed': sum(len(s.targets) for s in self.scopes.values() if isinstance(s, BorrowedScope)),
            'preserve': any(s.preserve for s in self.scopes.values()),
            'pending': len(t.pending), 'downloads': sum(len(s.downloads) for s in self.scopes.values()),
            'uploads': sum(len(s.uploads) for s in self.scopes.values()),
            'clients': sum(len(s.clients) for s in self.scopes.values()),
            'bootstrap_pending': bool(self.journal_state and self.journal_state.get('pendingBootstrap')),
            'journal_loaded': self.journal_loaded, 'blocked_error': self.blocked_error,
            'failure_stage': self.failure_stage,
            'runtime_endpoint_proven': bool(self.live_endpoint and t.upstream_url),
            'resources': {'scope_limit': self.max_owned_per_scope, 'generation_limit': self.max_owned_per_generation,
                'retained': sum(map(len, self.resource_targets.values())),
                'unknown_creates': sum(self.resource_unknown.values()),
                'scopes': resource_scopes,
                'limited': any(s['limited'] for s in resource_scopes.values()) or sum(map(len, self.resource_targets.values())) + sum(self.resource_unknown.values()) >= self.max_owned_per_generation}})

    async def start_janitor(self, app):
        async def run():
            while True:
                await asyncio.sleep(1)
                await self.sweep()
        self.janitor = asyncio.create_task(run())

    async def sweep(self, now=None):
        async with self.lock:
            if self.draining or self.transport.pending or self.transport_blocked or (self.journal is not None and not self.journal_loaded):
                return
            for namespace, scope in tuple(self.scopes.items()):
                await scope.sweep(now)
                if scope.namespace is None:
                    self.retired[namespace] = scope
                    self.scopes.pop(namespace, None)

    async def shutdown(self, app):
        self.closing = True
        if hasattr(self, 'transport'):
            self.transport.closing = True
        if self.janitor:
            self.janitor.cancel()
            try:
                await self.janitor
            except asyncio.CancelledError:
                pass
        # Revoke before any await; an already-sent mutation remains uncertain.
        # Release command waiters before closing downstream sockets: aiohttp's
        # close waits for the receive handler, which may itself await that reply.
        for scope in (*tuple(self.scopes.values()), *tuple(self.retired.values())):
            scope.epoch += 1
        for future in tuple(self.transport.pending.values()):
            if not future.done():
                future.set_exception(ConnectionError('broker shutting down; outcome uncertain, not replayed'))
        for scope in (*tuple(self.scopes.values()), *tuple(self.retired.values())):
            await scope.disconnect()
        await self.transport.disconnect()

