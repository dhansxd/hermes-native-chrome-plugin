"""Standalone broker entrypoint; config activation is intentionally separate."""
import argparse
import importlib.util
import os
import secrets
import stat
from pathlib import Path
from aiohttp import web
ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('_dyra_bundle_entry', ROOT / '__init__.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_sibling(name)


def validate_bind(host):
    if host != '127.0.0.1':
        raise ValueError('broker must bind 127.0.0.1')


@web.middleware
async def local_guard(request, handler):
    host = request.host.split(':', 1)[0]
    if host not in {'127.0.0.1', 'localhost'} or request.headers.get('Origin'):
        raise web.HTTPForbidden(text='loopback non-browser client required')
    try:
        return await handler(request)
    except web.HTTPException:
        raise
    except Exception:
        # No URL, token, payload or stack trace in a client response.
        return web.json_response({'error': 'native_broker_failed', 'status': 'tool_error'}, status=503)


async def marker(request):
    # Static body only: no token echo, scripting, credentials or redirects.
    return web.Response(text='Native Chrome profile marker\n', headers={
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'"})


def make_app(*, home=None, token_file=None, port=19347, evidence_queue=None, stop_event=None):
    import platform
    if platform.system() != 'Darwin':
        raise RuntimeError('unsupported_platform')
    controller = load('controller')
    home = controller.effective_home(home)
    path = Path(token_file) if token_file is not None else controller.state_directory(home) / 'control-token'
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'w') as stream:
            stream.write(secrets.token_urlsafe(32))
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError('unsafe control token file')
    native = load('native')
    prove_browser_identity = load('browser_identity').prove_browser_identity
    StateJournal = load('state_journal').StateJournal
    connector = native.NativeConnector(marker_origin=f'http://127.0.0.1:{int(port)}', evidence_queue=evidence_queue)
    connector.browser_identity = prove_browser_identity
    broker = load('broker').SessionBroker(connector, control_token=path.read_text().strip(),
        ws_connector=connector.connect_approved, journal=StateJournal(path.parent / 'ownership.json'))
    broker.profile_home = str(home)
    InstalledAppCatalog = load('app_catalog').InstalledAppCatalog
    CatalogAdapter = load('app_router').CatalogAdapter
    AppLauncher = load('app_launch').AppLauncher
    refresh = load('app_refresh').refresh
    import asyncio
    catalog = InstalledAppCatalog(
        app_dirs=[Path.home() / 'Applications/Chrome Apps.localized'],
        local_state=Path.home() / 'Library/Application Support/Google/Chrome/Local State')
    adapter = CatalogAdapter(catalog)
    async def launch(app):
        record = adapter.records.get(app)
        if record is None or not catalog.revalidate(record):
            raise PermissionError('installed app disappeared')
        process = await asyncio.create_subprocess_exec('/usr/bin/open', '-g', str(record.app_path),
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        if await process.wait() != 0:
            raise PermissionError('native app launch failed; no replay')
    class FreshLauncher(AppLauncher):
        async def refresh(self, transport, *, recheck):
            await refresh(catalog, transport, recheck=recheck)
        async def select(self, transport, url, *, recheck, preferred_target=None, reserved_targets=()):
            # No static file snapshot: registrar is re-read for every helper decision.
            await refresh(catalog, transport, recheck=recheck)
            return await super().select(transport, url, recheck=recheck,
                preferred_target=preferred_target, reserved_targets=reserved_targets)
    broker.app_launcher = FreshLauncher(adapter, launch)
    broker.lifecycle_stop_supported = stop_event is not None
    app = broker.app()
    async def stop(request):
        broker.authorize(request)
        data = await request.json()
        if data.get('home') != str(home):
            raise web.HTTPForbidden()
        state = load('lifecycle')._read_state(home)
        if (stop_event is None or state is None or state['desired_enabled'] is not False
                or state['phase'] not in {'detaching', 'detached'} or state['port'] != int(port)):
            return web.json_response({'error': 'stop_intent_required'}, status=409)
        if broker.lock.locked() or broker.journal_lock.locked():
            return web.json_response({'status': 'blocked', 'blockers': ['pending_operations']}, status=409)
        async with broker.lock:
            blockers = broker.drain_blockers()
            if (not broker.draining or not broker.drain_id
                    or data.get('drain_id') != broker.drain_id):
                return web.json_response({'error': 'quiet_drain_required'}, status=409)
            if blockers:
                return web.json_response({'status': 'blocked', 'blockers': blockers}, status=409)
            # Recheck retirement before ACK; failure leaves the listener and
            # runtime registry available to a later authenticated retry.
            blockers = await broker.cleanup_harnesses(timeout=5)
            if blockers:
                return web.json_response({'status': 'blocked', 'blockers': blockers}, status=409)
            broker.soft_stop = broker.closing = broker.transport.closing = True
            # Flush the acknowledgment before the owning runner closes listeners.
            response = web.json_response({'status': 'stopping', 'blockers': []})
            await response.prepare(request)
            await response.write_eof()
            stop_event.set()
            return response
    app.router.add_post('/control/stop', stop)
    @web.middleware
    async def lifecycle_guard(request, handler):
        if request.path in {'/control/acquire', '/control/activate', '/control/borrow-existing', '/control/list-existing'}:
            if not load('lifecycle').desired_enabled(home):
                return web.json_response({'error': 'detached'}, status=409)
        return await handler(request)
    app.middlewares.append(lifecycle_guard)
    async def identity(request):
        broker.authorize(request)
        return web.json_response({'service': load('plugin_identity').plugin_id(), 'home': str(home), 'protocol': 1})
    app.router.add_post('/control/identity', identity)
    app.router.add_get('/marker/{token:[A-Za-z0-9_-]+}', marker)
    app.middlewares.append(local_guard)
    return app


async def serve(*, host='127.0.0.1', port=19347, home=None, token_file=None, service_lock_fd=None):
    """Owned child runner: only its authenticated control route ends the loop."""
    import asyncio
    validate_bind(host)
    home = load('controller').effective_home(home)
    # Own before token/journal construction, through listener and cleanup exit.
    # Embedded make_app fixtures deliberately do not own a standalone service.
    with load('harness_cleanup').service_lock(home, inherited_fd=service_lock_fd):
        stop_event = asyncio.Event()
        app = make_app(home=home, token_file=token_file, port=port, stop_event=stop_event)
        runner = web.AppRunner(app, access_log=None, shutdown_timeout=2)
        try:
            await runner.setup()
            await web.TCPSite(runner, host, port).start()
            await stop_event.wait()
        finally:
            await runner.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=19347)
    parser.add_argument('--home', type=Path)
    parser.add_argument('--token-file', type=Path)
    parser.add_argument('--service-lock-fd', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    validate_bind(args.host)
    import asyncio
    asyncio.run(serve(home=args.home, token_file=args.token_file, host=args.host, port=args.port,
                      service_lock_fd=args.service_lock_fd))


if __name__ == '__main__':
    main()
