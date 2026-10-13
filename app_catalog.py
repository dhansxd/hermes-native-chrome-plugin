"""Read-only installed Chrome shim discovery; no browser or account mutations."""
from dataclasses import dataclass, field
import json
from pathlib import Path
import plistlib
from typing import Callable, Iterable
from urllib.parse import urlsplit, unquote


def _url_key(url: str) -> tuple[tuple[str, str, int], str] | None:
    """Conservative HTTP(S) origin/path key; ambiguous browser spellings fall back."""
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        return None
    if '\\' in url:
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        host = parsed.hostname.encode('idna').decode('ascii').lower()
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        path = parsed.path or '/'
        decoded = unquote(path)
        if '%2f' in path.lower() or '%5c' in path.lower():
            return None
        if any(segment in ('.', '..') for segment in decoded.split('/')):
            return None
        return (parsed.scheme, host, port), path
    except (ValueError, UnicodeError):
        return None


def _in_scope(url: str, scope: str) -> bool:
    target, registered = _url_key(url), _url_key(scope)
    if target is None or registered is None or target[0] != registered[0]:
        return False
    path, prefix = target[1], registered[1]
    return path == prefix or path.startswith(prefix if prefix.endswith('/') else prefix + '/')


@dataclass(frozen=True)
class InstalledApp:
    app_id: str
    app_path: Path
    profile: str
    start_url: str = field(repr=False)
    manifest_id: str | None = field(default=None, repr=False)
    scope: str | None = field(default=None, repr=False)
    _generation: tuple[int, ...] = field(default=(), repr=False)
    display_mode: str | None = None


@dataclass(frozen=True)
class RegistrarScope:
    manifest_id: str = field(repr=False)
    scope: str = field(repr=False)
    app_path: Path
    generation: tuple[int, ...] = field(repr=False)
    display_mode: str | None = None


class InstalledAppCatalog:
    def __init__(self, *, app_dirs: Iterable[Path], local_state: Path,
                 profile: str = 'Default',
                 registrar_loader: Callable[[str], str | dict] | None = None,
                 registrar_profile_verified: bool = False):
        self._registrar_loader = registrar_loader
        self._registrar_profile_verified = registrar_profile_verified
        self.app_dirs = tuple(Path(p) for p in app_dirs)
        self.local_state = Path(local_state)
        self.profile = profile
        self._registrar: dict[str, RegistrarScope] = {}

    def ingest_registrar(self, payload: str | dict, *, profile: str,
                         profile_verified: bool = False) -> int:
        """Ingest Chrome InstalledWebApps.Details, not the surrounding account data."""
        if profile != self.profile or profile_verified is not True:
            return 0
        self._registrar = {}
        try:
            data = json.loads(payload) if isinstance(payload, str) else payload
            details = data['InstalledWebApps']['Details']
        except (ValueError, KeyError, TypeError):
            return 0
        if not isinstance(details, list):
            return 0
        verified = {}
        installed = {app.app_id: app for app in self.snapshot()}
        seen: set[str] = set()
        for item in details:
            if not isinstance(item, dict):
                continue
            app_id, manifest_id, scope = item.get('!app_id'), item.get('manifest_id'), item.get('scope')
            if not isinstance(app_id, str):
                continue
            if app_id in seen:
                verified.pop(app_id, None)
                continue
            seen.add(app_id)
            if item.get('is_uninstalling') or item.get('is_from_sync_and_pending_installation'):
                continue
            if 'install_state' in item and item['install_state'] != '1':
                continue
            if 'user_display_mode' in item and item['user_display_mode'] != 'kStandalone':
                continue
            # Absent legacy metadata keeps standalone/WCO compatibility; an
            # explicit unknown mode never becomes positive registrar proof.
            if 'display_mode' in item and item['display_mode'] not in (
                    'minimal-ui', 'standalone', 'window-controls-overlay'):
                continue
            app = installed.get(app_id)
            scope_key, manifest_key = _url_key(scope), _url_key(manifest_id)
            if app is None or scope_key is None or manifest_key is None:
                continue
            parsed_scope = urlsplit(scope)
            if parsed_scope.query or parsed_scope.fragment:
                continue
            if scope_key[0] != manifest_key[0] or not _in_scope(app.start_url, scope):
                continue
            verified[app_id] = RegistrarScope(manifest_id, scope, app.app_path, app._generation, item.get('display_mode'))
        self._registrar = verified
        return len(verified)

    def ingest_filtered(self, payload: dict, *, profile_verified: bool = False) -> int:
        """Accept {profile, apps:[{app_id, manifest_id, scope, ...}]} allowlist."""
        if not isinstance(payload, dict):
            return 0
        apps = payload.get('apps', [])
        if not isinstance(apps, list):
            apps = []
        fields = ('manifest_id', 'scope', 'is_uninstalling',
                  'is_from_sync_and_pending_installation', 'install_state',
                  'user_display_mode', 'display_mode')
        details = [dict({'!app_id': app.get('app_id')},
                        **{key: app[key] for key in fields if key in app})
                   for app in apps if isinstance(app, dict)]
        return self.ingest_registrar({'InstalledWebApps': {'Details': details}},
            profile=payload.get('profile'), profile_verified=profile_verified)

    def match(self, url: str) -> InstalledApp | None:
        if self._registrar_loader and self._registrar_profile_verified is True:
            self._registrar = {}
            try:
                payload = self._registrar_loader(self.profile)
                if isinstance(payload, dict) and 'apps' in payload:
                    self.ingest_filtered(payload, profile_verified=True)
                else:
                    self.ingest_registrar(payload, profile=self.profile, profile_verified=True)
            except Exception:
                # The backend may embed account URLs in exceptions: never log them.
                self._registrar = {}
                return None
        candidates = [(len(_url_key(record.scope)[1].rstrip('/')), record)
                      for record in self.snapshot()
                      if record.scope and _in_scope(url, record.scope)]
        if not candidates:
            return None
        longest = max(length for length, _ in candidates)
        best = [record for length, record in candidates if length == longest]
        return best[0] if len(best) == 1 else None

    def revalidate(self, record: InstalledApp) -> bool:
        """Call immediately before launch; this is not an atomic Chrome launch lease."""
        return record in self.snapshot()

    def snapshot(self) -> tuple[InstalledApp, ...]:
        try:
            state = json.loads(self.local_state.read_text())
        except (OSError, ValueError, UnicodeError):
            return ()
        if not isinstance(state, dict):
            return ()
        shims = state.get('app_shims', {})
        if not isinstance(shims, dict):
            return ()
        records = []
        for root in self.app_dirs:
            for app in sorted(root.glob('*.app')):
                try:
                    plist = app / 'Contents/Info.plist'
                    stat = plist.stat()
                    generation = (stat.st_dev, stat.st_ino, stat.st_size,
                                  stat.st_mtime_ns, stat.st_ctime_ns)
                    info = plistlib.loads(plist.read_bytes())
                except (OSError, ValueError, plistlib.InvalidFileException):
                    continue
                if not isinstance(info, dict):
                    continue
                app_id = info.get('CrAppModeShortcutID')
                if not isinstance(app_id, str):
                    continue
                if info.get('CrBundleIdentifier') != 'com.google.Chrome':
                    continue
                if info.get('CrAppModeProfileDir', self.profile) != self.profile:
                    continue
                registration = shims.get(app_id)
                if not isinstance(registration, dict):
                    continue
                profiles = registration.get('installed_profiles')
                if not isinstance(profiles, list) or self.profile not in profiles:
                    continue
                if _url_key(info.get('CrAppModeShortcutURL')) is None:
                    continue
                enrichment = self._registrar.get(app_id)
                if enrichment and (enrichment.generation != generation or enrichment.app_path != app):
                    self._registrar.pop(app_id, None)
                    enrichment = None
                records.append(InstalledApp(app_id, app, self.profile,
                    info['CrAppModeShortcutURL'],
                    enrichment.manifest_id if enrichment else None,
                    enrichment.scope if enrichment else None, generation,
                    enrichment.display_mode if enrichment else None))
        present = {record.app_id for record in records}
        self._registrar = {key: value for key, value in self._registrar.items() if key in present}
        return tuple(records)
