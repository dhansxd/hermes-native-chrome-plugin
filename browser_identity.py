"""Independent macOS Chrome listener provenance. No import-time host probes.

Only the SHA-256 digest, browser UUID, Default and context ID leave this module.
PID, executable, process start and profile paths are inputs, never journal data.
Failure denies ownership; it does not launch, kill, adopt or repair anything.
"""
import asyncio
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from native import CHROME, ACTIVE_PORT, NativeFailure


async def chrome_process_inventory():
    """Read one complete process table; do not store commands or private URLs."""
    output = await _probe('/bin/ps', '-ww', '-axo', 'pid=', '-o', 'lstart=', '-o', 'command=')
    import os
    records, seen = [], set()
    for line in output.decode().splitlines():
        fields = line.strip().split(None, 6)
        if len(fields) != 7 or not fields[0].isdigit():
            raise PermissionError('incomplete browser process inventory')
        seen.add(int(fields[0]))
        # Fail conservatively even on a surviving helper or ambiguous executable.
        if 'Google Chrome' in fields[6]:
            records.append({'pid': fields[0], 'start': fields[1:6], 'command': fields[6]})
    if os.getpid() not in seen:
        raise PermissionError('incomplete browser process inventory')
    return records


async def listener_present(port):
    """A refused current-file TCP port is negative evidence, not an old WS."""
    import errno
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), .5)
    except OSError as error:
        if error.errno == errno.ECONNREFUSED:
            return False
        raise PermissionError('listener absence ambiguous') from None
    else:
        writer.close()
        await writer.wait_closed()
        return True


async def prove_previous_generation_absent(previous, *, active_port=ACTIVE_PORT,
                                           inventory=chrome_process_inventory,
                                           listener=listener_present):
    """Journal-bound absence, never reconstruct an endpoint from its UUID.

    More conservative than fingerprint inequality: ANY surviving Chrome process
    or native-file listener blocks launch, including other profiles/generations.
    An empty complete inventory on both sides of the listener check proves the
    fingerprint's process is absent without persisting PID or start-time data.
    """
    try:
        if (not isinstance(previous, dict) or set(previous) != {'fingerprint', 'uuid', 'profile', 'context_id'}
                or not re.fullmatch(r'[a-f0-9]{64}', previous['fingerprint'])
                or not re.fullmatch(r'[A-Za-z0-9_-]+', previous['uuid'])
                or previous['profile'] != 'Default' or not previous['context_id']):
            raise PermissionError('invalid prior generation')
        if await inventory():
            raise PermissionError('Chrome process still present')
        try:
            before = Path(active_port).read_text()
        except FileNotFoundError:
            before = None
        if before is not None:
            lines = before.splitlines()
            if (len(lines) != 2 or not lines[0].isdigit() or not 1 <= int(lines[0]) <= 65535
                    or not re.fullmatch(r'/devtools/browser/[A-Za-z0-9_-]+', lines[1])):
                raise PermissionError('ambiguous native endpoint file')
            if await listener(int(lines[0])):
                raise PermissionError('native listener still present')
        if await inventory():
            raise PermissionError('Chrome appeared during absence proof')
        try:
            after = Path(active_port).read_text()
        except FileNotFoundError:
            after = None
        if after != before:
            raise PermissionError('native endpoint changed during absence proof')
        return True
    except Exception:
        raise NativeFailure('journal_generation_ambiguous') from None



async def _probe(*argv):
    process = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL)
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 2)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.communicate()
        raise
    if process.returncode != 0 or len(output) > 1024 * 1024:
        raise PermissionError('browser provenance probe unavailable')
    return output


async def _read_argv(pid):
    """Read kernel argv, never reconstruct arguments from ps display text."""
    def read():
        import psutil
        try:
            process = psutil.Process(int(pid))
            started, executable = process.create_time(), process.exe()
            argv = process.cmdline()
            current = psutil.Process(int(pid))
            if (current.create_time() != started or current.exe() != executable
                    or (executable != CHROME and verify_chrome_executable(executable) is None)
                    or not process.is_running()
                    or current.create_time() != started or current.exe() != executable):
                raise PermissionError('browser process changed during argv read')
            return argv
        except (psutil.Error, OSError, ValueError):
            raise PermissionError('browser argv unavailable') from None
    return await asyncio.to_thread(read)


CHROME_CLONE_PATTERN = (r'/private/var/folders/[^/]+/[^/]+/X/com\.google\.Chrome\.code_sign_clone/'
                        r'code_sign_clone\.[A-Za-z0-9_-]+/Google Chrome\.app\.bundle/Contents/MacOS/Google Chrome')
_SIGNING_REQUIREMENT = ('anchor apple generic and identifier "com.google.Chrome" '
                        'and certificate leaf[subject.OU] = "EQHXZ8M8AV"')
_EXECUTABLE_CACHE = {}


def verify_chrome_executable(executable):
    """Runtime-only equivalence; clone naming is a filter, never authority.

    Hash the complete Mach-O (not merely CDHash), verify signatures and Apple's
    Google requirement on both files, and compare signing identity. Cache only
    unchanged device/inode/size/mtime/ctime/mode/owner pairs; no journal paths.
    """
    import os
    import stat
    import subprocess
    if not isinstance(executable, str) or not re.fullmatch(CHROME_CLONE_PATTERN, executable):
        return None
    paths = (CHROME, executable)
    def stamps():
        result = []
        for path in paths:
            item = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(item.st_mode):
                raise ValueError('not a regular executable')
            result.append((item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
                           item.st_ctime_ns, item.st_mode, item.st_uid, item.st_gid))
        return tuple(result)
    try:
        before = stamps()
        key = (paths, before)
        cached = _EXECUTABLE_CACHE.get(key)
        if cached is not None:
            return dict(cached) if stamps() == before else None
        digests, signatures = [], []
        for path in paths:
            with open(path, 'rb') as source:
                if source.read(4) not in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                                          b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                                          b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
                    return None
                source.seek(0)
                digests.append(hashlib.file_digest(source, 'sha256').hexdigest())
            verified = subprocess.run(['/usr/bin/codesign', '--verify', '--strict',
                '-R=' + _SIGNING_REQUIREMENT, path], capture_output=True, text=True, timeout=2)
            if verified.returncode:
                return None
            displayed = subprocess.run(['/usr/bin/codesign', '-d', '--verbose=4', path],
                                       capture_output=True, text=True, timeout=2)
            if displayed.returncode or len(displayed.stderr) > 65536:
                return None
            values = {}
            for name in ('Identifier', 'TeamIdentifier', 'CDHash'):
                matches = re.findall(r'^' + name + r'=(.+)$', displayed.stderr, re.MULTILINE)
                if len(matches) != 1:
                    return None
                values[name] = matches[0]
            authorities = tuple(re.findall(r'^Authority=(.+)$', displayed.stderr, re.MULTILINE))
            if (values['Identifier'] != 'com.google.Chrome' or values['TeamIdentifier'] != 'EQHXZ8M8AV'
                    or not re.fullmatch(r'[a-f0-9]{40}', values['CDHash']) or not authorities):
                return None
            signatures.append((values, authorities))
        if digests[0] != digests[1] or signatures[0] != signatures[1] or stamps() != before:
            return None
        result = {'original_exe': CHROME, 'sha256': digests[0], 'identifier': 'com.google.Chrome',
                  'team': 'EQHXZ8M8AV', 'cdhash': signatures[0][0]['CDHash']}
        # Bound retention, including retired clone paths; cache never grants by path.
        if len(_EXECUTABLE_CACHE) >= 16:
            _EXECUTABLE_CACHE.clear()
        _EXECUTABLE_CACHE[key] = dict(result)
        return result
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def verified_main_host(host):
    """Do not trust caller-supplied provenance: reverify it against both files."""
    if not isinstance(host, dict) or host.get('bundle') != 'com.google.Chrome':
        return False
    if host.get('exe') == CHROME and 'mapped_exe' not in host:
        return 'provenance' not in host
    if 'mapped_exe' in host and host.get('exe') != CHROME:
        return False
    provenance = verify_chrome_executable(host.get('mapped_exe', host.get('exe')))
    return provenance is not None and host.get('provenance') == provenance


async def _read_host(pid):
    """Kernel start/exe identity for an exact main listener, not an AX title."""
    def read():
        import psutil
        process = psutil.Process(int(pid))
        started, executable = process.create_time(), process.exe()
        provenance = verify_chrome_executable(executable) if executable != CHROME else None
        if executable != CHROME and provenance is None:
            raise AttachIdentityFailure('host-executable-mismatch')
        if not process.is_running():
            raise AttachIdentityFailure('host-process-unavailable')
        current = psutil.Process(int(pid))
        if current.create_time() != started or current.exe() != executable:
            raise AttachIdentityFailure('host-changed')
        return {'pid': int(pid), 'started': started, 'exe': executable,
                'bundle': 'com.google.Chrome',
                **({'provenance': provenance} if provenance else {})}
    return await asyncio.to_thread(read)


ATTACH_PROOF_REASONS = frozenset({
    'endpoint-invalid', 'endpoint-changed', 'listener-unavailable', 'listener-ambiguous',
    'host-unavailable', 'host-invalid', 'host-executable-mismatch', 'host-process-unavailable', 'listener-executable-unavailable',
    'listener-executable-missing', 'listener-executable-mismatch', 'process-unavailable',
    'process-invalid', 'argv-unavailable', 'argv-invalid', 'profile-ambiguous',
    'profile-rejected', 'listener-changed', 'process-changed', 'host-changed',
    'proof-unavailable', 'readiness-deadline', 'readiness-changed', 'no-main-ax-window'})


class AttachIdentityFailure(PermissionError):
    """Fixed safe reason; optional runtime-only independent readiness witness."""
    def __init__(self, reason, *, readiness_proof=None):
        self.reason = reason if reason in ATTACH_PROOF_REASONS else 'proof-unavailable'
        self.readiness_proof = readiness_proof
        super().__init__(self.reason)


async def _prove_listener(endpoint, *, probe=_probe, read_argv=_read_argv, read_host=None, active_port=None):
    active_port = Path(active_port) if active_port is not None else ACTIVE_PORT
    reason = 'endpoint-invalid'
    try:
        parsed = urlsplit(endpoint['url'])
        if (parsed.scheme != 'ws' or parsed.hostname != '127.0.0.1' or parsed.query or parsed.fragment
                or parsed.username or parsed.password or not parsed.port
                or not re.fullmatch(r'/devtools/browser/[A-Za-z0-9_-]+', parsed.path)):
            raise PermissionError('unverified browser endpoint')
        expected = f'{parsed.port}\n{parsed.path}'
        reason = 'endpoint-changed'
        if active_port.read_text().strip() != expected:
            raise PermissionError('browser endpoint changed')
        listener_args = ('/usr/sbin/lsof', '-nP', '-iTCP:' + str(parsed.port), '-sTCP:LISTEN', '-Fpc')
        reason = 'listener-unavailable'
        listener = (await probe(*listener_args)).decode().splitlines()
        pids = {line[1:] for line in listener if line.startswith('p')}
        if len(pids) != 1 or not next(iter(pids)).isdigit():
            raise AttachIdentityFailure('listener-ambiguous')
        pid = next(iter(pids))
        reason = 'host-unavailable'
        host = await read_host(pid) if read_host else None
        if host is not None and (host.get('pid') != int(pid) or not verified_main_host(host)
                or host.get('bundle') != 'com.google.Chrome'
                or not isinstance(host.get('started'), (int, float))):
            raise AttachIdentityFailure('host-invalid')
        reason = 'listener-executable-unavailable'
        files = (await probe('/usr/sbin/lsof', '-a', '-p', pid, '-d', 'txt', '-Fnf')).decode().splitlines()
        executables = [line[1:] for line in files if line.startswith('n')]
        # macOS txt also includes these auxiliary mapped data files. Their
        # early publication is not evidence of a foreign executable. Unknown
        # non-Chrome names remain fail-closed; only an independently rechecked
        # kernel/argv/start/listener witness may authorize a readiness retry.
        auxiliary_txt = (r'(?:/private/var/db/diagnostics/logd/\.plist-cache\.[^/]+'
                         r'|/System/Library/CoreServices/SystemVersion\.bundle/'
                         r'[^/]+\.lproj/SystemVersion\.strings)')
        # When the kernel reports a clone, require that exact verified path in
        # both mappings. In journal-only proofs obtain the same kernel witness
        # only when original-path mapping is absent (legacy canonical path).
        if host is None and CHROME not in executables:
            host = await _read_host(pid)
            if not verified_main_host(host):
                raise AttachIdentityFailure('host-invalid')
        actual_exe = host['exe'] if host is not None else CHROME
        # proc_pidpath may still report original while lsof exposes the clone.
        # Never use basename matching: one exact signed+hashed mapped candidate.
        mapped_provenance = None
        if actual_exe == CHROME and CHROME not in executables:
            candidates = [name for name in executables if re.fullmatch(CHROME_CLONE_PATTERN, name)]
            if len(candidates) == 1:
                mapped_provenance = await asyncio.to_thread(verify_chrome_executable, candidates[0])
                if mapped_provenance is not None:
                    actual_exe = candidates[0]
        missing_executable = actual_exe not in executables
        if missing_executable and not (host is not None and
                all(re.fullmatch(auxiliary_txt, name) for name in executables)):
            raise AttachIdentityFailure('listener-executable-missing' if not executables else 'listener-executable-mismatch')
        reason = 'process-unavailable'
        process = (await probe('/bin/ps', '-p', pid, '-o', 'pid=', '-o', 'lstart=', '-o', 'command=')).decode().strip()
        fields = process.split(None, 6)
        if len(fields) != 7 or fields[0] != pid or not fields[6].startswith(CHROME):
            raise AttachIdentityFailure('process-invalid')
        reason = 'argv-unavailable'
        argv = await read_argv(pid)
        if (not isinstance(argv, (list, tuple)) or not argv or argv[0] != CHROME
                or any(not isinstance(arg, str) or '\x00' in arg for arg in argv)):
            raise AttachIdentityFailure('argv-invalid')
        flags = argv[1:]
        allowed = {'--user-data-dir': str(active_port.parent), '--profile-directory': 'Default'}
        seen = set()
        index = 0
        while index < len(flags):
            flag = flags[index]
            for name, expected_value in allowed.items():
                if flag.startswith(name):
                    if name in seen:
                        raise AttachIdentityFailure('profile-ambiguous')
                    seen.add(name)
                    if flag == name:
                        index += 1
                        value = flags[index] if index < len(flags) else None
                    elif flag.startswith(name + '='):
                        value = flag[len(name) + 1:]
                    else:
                        value = None
                    if value != expected_value:
                        raise AttachIdentityFailure('profile-rejected')
                    break
            index += 1
        # Main-process absence of --profile-directory is Chrome's original
        # Default mapping. A profile marker must separately prove the live
        # browserContextId; no URL participates in this fingerprint.
        reason = 'listener-changed'
        second = (await probe(*listener_args)).decode().splitlines()
        if {line[1:] for line in second if line.startswith('p')} != {pid} or active_port.read_text().strip() != expected:
            raise AttachIdentityFailure('listener-changed')
        reason = 'listener-executable-unavailable'
        current_files = (await probe('/usr/sbin/lsof', '-a', '-p', pid, '-d', 'txt', '-Fnf')).decode().splitlines()
        current_executables = [line[1:] for line in current_files if line.startswith('n')]
        if actual_exe not in current_executables and not (host is not None and
                all(re.fullmatch(auxiliary_txt, name) for name in current_executables)):
            raise AttachIdentityFailure('listener-executable-mismatch')
        missing_executable = missing_executable or actual_exe not in current_executables
        if (mapped_provenance is not None and
                await asyncio.to_thread(verify_chrome_executable, actual_exe) != mapped_provenance):
            raise AttachIdentityFailure('listener-executable-mismatch')
        reason = 'process-changed'
        current_process = (await probe('/bin/ps', '-p', pid, '-o', 'pid=', '-o', 'lstart=', '-o', 'command=')).decode().strip().split(None, 6)
        if (len(current_process) != 7 or current_process[:6] != fields[:6]
                or not current_process[6].startswith(CHROME) or await read_argv(pid) != argv):
            raise AttachIdentityFailure('process-changed')
        reason = 'host-changed'
        if host is not None and await (read_host or _read_host)(pid) != host:
            raise AttachIdentityFailure('host-changed')
        reason = 'listener-changed'
        final_listener = (await probe(*listener_args)).decode().splitlines()
        if ({line[1:] for line in final_listener if line.startswith('p')} != {pid}
                or active_port.read_text().strip() != expected):
            raise AttachIdentityFailure('listener-changed')
        fingerprint = hashlib.sha256(json.dumps([pid, fields[1:6], CHROME,
            str(active_port.parent), 'Default'], separators=(',', ':')).encode()).hexdigest()
        if mapped_provenance is not None:
            host = {**host, 'mapped_exe': actual_exe, 'provenance': mapped_provenance}
        proof = {'fingerprint': fingerprint, 'uuid': parsed.path.rsplit('/', 1)[1],
                 'profile': 'Default', **({'host': host} if read_host else {})}
        if missing_executable:
            # Never confer authority from a partial proof. Retry only with exact
            # kernel host, argv/profile, ps start and listener stable on both sides.
            raise AttachIdentityFailure('listener-executable-missing',
                readiness_proof=proof if read_host else None)
        return proof
    except AttachIdentityFailure:
        raise
    except (OSError, ValueError, UnicodeError, IndexError, KeyError):
        raise AttachIdentityFailure(reason) from None


async def prove_attach_identity(endpoint, *, probe=_probe, read_argv=_read_argv,
                                read_host=_read_host, active_port=None):
    # Endpoint/listener/Default mapping only. This is NOT a browserContextId proof.
    return await _prove_listener(endpoint, probe=probe, read_argv=read_argv,
                                 read_host=read_host, active_port=active_port)


async def prove_browser_identity(endpoint, context_id, *, probe=_probe, read_argv=_read_argv, active_port=None):
    if not context_id:
        raise PermissionError('unverified browser context')
    proof = await _prove_listener(endpoint, probe=probe, read_argv=read_argv, active_port=active_port)
    return {**proof, 'context_id': context_id}
