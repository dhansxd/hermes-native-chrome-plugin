"""Exact Chrome consent approval; caller owns the bounded handshake."""
import json
import plistlib
import subprocess
from pathlib import Path
PAIRS={('Allow remote debugging?','Allow'),('Izinkan proses debug jarak jauh?','Izinkan')}
CHROME='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
def matches(sheet,button):
    return (sheet,button) in PAIRS
def button_for_dialog(name,headings):
    labels={name} if name in dict(PAIRS) else set()
    labels.update(h for h in headings if h in dict(PAIRS))
    return dict(PAIRS)[next(iter(labels))] if len(labels)==1 else None
def verify_host(executable):
    p=Path(executable).resolve()
    if str(p)==CHROME:return 'com.google.Chrome'
    from browser_identity import verify_chrome_executable
    if verify_chrome_executable(executable) is not None:return 'com.google.Chrome'
    if p.name!='app_mode_loader' or p.parent.name!='MacOS' or p.parent.parent.name!='Contents':return None
    app=p.parents[2]
    if app.suffix!='.app':return None
    try:d=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    except (OSError,ValueError,plistlib.InvalidFileException):return None
    ident=d.get('CrAppModeShortcutID');bundle=d.get('CFBundleIdentifier')
    if not isinstance(ident,str) or not ident or d.get('CrBundleIdentifier')!='com.google.Chrome':return None
    return bundle if bundle=='com.google.Chrome.app.'+ident else None
def hosts():
    import psutil
    result=[]
    for p in psutil.process_iter(['pid','name','exe','create_time']):
        try:
            if p.info['name'] not in {'Google Chrome','app_mode_loader'}:continue
            exe=p.info['exe'];bundle=verify_host(exe)
            if bundle:
                host={'pid':p.pid,'exe':exe,'bundle':bundle,'started':p.info['create_time']}
                if bundle=='com.google.Chrome' and exe!=CHROME:
                    from browser_identity import verify_chrome_executable
                    provenance=verify_chrome_executable(exe)
                    if provenance is None:continue
                    host['provenance']=provenance
                result.append(host)
        except (psutil.Error,OSError,ValueError):continue
    return result
def host_still_valid(host):
    import psutil
    try:
        p=psutil.Process(host['pid'])
        if p.create_time()!=host['started'] or p.exe()!=host['exe']:return False
        if host.get('bundle')=='com.google.Chrome' and (host.get('exe')!=CHROME or 'mapped_exe' in host):
            from browser_identity import verified_main_host
            if not verified_main_host(host):return False
        return verify_host(p.exe())==host['bundle'] and p.create_time()==host['started'] and p.exe()==host['exe']
    except (psutil.Error,OSError,ValueError):return False
SCRIPT=r'''on headings(n, depth)
 if depth > 16 then return {}
 set labels to {}
 tell application "System Events"
  try
   if (role of n as text) is "AXHeading" then set end of labels to name of n as text
  end try
  try
   repeat with x in UI elements of n
    set labels to labels & my headings(x, depth + 1)
   end repeat
  end try
 end tell
 return labels
end headings
on clickButton(n, wanted, depth, hostPid, expectedBundle)
 if depth > 16 then return false
 tell application "System Events"
  try
   if (role of n as text) is "AXButton" and (description of n as text) is wanted then
    set p to first application process whose unix id is hostPid
    if (unix id of p) is not hostPid then return false
    if (bundle identifier of p as text) is not expectedBundle then return false
    perform action "AXPress" of n
    return true
   end if
  end try
  try
   repeat with x in UI elements of n
    if my clickButton(x, wanted, depth + 1, hostPid, expectedBundle) then return true
   end repeat
  end try
 end tell
 return false
end clickButton
on run argv
 set hostPid to item 1 of argv as integer
 set expectedBundle to item 2 of argv
 tell application "System Events"
  try
   set p to first application process whose unix id is hostPid
   if (unix id of p) is not hostPid then return "stale-host"
   if (bundle identifier of p as text) is not expectedBundle then return "stale-host"
   repeat with w in windows of p
    try
     repeat with s in sheets of w
      set labelText to ""
      try
       set labelText to name of s as text
      end try
      set seenEnglish to labelText is "Allow remote debugging?"
      set seenIndonesian to labelText is "Izinkan proses debug jarak jauh?"
      set hs to my headings(s, 0)
      if hs contains "Allow remote debugging?" then set seenEnglish to true
      if hs contains "Izinkan proses debug jarak jauh?" then set seenIndonesian to true
      set wanted to ""
      if seenEnglish and not seenIndonesian then set wanted to "Allow"
      if seenIndonesian and not seenEnglish then set wanted to "Izinkan"
      if wanted is not "" then
       if my clickButton(s, wanted, 0, hostPid, expectedBundle) then return "clicked"
      end if
     end repeat
    end try
   end repeat
  on error e number n
   if n is -1719 or n is -1743 then error e number n
  end try
 end tell
 return "not-found"
end run
'''
def approve_host(host,*,runner=None):
    if not host_still_valid(host):return 'stale-host'
    runner=runner or subprocess.run
    p=runner(['osascript','-e',SCRIPT,str(host['pid']),host['bundle']],text=True,capture_output=True,timeout=6)
    if p.returncode:raise RuntimeError('Chrome Accessibility approval failed: '+p.stderr.strip())
    result=p.stdout.strip()
    if result not in {'clicked','not-found','stale-host'}:raise RuntimeError('Unexpected consent helper result')
    return result
def approve_once():
    for host in hosts():
        result=approve_host(host)
        if result=='clicked':
            print(json.dumps({'event':'debug_consent_clicked','host_pid':host['pid'],'host_kind':'chrome' if host['bundle']=='com.google.Chrome' else 'chrome-app'}),flush=True)
            return result
    return 'not-found'
RAISE_MAIN_SCRIPT = r'''on run argv
 set hostPid to item 1 of argv as integer
 set expectedBundle to item 2 of argv
 tell application "System Events"
  set p to first application process whose unix id is hostPid
  if (unix id of p) is not hostPid then return "stale-host"
  if (bundle identifier of p as text) is not expectedBundle then return "stale-host"
  repeat with w in windows of p
   if (role of w as text) is "AXWindow" and (subrole of w as text) is "AXStandardWindow" then
    if (unix id of p) is not hostPid then return "stale-host"
    if (bundle identifier of p as text) is not expectedBundle then return "stale-host"
    perform action "AXRaise" of w
    set frontmost of p to true
    return "raised"
   end if
  end repeat
 end tell
 return "not-found"
end run
'''


def pending_host_valid(host, pending):
    # Enumeration/host_still_valid verifies exact Chrome or installed shim.
    return (pending() and host_still_valid(host)
            and (host.get('bundle') == 'com.google.Chrome'
                 or str(host.get('bundle', '')).startswith('com.google.Chrome.app.')))


async def _run_pending_ax(script, host, pending):
    # No detached to_thread subprocess may outlive the original handshake.
    # Only this helper child is canceled; never terminate any Chrome process.
    import asyncio
    authority = getattr(pending, '__self__', None)
    operation = 'approve' if script == SCRIPT else 'raise' if script == RAISE_MAIN_SCRIPT else 'probe'
    def record(phase, **fields):
        if authority is not None and hasattr(authority, 'record'):
            authority.record(phase, operation=operation, host_kind='main' if host.get('bundle') == 'com.google.Chrome' else 'pwa', **fields)
    if not pending_host_valid(host, pending):
        record('ax_host_check', result='stale-host', reason='pending-ended' if not pending() else 'host-invalid')
        return 'stale-host'
    record('ax_host_check', result='valid')
    record('ax_spawn')
    # Start an inert stdin reader, then deliver the script only after spawn
    # and another fence. Shield spawn so cancellation still drains its child.
    spawning = asyncio.create_task(asyncio.create_subprocess_exec('osascript', '-',
        str(host['pid']), host['bundle'], stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE))
    try:
        process = await asyncio.shield(spawning)
        record('ax_spawned')
    except asyncio.CancelledError:
        record('ax_cancelled', reason='spawn-cancelled')
        process = await spawning
        if process.returncode is None:
            process.kill()
        await process.wait()
        record('ax_reaped')
        raise
    communicating = None
    try:
        if not pending_host_valid(host, pending):
            record('ax_host_check', result='stale-host', reason='pending-ended' if not pending() else 'host-invalid')
            return 'stale-host'
        async def communicate():
            # Submission is distinct from completed stdin delivery/child result.
            record('ax_script_submitted')
            response = await process.communicate(script.encode())
            # Successful child exit is evidence that the stdin-reader consumed
            # the script; cancellation/kill must not manufacture delivery proof.
            if process.returncode == 0:
                record('ax_script_delivered')
            return response
        communicating = asyncio.create_task(communicate())
        until = asyncio.get_running_loop().time() + 2
        while not communicating.done():
            if not pending() or asyncio.get_running_loop().time() >= until:
                record('ax_deadline', result='stale-host', reason='pending-ended' if not pending() else 'helper-deadline')
                return 'stale-host'
            await asyncio.wait({communicating}, timeout=.02)
        output, _ = await communicating
        if not pending_host_valid(host, pending):
            record('ax_result', result='stale-host', reason='pending-ended' if not pending() else 'host-invalid')
            return 'stale-host'
        if process.returncode:
            record('ax_result', result='failed', reason='nonzero-exit')
            raise RuntimeError('Scoped Chrome AX helper failed')
        result = output.decode().strip()
        # Script host mismatch differs from cancellation/helper deadline fences.
        if result == 'stale-host' and script == SCRIPT:
            return 'host-mismatch'
        if result not in {'clicked', 'raised', 'not-found', 'stale-host'}:
            record('ax_result', result='unexpected', reason='invalid-output')
            raise RuntimeError('Unexpected scoped Chrome AX result')
        record('ax_result', result=result)
        return result
    except asyncio.CancelledError:
        record('ax_cancelled', reason='cancelled')
        raise
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        if communicating is not None:
            await asyncio.gather(communicating, return_exceptions=True)
        record('ax_reaped')


async def approve_pending(host, pending, *, runner=None):
    if not pending_host_valid(host, pending):
        return 'stale-host'
    seen = set()
    for candidate in [host, *hosts()]:
        if candidate['pid'] in seen:
            continue
        seen.add(candidate['pid'])
        if not pending_host_valid(candidate, pending):
            continue
        result = await (runner or _run_pending_ax)(SCRIPT, candidate, pending)
        if result == 'host-mismatch':
            if candidate['pid'] == host['pid']:
                return 'stale-host'
            continue
        if result in {'clicked', 'stale-host'}:
            # A fenced/timed-out helper is not evidence of an absent dialog.
            return result
        if not pending():
            return 'stale-host'
    return 'not-found'


async def raise_pending_main(host, pending, *, runner=None):
    from browser_identity import verified_main_host
    if not verified_main_host(host) or not pending_host_valid(host, pending):
        return 'stale-host'
    return await (runner or _run_pending_ax)(RAISE_MAIN_SCRIPT, host, pending)


if __name__=='__main__':print(approve_once())
