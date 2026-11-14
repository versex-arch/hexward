"""System audit: persistence, security settings, live processes, hosts file.

Windows gets the full treatment; other platforms currently get the hosts check
(the log, scan, network and AI modules are fully cross-platform).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .core import IS_WINDOWS, Finding, Severity, run_cmd
from .heuristics import score_text

if IS_WINDOWS:
    import winreg

_RE_TEMP_PATH = re.compile(
    r"\\(?:temp|tmp)\\|\\users\\public\\|\\\$recycle\.bin\\|\\downloads\\|"
    r"\\programdata\\[^\\]+\.(?:exe|bat|cmd|vbs|js|ps1|scr)|\\appdata\\roaming\\[^\\]+\.(?:exe|scr|bat|vbs|js)",
    re.I)
_RE_SCRIPT_HOST = re.compile(r"(?:^|[\\\"\s])(?:wscript|cscript|mshta|powershell|pwsh)(?:\.exe)?[\"\s]", re.I)

RUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
]


def judge_command(cmd: str) -> tuple[Severity | None, list[str]]:
    """Rate an autostart / task / process command line."""
    score, why = score_text(cmd)
    if _RE_TEMP_PATH.search(cmd):
        score += 3
        why.append("runs from a user-writable drop location")
    if score >= 3:
        return Severity.HIGH, why
    if _RE_SCRIPT_HOST.search(cmd + " "):
        return Severity.MEDIUM, why + ["launches a script interpreter"]
    return None, why


def _reg_values(root, path: str, view: int = 0):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    return
                yield name, value
                i += 1
    except OSError:
        return


def _reg_get(root, path: str, name: str, view: int = 0):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def autoruns() -> dict[str, str]:
    """All Run-key autostart entries as {location\\name: command}."""
    if not IS_WINDOWS:
        return {}
    out: dict[str, str] = {}
    hives = [("HKCU", winreg.HKEY_CURRENT_USER, 0),
             ("HKLM", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
             ("HKLM32", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)]
    for label, root, view in hives:
        for key in RUN_KEYS:
            for name, value in _reg_values(root, key, view):
                out[f"{label}\\{key}\\{name}"] = str(value)
    return out


def startup_dirs() -> list[Path]:
    if not IS_WINDOWS:
        return [p for p in (Path.home() / ".config/autostart", Path.home() / "Library/LaunchAgents")
                if p.is_dir()]
    rel = "Microsoft/Windows/Start Menu/Programs/Startup"
    dirs = [Path(os.environ.get("APPDATA", "")) / rel, Path(os.environ.get("PROGRAMDATA", "")) / rel]
    return [d for d in dirs if d.is_dir()]


def hosts_path() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"
    return Path("/etc/hosts")


_RE_SECURITY_DOMAIN = re.compile(
    r"microsoft|windowsupdate|kaspersky|avast|avg\.|eset|bitdefender|malwarebytes|symantec|norton|"
    r"mcafee|sophos|drweb|virustotal|trendmicro|f-secure|comodo|emsisoft", re.I)


def audit_hosts() -> list[Finding]:
    try:
        text = hosts_path().read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    blocked, other = [], []
    for line in text.splitlines():
        parts = line.split("#")[0].split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        for name in names:
            if name.lower() in ("localhost", "localhost.localdomain", "broadcasthost",
                                "ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters"):
                continue
            (blocked if _RE_SECURITY_DOMAIN.search(name) else other).append(f"{ip} {name}")
    out = []
    if blocked:
        out.append(Finding("hosts-security-redirect", Severity.HIGH,
                           "hosts file redirects security/update domains", str(hosts_path()),
                           blocked[:10], "Malware does this to block updates. Remove the entries."))
    if other:
        out.append(Finding("hosts-custom-entries", Severity.INFO,
                           f"hosts file has {len(other)} custom entr{'y' if len(other) == 1 else 'ies'}",
                           str(hosts_path()), other[:8]))
    return out


# ------------------------------------------------------------ Windows only

def _audit_persistence() -> list[Finding]:
    out = []
    for where, cmd in autoruns().items():
        sev, why = judge_command(cmd)
        if sev:
            out.append(Finding("autorun-suspicious", sev, "Suspicious autostart entry", where,
                               [cmd] + why, "If you do not recognise it, remove the value and scan the file."))
    for d in startup_dirs():
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for f in entries:
            if f.suffix.lower() in (".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".ps1", ".hta",
                                    ".wsf", ".scr", ".pif"):
                out.append(Finding("startup-script", Severity.MEDIUM,
                                   "Script in the Startup folder runs at every logon", str(f)))

    hklm, v64 = winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY
    winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    shell = _reg_get(hklm, winlogon, "Shell", v64)
    if shell is not None and str(shell).strip().lower() != "explorer.exe":
        out.append(Finding("winlogon-shell", Severity.HIGH, "Winlogon Shell was replaced",
                           winlogon, [str(shell)], "Expected value: explorer.exe"))
    userinit = _reg_get(hklm, winlogon, "Userinit", v64)
    if userinit is not None:
        parts = [p.strip().lower() for p in str(userinit).split(",") if p.strip()]
        if any(not p.endswith("\\system32\\userinit.exe") for p in parts):
            out.append(Finding("winlogon-userinit", Severity.HIGH, "Winlogon Userinit runs extra programs",
                               winlogon, [str(userinit)]))

    ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for exe in ("sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe",
                "displayswitch.exe", "atbroker.exe"):
        dbg = _reg_get(hklm, f"{ifeo}\\{exe}", "Debugger", v64)
        if dbg:
            out.append(Finding("ifeo-backdoor", Severity.CRITICAL,
                               f"Accessibility backdoor: {exe} is hijacked on the logon screen",
                               f"HKLM\\{ifeo}\\{exe}", [str(dbg)],
                               "Delete the Debugger value; assume someone had admin access."))
    appinit = _reg_get(hklm, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", v64)
    if appinit and str(appinit).strip():
        out.append(Finding("appinit-dlls", Severity.HIGH, "AppInit_DLLs injects a DLL into every GUI process",
                           "HKLM AppInit_DLLs", [str(appinit)]))
    return out


def _audit_settings() -> list[Finding]:
    out = []
    hklm, v64 = winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY
    pol = r"SOFTWARE\Policies\Microsoft\Windows Defender"
    if _reg_get(hklm, pol, "DisableAntiSpyware", v64) == 1:
        out.append(Finding("defender-disabled", Severity.HIGH, "Microsoft Defender is disabled by policy", pol))
    for base in (pol, r"SOFTWARE\Microsoft\Windows Defender"):
        if _reg_get(hklm, base + r"\Real-Time Protection", "DisableRealtimeMonitoring", v64) == 1:
            out.append(Finding("defender-realtime-off", Severity.HIGH,
                               "Defender real-time protection is turned off", base,
                               advice="Turn it back on unless another antivirus is active."))
            break
    excl = [name for name, _ in _reg_values(hklm, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", v64)]
    risky = [e for e in excl if _RE_TEMP_PATH.search(e + "\\") or re.fullmatch(r"[A-Za-z]:\\?", e)]
    if risky:
        out.append(Finding("defender-exclusions", Severity.HIGH,
                           "Defender ignores drop locations or a whole drive", "Defender exclusions", risky[:10],
                           "Malware adds such exclusions to hide. Remove any you did not create."))
    fw = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    off = [p for p in ("DomainProfile", "StandardProfile", "PublicProfile")
           if _reg_get(hklm, f"{fw}\\{p}", "EnableFirewall") == 0]
    if off:
        out.append(Finding("firewall-off", Severity.HIGH, "Windows Firewall is off", ", ".join(off)))
    if _reg_get(hklm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", v64) == 0:
        out.append(Finding("uac-off", Severity.HIGH, "User Account Control (UAC) is disabled"))
    if _reg_get(hklm, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") == 0:
        out.append(Finding("rdp-enabled", Severity.LOW, "Remote Desktop is enabled",
                           advice="Fine if intended; never expose port 3389 to the internet directly."))
    return out


def protection_status() -> dict:
    """Cheap registry-only view of the OS protections; None means unknown."""
    if not IS_WINDOWS:
        return {"defender": None, "firewall": None}
    hklm, v64 = winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY
    pol, wd = r"SOFTWARE\Policies\Microsoft\Windows Defender", r"SOFTWARE\Microsoft\Windows Defender"
    rt = r"\Real-Time Protection"
    defender = not (_reg_get(hklm, pol, "DisableAntiSpyware", v64) == 1
                    or _reg_get(hklm, pol + rt, "DisableRealtimeMonitoring", v64) == 1
                    or _reg_get(hklm, wd + rt, "DisableRealtimeMonitoring", v64) == 1)
    fw = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    firewall = all(_reg_get(hklm, fw + "\\" + p, "EnableFirewall") != 0 for p in ("StandardProfile", "PublicProfile"))
    return {"defender": defender, "firewall": firewall}


_PS_QUERY = (
    "$ErrorActionPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    "$p=@(Get-CimInstance Win32_Process|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine);"
    "$t=@(Get-ScheduledTask|ForEach-Object{[pscustomobject]@{Path=$_.TaskPath+$_.TaskName;"
    "State=[string]$_.State;Actions=(@($_.Actions|ForEach-Object{$_.Execute+' '+$_.Arguments}) -join ' ;; ')}});"
    "@{processes=$p;tasks=$t}|ConvertTo-Json -Depth 4 -Compress"
)

_SYSTEM_PROCS = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
                 "wininit.exe", "spoolsv.exe", "dwm.exe", "taskhostw.exe", "conhost.exe", "explorer.exe",
                 "runtimebroker.exe", "sihost.exe", "fontdrvhost.exe"}
_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe",
           "acrord32.exe", "acrobat.exe", "mspub.exe"}
_SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
           "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}


def _audit_live() -> list[Finding]:
    raw = run_cmd(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_QUERY], timeout=90)
    try:
        data = json.loads(raw) if raw else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return [Finding("live-unavailable", Severity.INFO,
                        "Could not enumerate processes and scheduled tasks (PowerShell blocked or timed out)")]
    out = []
    windir = os.environ.get("SystemRoot", r"C:\Windows").lower() + "\\"
    procs = [p for p in (data.get("processes") or []) if isinstance(p, dict)]
    by_pid = {p.get("ProcessId"): p for p in procs}
    me = os.getpid()
    for p in procs:
        name = str(p.get("Name") or "").lower()
        path = str(p.get("ExecutablePath") or "")
        if path.startswith(("\\\\?\\", "\\??\\")):  # NT namespace prefix
            path = path[4:]
        cmd = str(p.get("CommandLine") or "")
        pid = p.get("ProcessId")
        target = f"{name} (pid {pid})"
        if pid == me or _PS_QUERY[:40] in cmd:
            continue
        if name in _SYSTEM_PROCS and path and not path.lower().startswith(windir):
            out.append(Finding("proc-masquerade", Severity.HIGH,
                               "Process uses a Windows system name but runs from another folder",
                               target, [path], "Scan the file; genuine copies live under C:\\Windows."))
            continue
        parent = by_pid.get(p.get("ParentProcessId")) or {}
        pname = str(parent.get("Name") or "").lower()
        if name in _SHELLS and pname in _OFFICE:
            out.append(Finding("proc-office-shell", Severity.HIGH,
                               f"{pname} spawned {name} - typical for malicious documents", target, [cmd]))
            continue
        score, why = score_text(cmd)
        if score >= 3:
            out.append(Finding("proc-cmdline", Severity.HIGH, "Process with a malicious-looking command line",
                               target, [cmd] + why))
        elif path and _RE_TEMP_PATH.search(path):
            out.append(Finding("proc-temp", Severity.LOW, "Process running from a temp/download folder",
                               target, [path], "Normal for installers and updaters; suspicious otherwise."))
    for t in data.get("tasks") or []:
        if not isinstance(t, dict):
            continue
        actions = str(t.get("Actions") or "")
        sev, why = judge_command(actions)
        if sev is None or t.get("State") == "Disabled":
            continue
        if sev < Severity.HIGH and str(t.get("Path", "")).startswith("\\Microsoft\\"):
            continue
        out.append(Finding("task-suspicious", sev, "Suspicious scheduled task", str(t.get("Path")),
                           [actions] + why))
    return out


def audit_system() -> list[Finding]:
    findings = audit_hosts()
    if IS_WINDOWS:
        for part in (_audit_persistence, _audit_settings, _audit_live):
            try:
                findings += part()
            except Exception as exc:  # one broken probe must not hide the others
                findings.append(Finding("audit-error", Severity.INFO,
                                        f"{part.__name__} failed: {type(exc).__name__}: {exc}"))
    return findings
