"""Windows Event Log analysis through the built-in wevtutil (no dependencies)."""

from __future__ import annotations

import re

from .core import IS_WINDOWS, Finding, Severity, run_cmd

_RE_EVENT_ID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_RE_DATA = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]\s*>([^<]*)</Data>")

# event id -> (severity, title)
_NOTABLE = {
    1102: (Severity.HIGH, "Security audit log was cleared"),
    4720: (Severity.MEDIUM, "Local user account created"),
    4732: (Severity.MEDIUM, "Member added to a security-enabled local group"),
    4698: (Severity.LOW, "Scheduled task created"),
    4740: (Severity.MEDIUM, "User account locked out"),
}


def _query(log: str, ids: list[int], hours: int, max_events: int) -> list[tuple[int, dict]] | None:
    id_expr = " or ".join(f"EventID={i}" for i in ids)
    xpath = f"*[System[({id_expr}) and TimeCreated[timediff(@SystemTime) <= {hours * 3600 * 1000}]]]"
    out = run_cmd(["wevtutil", "qe", log, f"/q:{xpath}", f"/c:{max_events}", "/rd:true", "/f:xml"],
                  timeout=120)
    if out is None:
        return None
    events = []
    for chunk in out.split("</Event>"):
        m = _RE_EVENT_ID.search(chunk)
        if m:
            events.append((int(m.group(1)), dict(_RE_DATA.findall(chunk))))
    return events


def analyze_windows_events(hours: int = 24, threshold: int = 5, max_events: int = 20000) -> list[Finding]:
    if not IS_WINDOWS:
        return [Finding("winlog-unsupported", Severity.INFO, "Windows event log analysis needs Windows")]
    findings: list[Finding] = []
    sec = _query("Security", [4625, *_NOTABLE], hours, max_events)
    if sec is None:
        findings.append(Finding(
            "winlog-access", Severity.INFO,
            "Cannot read the Security event log - run the terminal as Administrator"))
        sec = []

    by_src: dict[str, list] = {}
    for eid, data in sec:
        if eid == 4625:
            ip = data.get("IpAddress", "-")
            src = ip if ip not in ("-", "", "::1", "127.0.0.1") else "local:" + data.get("WorkstationName", "?")
            entry = by_src.setdefault(src, [0, set(), set()])
            entry[0] += 1
            if len(entry[1]) < 32:
                entry[1].add(data.get("TargetUserName", "?"))
            entry[2].add(data.get("LogonType", "?"))
        else:
            sev, title = _NOTABLE[eid]
            who = data.get("SubjectUserName", "")
            what = data.get("TargetUserName") or data.get("TaskName") or ""
            findings.append(Finding(f"win-event-{eid}", sev, title, what,
                                    [f"by {who}"] if who else []))

    for src, (count, users, types) in by_src.items():
        if count < threshold:
            continue
        remote = "10" in types or "3" in types
        findings.append(Finding(
            "win-logon-bruteforce",
            Severity.HIGH if count >= 30 and remote else Severity.MEDIUM,
            "Repeated failed Windows logons (brute force)", src,
            [f"{count} failures in {hours}h, logon types {','.join(sorted(types))}",
             "accounts: " + ", ".join(sorted(users)[:10])],
            "If RDP/SMB is reachable from the internet, close it or put it behind a VPN; "
            "enable account lockout.",
        ))

    system = _query("System", [7045], hours, 2000) or []
    for _eid, data in system:
        image = data.get("ImagePath", "")
        low = image.lower()
        sev = Severity.LOW
        if any(t in low for t in ("\\temp\\", "\\users\\public\\", "powershell", "cmd.exe", "%comspec%",
                                  "\\appdata\\", "rundll32", "mshta")):
            sev = Severity.HIGH
        findings.append(Finding("win-service-installed", sev, "New service installed",
                                data.get("ServiceName", "?"), [image]))
    return findings
