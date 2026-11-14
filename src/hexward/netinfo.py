"""Listening TCP sockets, cross-platform, using only tools the OS ships with."""

from __future__ import annotations

import csv
import io
import re
import sys
from dataclasses import dataclass

from .core import IS_WINDOWS, Finding, Severity, run_cmd


@dataclass(frozen=True)
class Listener:
    addr: str
    port: int
    pid: int
    proc: str

    @property
    def loopback(self) -> bool:
        return self.addr.startswith("127.") or self.addr in ("::1", "localhost")

    def label(self) -> str:
        host = f"[{self.addr}]" if ":" in self.addr else self.addr
        return f"{host}:{self.port} ({self.proc or 'pid ' + str(self.pid)})"


def _split(endpoint: str) -> tuple[str, int] | None:
    host, _, port = endpoint.rpartition(":")
    if not port.isdigit():
        return None
    host = host.strip("[]").split("%")[0]
    if host in ("*", "", "0.0.0.0"):
        host = "0.0.0.0"
    return host, int(port)


def _windows() -> list[Listener] | None:
    out = run_cmd(["netstat", "-ano"], timeout=30)
    if out is None:
        return None
    names: dict[int, str] = {}
    tl = run_cmd(["tasklist", "/fo", "csv", "/nh"], timeout=30)
    if tl:
        for row in csv.reader(io.StringIO(tl)):
            if len(row) >= 2 and row[1].strip().isdigit():
                names[int(row[1])] = row[0]
    res = []
    for line in out.splitlines():
        f = line.split()
        # A listening socket has the wildcard remote endpoint; avoids relying on
        # the (possibly localised) state column.
        if len(f) >= 4 and f[0] == "TCP" and f[2] in ("0.0.0.0:0", "[::]:0") and f[-1].isdigit():
            ep = _split(f[1])
            if ep:
                pid = int(f[-1])
                res.append(Listener(ep[0], ep[1], pid, names.get(pid, "")))
    return res


def _linux() -> list[Listener] | None:
    out = run_cmd(["ss", "-H", "-ltnp"], timeout=15)
    if out is None:
        return None
    res = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        ep = _split(f[3])
        if not ep:
            continue
        m = re.search(r'\(\("([^"]+)",pid=(\d+)', line)
        res.append(Listener(ep[0], ep[1], int(m.group(2)) if m else 0, m.group(1) if m else ""))
    return res


def _mac() -> list[Listener] | None:
    out = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"], timeout=15)
    if out is None:
        return None
    res, pid, cmd = [], 0, ""
    for line in out.splitlines():
        if line[:1] == "p" and line[1:].isdigit():
            pid = int(line[1:])
        elif line[:1] == "c":
            cmd = line[1:]
        elif line[:1] == "n":
            ep = _split(line[1:])
            if ep:
                res.append(Listener(ep[0], ep[1], pid, cmd))
    return res


def get_listeners() -> list[Listener] | None:
    """None means the platform tool was unavailable (not 'nothing is listening')."""
    if IS_WINDOWS:
        found = _windows()
    elif sys.platform == "darwin":
        found = _mac()
    else:
        found = _linux()
    return None if found is None else sorted(set(found), key=lambda l: (l.port, l.addr))


# port -> (service, severity when reachable from other machines)
RISKY_PORTS = {
    21: ("FTP", Severity.MEDIUM), 23: ("Telnet", Severity.HIGH),
    # SMB is on by default on Windows and normally firewalled on public networks.
    445: ("SMB file sharing", Severity.LOW), 3389: ("RDP", Severity.MEDIUM),
    5900: ("VNC", Severity.HIGH), 5985: ("WinRM", Severity.MEDIUM), 5986: ("WinRM", Severity.MEDIUM),
    2375: ("Docker API (no TLS)", Severity.HIGH), 3306: ("MySQL", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.MEDIUM), 6379: ("Redis", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH), 9200: ("Elasticsearch", Severity.HIGH),
    11211: ("memcached", Severity.HIGH), 1433: ("MS SQL", Severity.MEDIUM),
}


def audit_network(listeners: list[Listener] | None) -> list[Finding]:
    if listeners is None:
        return [Finding("net-unavailable", Severity.INFO,
                        "Could not list listening sockets (netstat/ss/lsof missing or blocked)")]
    by_port: dict[int, list[Listener]] = {}
    for l in listeners:
        if l.port in RISKY_PORTS and not l.loopback:
            by_port.setdefault(l.port, []).append(l)
    out = []
    for port, group in by_port.items():
        service, sev = RISKY_PORTS[port]
        out.append(Finding(
            "net-risky-listener", sev, f"{service} accepts connections from the network",
            f"port {port} ({group[0].proc or 'pid ' + str(group[0].pid)})",
            ["bound to " + ", ".join(sorted({l.addr for l in group}))],
            "If other machines do not need it, disable the service or block the port in the firewall. "
            "(A listening socket does not prove the firewall lets traffic through.)",
        ))
    return out
