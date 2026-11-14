"""Streaming log analysis: SSH/sudo auth logs and nginx/apache access logs.

Everything is single-pass and line-streamed, so multi-gigabyte logs use
constant memory per distinct client IP (and the IP table itself is capped).
"""

from __future__ import annotations

import bz2
import gzip
import ipaddress
import re
import sys
from collections import deque
from typing import Iterable, Iterator
from urllib.parse import unquote_plus

from .core import Finding, Severity

MAX_TRACKED_IPS = 500_000
MAX_SET = 64  # cap for per-IP sample sets


def open_log(path: str) -> Iterator[str]:
    """Yield lines from a plain, .gz or .bz2 log, or stdin when path is '-'."""
    if path == "-":
        yield from sys.stdin
        return
    if path.endswith(".gz"):
        fh = gzip.open(path, "rt", encoding="utf-8", errors="replace")
    elif path.endswith(".bz2"):
        fh = bz2.open(path, "rt", encoding="utf-8", errors="replace")
    else:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    with fh:
        yield from fh


class AllowList:
    def __init__(self, cidrs: Iterable[str] = ()):
        self.nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        self._memo: dict[str, bool] = {}

    def __contains__(self, ip: str) -> bool:
        if not self.nets:
            return False
        hit = self._memo.get(ip)
        if hit is None:
            try:
                addr = ipaddress.ip_address(ip)
                hit = any(addr in n for n in self.nets)
            except ValueError:
                hit = False
            if len(self._memo) < 100_000:
                self._memo[ip] = hit
        return hit


def _cap_add(s: set, item) -> None:
    if len(s) < MAX_SET:
        s.add(item)


# ====================================================================== auth

_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def _auth_ts(line: str) -> float | None:
    """Seconds on a per-year clock; enough for sliding windows inside one log."""
    try:
        if line[:1].isdigit():  # ISO 8601: 2026-11-14T10:22:33...
            mon, day = int(line[5:7]) - 1, int(line[8:10])
            h, m, s = int(line[11:13]), int(line[14:16]), int(line[17:19])
        else:  # classic syslog: "Nov 14 10:22:33"
            mon, day = _MONTHS[line[:3]], int(line[4:6])
            h, m, s = int(line[7:9]), int(line[10:12]), int(line[13:15])
        return ((mon * 31 + day) * 24 + h) * 3600 + m * 60 + s
    except (KeyError, ValueError, IndexError):
        return None


_RE_FAIL = re.compile(r"Failed \S+ for (invalid user )?(\S*) from (\S+) port")
_RE_MAXAUTH = re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(\S*) from (\S+)")
_RE_INVALID = re.compile(r"Invalid user (\S*) from (\S+)")
_RE_ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
_RE_NOID = re.compile(
    r"(?:Did not receive identification string from|banner exchange: Connection from|"
    r"Bad protocol version identification .{0,200}? from) (\S+)"
)
_RE_SUDO = re.compile(r"sudo: +(\S+) : (user NOT in sudoers|\d+ incorrect password attempts?)")
_RE_PAM = re.compile(r"pam_unix\((\w[\w-]*):auth\): authentication failure;.*?\buser=(\S+)")


class _SshIp:
    __slots__ = ("fails", "invalid", "users", "window", "peak", "noid")

    def __init__(self):
        self.fails = 0
        self.invalid = 0
        self.users: set[str] = set()
        self.window: deque[float] = deque()
        self.peak = 0
        self.noid = 0


def analyze_auth(lines: Iterable[str], threshold: int = 5, window_min: int = 10,
                 allow: AllowList | None = None, limit: int = 25) -> list[Finding]:
    allow = allow or AllowList()
    window = window_min * 60
    ips: dict[str, _SshIp] = {}
    user_ips: dict[str, set[str]] = {}
    user_fails: dict[str, int] = {}
    sudo: dict[str, list[str]] = {}
    pam: dict[tuple[str, str], int] = {}
    findings: list[Finding] = []

    def state(ip: str) -> _SshIp | None:
        st = ips.get(ip)
        if st is None:
            if len(ips) >= MAX_TRACKED_IPS:
                return None
            st = ips[ip] = _SshIp()
        return st

    for line in lines:
        if "sshd" in line:
            m = _RE_FAIL.search(line) or _RE_MAXAUTH.search(line)
            if m:
                user, ip = m.group(m.lastindex - 1), m.group(m.lastindex)
                if ip in allow:
                    continue
                st = state(ip)
                if st is None:
                    continue
                st.fails += 1
                _cap_add(st.users, user or "<empty>")
                ts = _auth_ts(line)
                if ts is not None:
                    w = st.window
                    w.append(ts)
                    while w and (ts - w[0] > window or ts < w[0]):
                        w.popleft()
                    if len(w) > st.peak:
                        st.peak = len(w)
                if user:
                    _cap_add(user_ips.setdefault(user, set()), ip)
                    user_fails[user] = user_fails.get(user, 0) + 1
                continue
            m = _RE_ACCEPT.search(line)
            if m:
                method, user, ip = m.groups()
                st = ips.get(ip)
                if st and st.fails >= threshold and ip not in allow:
                    findings.append(Finding(
                        "ssh-compromise", Severity.CRITICAL,
                        f"Successful SSH login as '{user}' after {st.fails} failed attempts",
                        ip, [line.strip()],
                        "Treat the account as compromised: rotate its credentials, review "
                        "its session history, and block the source address.",
                    ))
                elif user == "root" and method == "password" and ip not in allow:
                    findings.append(Finding(
                        "ssh-root-password", Severity.MEDIUM,
                        "root logged in over SSH with a password", ip, [line.strip()],
                        "Set 'PermitRootLogin prohibit-password' and use keys.",
                    ))
                continue
            m = _RE_INVALID.search(line)
            if m:
                user, ip = m.groups()
                if ip not in allow and (st := state(ip)) is not None:
                    st.invalid += 1
                    _cap_add(st.users, user or "<empty>")
                continue
            m = _RE_NOID.search(line)
            if m and m.group(1) not in allow and (st := state(m.group(1))) is not None:
                st.noid += 1
            continue
        if "sudo" in line:
            m = _RE_SUDO.search(line)
            if m:
                ev = sudo.setdefault(m.group(1), [])
                if len(ev) < 5:
                    ev.append(line.strip())
                continue
        if "pam_unix" in line and "sshd" not in line:
            m = _RE_PAM.search(line)
            if m:
                key = (m.group(1), m.group(2))
                pam[key] = pam.get(key, 0) + 1

    brute, spray, probes = [], [], []
    for ip, st in ips.items():
        attempts = st.fails or st.invalid
        if attempts >= threshold:
            brute.append((attempts, ip, st))
        elif len(st.users) >= 5:
            spray.append((len(st.users), ip, st))
        elif st.noid >= 3:
            probes.append((st.noid, ip, st))

    def emit(items, build):
        items.sort(key=lambda t: -t[0])
        for item in items[:limit]:
            findings.append(build(*item))
        if len(items) > limit:
            findings.append(Finding(
                build(*items[0]).rule + "-more", Severity.INFO,
                f"{len(items) - limit} more sources of the same kind were suppressed (raise --limit)",
            ))

    def b_brute(n, ip, st):
        ev = [f"{n} failed logins, {len(st.users)} distinct usernames"]
        if st.peak:
            ev.append(f"peak {st.peak} failures within {window_min} min")
        ev.append("usernames: " + ", ".join(sorted(st.users)[:12]))
        return Finding("ssh-bruteforce", Severity.HIGH if n >= 30 else Severity.MEDIUM,
                       "SSH brute-force attack", ip, ev,
                       "Block the address (fail2ban / firewall); disable password authentication.")

    def b_spray(n, ip, st):
        return Finding("ssh-user-enum", Severity.MEDIUM, "SSH username enumeration / password spraying",
                       ip, [f"{n}+ usernames tried: " + ", ".join(sorted(st.users)[:12])],
                       "Block the address; disable password authentication.")

    def b_probe(n, ip, st):
        return Finding("ssh-probe", Severity.LOW, "SSH port probing / banner grabbing", ip,
                       [f"{n} connections without a valid SSH handshake"])

    emit(brute, b_brute)
    emit(spray, b_spray)
    emit(probes, b_probe)

    for user, srcs in user_ips.items():
        if len(srcs) >= 10 and user_fails[user] >= 30:
            findings.append(Finding(
                "ssh-distributed", Severity.MEDIUM,
                f"Distributed brute-force against account '{user}'", user,
                [f"{user_fails[user]} failures from {len(srcs)}+ addresses"],
                "Likely a botnet; per-IP blocking will not help - require keys or MFA.",
            ))
    for user, ev in sudo.items():
        findings.append(Finding("sudo-abuse", Severity.MEDIUM,
                                f"Failed or unauthorised sudo use by '{user}'", user, ev))
    for (service, user), n in pam.items():
        if n >= threshold:
            findings.append(Finding("pam-failures", Severity.MEDIUM,
                                    f"{n} authentication failures for '{user}' via {service}", user))
    return findings


# ======================================================================= web

_RE_ACCESS = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')

_ATTACKS = {
    "sql-injection": (
        r"union(?:\s|/\*.*?\*/)+(?:all\s+)?select|select\s.{1,80}\sfrom\s|information_schema|"
        r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w|sleep\s*\(\s*\d|benchmark\s*\(|"
        r"waitfor\s+delay|pg_sleep|load_file\s*\(|into\s+(?:out|dump)file|extractvalue\s*\(|"
        r"updatexml\s*\(|;\s*drop\s+table"
    ),
    "xss": (
        r"<script|javascript:|\bon(?:error|load|mouseover|focus|click)\s*=|<svg[\s/>]|<iframe|"
        r"document\.cookie|alert\s*\(|<img[^>]{0,80}\bsrc"
    ),
    "path-traversal": (
        r"\.\./|\.\.\\|/etc/(?:passwd|shadow|hosts)|/proc/self/|win\.ini|boot\.ini|"
        r"c:[\\/]+windows"
    ),
    "command-injection": (
        r"(?:;|\||&&|`|\$\()\s*(?:cat|wget|curl|bash|sh|nc|id|whoami|uname|ping|powershell|cmd)(?![\w=.-])|"
        r"/bin/(?:ba)?sh|cmd\.exe|php://(?:input|filter)|data://text|expect://|base64_decode\s*\(|"
        r"\b(?:system|passthru|shell_exec|eval)\s*\(|invokefunction|call_user_func"
    ),
    "known-exploit": r"\$\{\s*(?:jndi|lower|upper|env|sys)\s*:|\(\)\s*\{\s*:;\s*\}",
}
_ATTACK_RES = {k: re.compile(v, re.I | re.S) for k, v in _ATTACKS.items()}

_RE_SENSITIVE = re.compile(
    r"(?:^|/)(?:\.env(?:\.|$)|\.git/|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store|\.htpasswd|\.vscode/|"
    r"wp-login\.php|xmlrpc\.php|wp-config|phpmyadmin|pma/|adminer|phpinfo|info\.php|"
    r"server-status|server-info|actuator(?:/|$)|jolokia|manager/html|cgi-bin/|hnap1|boaform|"
    r"goform|setup\.cgi|(?:shell|cmd|c99|r57|wso|alfa)\.php|eval-stdin\.php|vendor/phpunit|"
    r"config\.(?:json|ya?ml|php|inc)$|backup\.(?:zip|sql|tar|gz|rar)|[\w-]+\.(?:sql|bak|old|swp)$|"
    r"_profiler|telescope/|_ignition|owa/|ecp/|autodiscover|remote/login|dana-na|"
    r"global-protect|solr/|druid/|nacos/|geoserver|id_rsa|credentials$)", re.I)

_RE_SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|gobuster|ffuf|feroxbuster|"
    r"acunetix|nessus|openvas|hydra|whatweb|wfuzz|\bdirb\b|arachni|w3af|burp|owasp|netsparker|"
    r"qualys|havij|metasploit|jaeles|l9explore|l9tcpid|zmeu|morfeus|muieblackcat|libredtail|"
    r"censysinspect|expanse|internetmeasurement|masscan|xenu|fimap|commix|joomscan", re.I)
_RE_GENERIC_UA = re.compile(
    r"^(?:-|)$|python-requests|python-urllib|curl/|wget/|go-http-client|libwww-perl|^java/|"
    r"okhttp|aiohttp|scrapy|httpclient", re.I)
_RE_LOGIN = re.compile(
    r"wp-login\.php|xmlrpc\.php|/(?:login|signin|sign-in|auth|admin|session|token)(?:[/?.]|$)", re.I)


# A request can only match an attack regex if it contains one of these, so the
# (expensive) regexes run on a tiny fraction of lines.
_TRIGGER_CHARS = "'\"<;|`$("
_TRIGGER_WORDS = ("..", "union", "select", "information_schema", "waitfor", "pg_sleep", "file",
                  "javascript:", "onerror", "onload", "onmouseover", "onfocus", "onclick",
                  "document.cookie", "/etc/", "/proc/", ".ini", "c:", "&&", "/bin/", "cmd.exe",
                  "://", "invokefunction", "call_user_func")


def _classify_url(url: str) -> tuple[tuple[str, ...], bool, str]:
    """-> (attack kinds, is sensitive path, decoded path without query)."""
    decoded = url
    if "%" in url or "+" in url:
        decoded = unquote_plus(url)
        if "%" in decoded:  # double encoding is itself an evasion technique
            decoded = unquote_plus(decoded)
    kinds: tuple[str, ...] = ()
    low = decoded.lower()
    if any(c in decoded for c in _TRIGGER_CHARS) or any(w in low for w in _TRIGGER_WORDS):
        kinds = tuple(name for name, rx in _ATTACK_RES.items() if rx.search(decoded))
    path = decoded.partition("?")[0]
    return kinds, bool(_RE_SENSITIVE.search(path)), path


def _classify_ua(ua: str) -> int:
    """Bit flags: 1 generic script client, 2 known attack tool, 4 exploit payload in the UA."""
    flags = 0
    if _RE_SCANNER_UA.search(ua):
        flags |= 2
    elif _RE_GENERIC_UA.search(ua):
        flags |= 1
    if ("${" in ua or "() {" in ua) and _ATTACK_RES["known-exploit"].search(ua):
        flags |= 4
    return flags


class _WebIp:
    __slots__ = ("total", "err", "paths", "sens", "sens_ev", "attacks", "attack_ev", "uas",
                 "generic_ua", "logins", "minute", "cur", "peak", "malformed")

    def __init__(self):
        self.total = 0
        self.err = 0
        self.paths: set[str] = set()
        self.sens = 0
        self.sens_ev: list[str] = []
        self.attacks: dict[str, int] = {}
        self.attack_ev: list[str] = []
        self.uas: set[str] = set()
        self.generic_ua = False
        self.logins = 0
        self.minute = ""
        self.cur = 0
        self.peak = 0
        self.malformed = 0


def analyze_web(lines: Iterable[str], scan_threshold: int = 20, login_threshold: int = 20,
                flood_rpm: int = 300, allow: AllowList | None = None, limit: int = 25) -> list[Finding]:
    allow = allow or AllowList()
    ips: dict[str, _WebIp] = {}
    exposed: dict[str, str] = {}  # sensitive path answered 200 -> sample line
    # Real logs repeat the same URLs and User-Agents endlessly: classify each once.
    url_cache: dict[str, tuple] = {}
    ua_cache: dict[str, int] = {}
    match = _RE_ACCESS.match

    for line in lines:
        m = match(line)
        if not m:
            continue
        ip, ts, request, status, ua = m.groups()
        if ip in allow:
            continue
        st = ips.get(ip)
        if st is None:
            if len(ips) >= MAX_TRACKED_IPS:
                continue
            st = ips[ip] = _WebIp()
        st.total += 1

        minute = ts[:17]  # dd/Mon/yyyy:HH:MM
        if minute == st.minute:
            st.cur += 1
        else:
            st.minute, st.cur = minute, 1
        if st.cur > st.peak:
            st.peak = st.cur

        parts = request.split(" ")
        if len(parts) < 2 or not parts[1].startswith(("/", "http", "*")):
            st.malformed += 1
            continue
        method, url = parts[0], parts[1]

        if status[0] == "4":
            st.err += 1
            _cap_add(st.paths, url[:120])

        info = url_cache.get(url)
        if info is None:
            info = _classify_url(url)
            if len(url_cache) < 200_000:
                url_cache[url] = info
        kinds, sensitive, path = info

        ua_class = 0
        if ua is not None:
            ua_class = ua_cache.get(ua, -1)
            if ua_class < 0:
                ua_class = _classify_ua(ua)
                if len(ua_cache) < 50_000:
                    ua_cache[ua] = ua_class
            if ua_class & 4 and "known-exploit" not in kinds:
                kinds = kinds + ("known-exploit",)
            if ua_class & 2:
                _cap_add(st.uas, ua[:100])
            elif ua_class & 1:
                st.generic_ua = True

        if kinds:
            for name in kinds:
                st.attacks[name] = st.attacks.get(name, 0) + 1
            if len(st.attack_ev) < 4:
                st.attack_ev.append(f"{status} {method} {url}")
        if sensitive:
            st.sens += 1
            if len(st.sens_ev) < 4:
                st.sens_ev.append(f"{status} {method} {url}")
            if status == "200" and len(exposed) < 200:
                exposed.setdefault(path[:200], line.strip())

        if (method == "POST" and _RE_LOGIN.search(path)) or status == "401":
            st.logins += 1

    buckets: dict[str, list] = {"attack": [], "scan": [], "ua": [], "brute": [], "flood": []}
    for ip, st in ips.items():
        if st.attacks:
            buckets["attack"].append((sum(st.attacks.values()), ip, st))
        if (st.err >= scan_threshold and len(st.paths) >= min(10, scan_threshold)) \
                or st.sens >= 5 or st.malformed >= 5:
            buckets["scan"].append((st.err + st.sens + st.malformed, ip, st))
        if st.uas:
            buckets["ua"].append((st.total, ip, st))
        if st.logins >= login_threshold:
            buckets["brute"].append((st.logins, ip, st))
        if st.peak >= flood_rpm:
            buckets["flood"].append((st.peak, ip, st))

    def b_attack(n, ip, st):
        kinds = ", ".join(f"{k} x{v}" for k, v in sorted(st.attacks.items()))
        return Finding("web-attack", Severity.HIGH, "Web attack payloads in requests", ip,
                       [kinds] + st.attack_ev,
                       "Block the address; check that the targeted endpoints are patched and "
                       "review responses with status 200 for these requests.")

    def b_scan(n, ip, st):
        ev = [f"{st.total} requests, {st.err} client errors over {len(st.paths)}+ paths, "
              f"{st.sens} sensitive-path probes, {st.malformed} malformed requests"]
        if st.generic_ua:
            ev.append("uses a script/empty User-Agent")
        return Finding("web-scan", Severity.MEDIUM, "Vulnerability / content scanning", ip,
                       ev + st.sens_ev, "Block or rate-limit the address.")

    def b_ua(n, ip, st):
        return Finding("web-scanner-ua", Severity.MEDIUM, "Known attack-tool User-Agent", ip,
                       [f"{st.total} requests"] + sorted(st.uas)[:4])

    def b_brute(n, ip, st):
        return Finding("web-bruteforce", Severity.HIGH if n >= 200 else Severity.MEDIUM,
                       "HTTP login brute-force", ip,
                       [f"{n} login attempts / 401 responses"],
                       "Rate-limit the login endpoint and enable MFA or lockout.")

    def b_flood(n, ip, st):
        return Finding("web-flood", Severity.MEDIUM, "Request flood (possible DoS or scraping)", ip,
                       [f"peak {n} requests in one minute, {st.total} total"],
                       "Apply rate limiting (nginx limit_req).")

    builders = {"attack": b_attack, "scan": b_scan, "ua": b_ua, "brute": b_brute, "flood": b_flood}
    findings: list[Finding] = []
    for key, items in buckets.items():
        items.sort(key=lambda t: -t[0])
        for item in items[:limit]:
            findings.append(builders[key](*item))
        if len(items) > limit:
            findings.append(Finding(f"web-{key}-more", Severity.INFO,
                                    f"{len(items) - limit} more sources of the same kind were "
                                    f"suppressed (raise --limit)"))
    for path, sample in exposed.items():
        findings.append(Finding(
            "web-exposed-file", Severity.HIGH,
            "Sensitive path answered with HTTP 200 - it may be publicly exposed", path, [sample],
            "Open the URL yourself; if it really serves the file, remove it or deny access "
            "and rotate any secrets it contained.",
        ))
    return findings


# ================================================================= detection

def detect_format(sample: list[str]) -> str | None:
    web = sum(1 for ln in sample if _RE_ACCESS.match(ln))
    auth = sum(1 for ln in sample if "sshd" in ln or "sudo" in ln or "pam_unix" in ln)
    if web == 0 and auth == 0:
        return None
    return "web" if web >= auth else "auth"


def analyze_path(path: str, kind: str = "auto", **opts) -> tuple[str, list[Finding]]:
    """Analyze one log file. Returns (detected kind, findings). Raises OSError on I/O errors."""
    lines = open_log(path)
    head: list[str] = []
    if kind == "auto":
        for line in lines:
            if line.strip():
                head.append(line)
            if len(head) >= 200:
                break
        kind = detect_format(head) or ""
        if not kind:
            return "unknown", [Finding(
                "log-unknown", Severity.INFO,
                "Could not recognise the log format (use --type auth|web)", path)]

    def chained() -> Iterator[str]:
        yield from head
        yield from lines

    web_keys = ("scan_threshold", "login_threshold", "flood_rpm")
    auth_keys = ("threshold", "window_min")
    common = {k: opts[k] for k in ("allow", "limit") if k in opts}
    if kind == "web":
        res = analyze_web(chained(), **common, **{k: opts[k] for k in web_keys if k in opts})
    else:
        res = analyze_auth(chained(), **common, **{k: opts[k] for k in auth_keys if k in opts})
    return kind, res
