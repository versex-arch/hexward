"""Static heuristics: file names, PE structure, script and command-line content.

Heuristics never claim certainty: they produce a score with reasons, and the
caller maps the score to MEDIUM/HIGH. Only hash signatures yield CRITICAL.
"""

from __future__ import annotations

import math
import re
import struct

# ------------------------------------------------------------ text / cmdline

_I = re.I
# (regex, score, reason). Applied to scripts, shortcuts, autoruns, task actions
# and live process command lines.
TEXT_RULES: list[tuple[re.Pattern, int, str]] = [(re.compile(p, _I), s, r) for p, s, r in [
    (r"-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{60,}", 3, "encoded PowerShell command"),
    (r"(?:iex|invoke-expression)\b.{0,200}(?:downloadstring|downloaddata|downloadfile|invoke-webrequest|\biwr\b|\birm\b|net\.webclient)",
     4, "download-and-execute (IEX)"),
    (r"(?:downloadstring|invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod).{0,200}\|\s*(?:iex|invoke-expression)",
     4, "download-and-execute (pipe to IEX)"),
    (r"frombase64string", 1, "base64 decoding"),
    (r"-w(?:in|indowstyle)?\s+h(?:id|idden)?\b", 1, "hidden window"),
    (r"-e(?:p|xecutionpolicy)\s+(?:bypass|unrestricted)", 1, "execution policy bypass"),
    (r"certutil(?:\.exe)?\b.{0,200}-(?:urlcache|decode|decodehex)", 3, "certutil used as downloader/decoder"),
    (r"bitsadmin.{0,200}/transfer", 2, "bitsadmin download"),
    (r"mshta(?:\.exe)?[\"']?\s+[\"']?(?:https?:|javascript:|vbscript:)", 4, "mshta remote/script execution"),
    (r"regsvr32.{0,200}/i:https?:", 4, "regsvr32 remote scriptlet (Squiblydoo)"),
    (r"rundll32.{0,200}(?:javascript:|\\temp\\|\\appdata\\)", 3, "rundll32 abuse"),
    (r"(?:add|set)-mppreference\b.{0,200}-(?:exclusion|disable)", 4, "tampers with Microsoft Defender"),
    (r"vssadmin.{0,60}delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.{0,80}recoveryenabled\s+no|wbadmin\s+delete\s+catalog",
     5, "destroys backups/shadow copies (ransomware behaviour)"),
    (r"wevtutil(?:\.exe)?\s+cl\b|clear-eventlog", 3, "clears event logs"),
    (r"reg(?:\.exe)?\s+add\b.{0,200}\\currentversion\\run", 2, "adds a Run-key autostart"),
    (r"schtasks(?:\.exe)?\b.{0,200}/create", 1, "creates a scheduled task"),
    (r"net1?\s+user\s+\S+\s+\S+\s+/add|net1?\s+localgroup\s+administrators\b.{0,80}/add", 3, "creates user / adds admin"),
    (r"(?:curl|wget)\s[^|\n]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", 3, "pipes a download into a shell"),
    (r"/dev/tcp/\d|bash\s+-i\s+>&|\bnc(?:at)?\b.{0,80}\s-e\s+/bin/|mkfifo.{0,80}\bnc\b", 4, "reverse shell"),
    (r"eval\(\s*(?:atob|unescape|string\.fromcharcode)", 3, "eval of decoded JavaScript"),
    (r"activexobject\(\s*[\"'](?:msxml2\.xmlhttp|adodb\.stream|wscript\.shell)", 2, "ActiveX downloader/shell object"),
    (r"createobject\(\s*[\"'](?:wscript\.shell|msxml2\.|adodb\.stream)", 2, "COM downloader/shell object"),
    (r"amsiutils|amsiinitfailed|amsiscanbuffer", 4, "AMSI bypass"),
    (r"mimikatz|sekurlsa::|lsass\.dmp|comsvcs(?:\.dll)?.{0,40}minidump|procdump.{0,80}lsass", 5, "credential dumping"),
    (r"stratum\+(?:tcp|ssl)://|\bxmrig\b", 4, "cryptocurrency miner"),
    (r"[A-Za-z0-9+/]{3000,}={0,2}", 1, "very large base64 blob"),
]]

# Python gets its own narrow rules: generic ones would flag every security tool
# (including this file) that merely mentions those strings.
PYTHON_RULES: list[tuple[re.Pattern, int, str]] = [(re.compile(p, _I), s, r) for p, s, r in [
    (r"exec\s*\(\s*(?:base64\.b(?:64|85|32)decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|codecs\.decode|__import__\(\s*['\"]base64)",
     4, "exec of decoded/packed payload"),
    (r"exec\s*\(\s*(?:requests\.get|urllib\.request\.urlopen|urlopen)\s*\(", 4, "exec of downloaded code"),
    (r"socket\.socket\(.{0,400}(?:os\.dup2|pty\.spawn|subprocess\.(?:call|Popen)\(\s*\[?\s*['\"](?:/bin/(?:ba)?sh|cmd(?:\.exe)?)['\"])",
     4, "reverse shell"),
]]

SCRIPT_EXTS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
               ".hta", ".sh", ".lnk", ".sct", ".url"}


def score_text(text: str, rules=TEXT_RULES) -> tuple[int, list[str]]:
    score, reasons = 0, []
    for rx, pts, reason in rules:
        if rx.search(text):
            score += pts
            reasons.append(reason)
    return score, reasons


def decode_sample(data: bytes, limit: int = 512 * 1024) -> str:
    """Decode script bytes; handles UTF-16 (PowerShell, .lnk) with or without BOM."""
    data = data[:limit]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="ignore")
    if data.count(b"\x00") * 5 > len(data):
        data = data.replace(b"\x00", b"")
    return data.decode("utf-8", errors="ignore") if b"\x00" not in data else data.decode("latin-1")


# ------------------------------------------------------------------- names

_RE_DOUBLE_EXT = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip|rar|mp[34]|avi|mkv)\s*"
    r"\.(?:exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|lnk|msi|cpl|jar)$", _I)
_RE_PADDED_EXT = re.compile(r"\s{5,}\.\w{2,4}$")
INERT_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".pdf", ".doc", ".docx", ".xls",
              ".xlsx", ".mp3", ".mp4", ".avi", ".csv", ".log", ".ini", ".xml", ".json", ".md"}


def name_reasons(name: str) -> list[tuple[int, str]]:
    out = []
    if "\u202e" in name:
        out.append((5, "right-to-left override character hides the real extension"))
    if _RE_DOUBLE_EXT.search(name):
        out.append((5, "double extension disguises an executable as a document"))
    elif _RE_PADDED_EXT.search(name):
        out.append((3, "extension pushed out of view with whitespace padding"))
    return out


# ---------------------------------------------------------------------- PE

def entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    total = 0.0
    count = data.count
    for b in range(256):
        c = count(bytes((b,)))
        if c:
            p = c / n
            total -= p * math.log2(p)
    return total


class PEInfo:
    __slots__ = ("sections", "signed", "dotnet", "is_dll")

    def __init__(self):
        self.sections: list[tuple[str, int, int, int, int]] = []  # name, vsize, rawsize, rawptr, flags
        self.signed = False
        self.dotnet = False
        self.is_dll = False


def parse_pe(d: bytes) -> PEInfo | None:
    try:
        if d[:2] != b"MZ" or len(d) < 0x40:
            return None
        off = struct.unpack_from("<I", d, 0x3C)[0]
        if off > len(d) - 24 or d[off:off + 4] != b"PE\x00\x00":
            return None
        nsec, = struct.unpack_from("<H", d, off + 6)
        opt_size, chars = struct.unpack_from("<HH", d, off + 20)
        opt = off + 24
        magic, = struct.unpack_from("<H", d, opt)
        if magic not in (0x10B, 0x20B):
            return None
        dd = opt + (96 if magic == 0x10B else 112)
        info = PEInfo()
        info.is_dll = bool(chars & 0x2000)
        num_dirs, = struct.unpack_from("<I", d, dd - 4)
        if num_dirs > 4:
            info.signed = struct.unpack_from("<I", d, dd + 4 * 8 + 4)[0] > 0
        if num_dirs > 14:
            info.dotnet = struct.unpack_from("<I", d, dd + 14 * 8)[0] > 0
        base = opt + opt_size
        for i in range(min(nsec, 96)):
            s = base + 40 * i
            name = d[s:s + 8].rstrip(b"\x00").decode("latin-1")
            vsize, _va, rawsize, rawptr = struct.unpack_from("<IIII", d, s + 8)
            flags, = struct.unpack_from("<I", d, s + 36)
            info.sections.append((name, vsize, rawsize, rawptr, flags))
        return info
    except struct.error:
        return None


_PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
                    ".MPRESS1", ".MPRESS2", ".petite", ".enigma1", ".enigma2", ".nsp0", ".nsp1",
                    "PEC2", ".perplex", ".yP", ".packed", "pebundle", ".boom", ".taz"}

# (all of these names present) -> score, reason
_API_COMBOS: list[tuple[tuple[bytes, ...], int, str]] = [
    ((b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"), 3, "remote process injection APIs"),
    ((b"NtUnmapViewOfSection", b"WriteProcessMemory"), 3, "process hollowing APIs"),
    ((b"QueueUserAPC", b"WriteProcessMemory"), 2, "APC injection APIs"),
    ((b"SetWindowsHookEx", b"GetAsyncKeyState"), 2, "keylogging APIs"),
    ((b"URLDownloadToFile", b"ShellExecute"), 2, "download-and-run APIs"),
    ((b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess"), 1, "anti-debugging"),
    ((b"MiniDumpWriteDump", b"lsass"), 4, "LSASS memory dumping"),
    ((b"CryptEncrypt", b"FindNextFile", b"DeleteShadow"), 4, "encrypt-files-and-kill-backups pattern"),
]
_STRINGS: list[tuple[str, int, str]] = [
    ("vssadmin", 2, "references vssadmin (shadow copy tool)"),
    ("DisableRealtimeMonitoring", 3, "references disabling Defender"),
    ("Add-MpPreference", 3, "references Defender exclusions"),
    ("SbieDll.dll", 1, "sandbox detection"),
    ("stratum+tcp://", 3, "mining pool protocol"),
    ("sekurlsa", 4, "credential dumping module"),
]


def pe_reasons(info: PEInfo, data: bytes, read_section) -> list[tuple[int, str]]:
    """`read_section(offset, size)` returns up to `size` raw bytes at `offset`."""
    # Two weak signal families, each capped at 3 points so that neither can
    # reach the reporting threshold (4) alone: plenty of legitimate software is
    # UPX-packed, and browsers/debuggers legitimately import injection APIs.
    packed: list[tuple[int, str]] = []
    names = {s[0] for s in info.sections}
    hits = names & _PACKER_SECTIONS
    if hits:
        packed.append((2, "packer section names: " + ", ".join(sorted(hits))))
    wx = hi = 0
    for name, vsize, rawsize, rawptr, flags in info.sections[:12]:
        executable = bool(flags & 0x20000000)
        if executable and flags & 0x80000000:
            wx += 1
        if executable and rawsize >= 4096:
            sample = read_section(rawptr, min(rawsize, 256 * 1024))
            if len(sample) >= 4096 and entropy(sample) >= 7.3:
                hi += 1
    if wx:
        packed.append((1, f"{wx} section(s) both writable and executable"))
    if hi:
        packed.append((2, f"{hi} executable section(s) with packed/encrypted entropy"))
    apis = [(pts, reason) for needles, pts, reason in _API_COMBOS if all(n in data for n in needles)]

    def capped(group: list[tuple[int, str]], cap: int = 3) -> list[tuple[int, str]]:
        excess = sum(p for p, _ in group) - cap
        return group + ([(-excess, f"(capped at {cap}: same kind of evidence)")] if excess > 0 else [])

    out: list[tuple[int, str]] = capped(packed) + capped(apis)
    for text, pts, reason in _STRINGS:
        if text.encode() in data or text.encode("utf-16-le") in data:
            out.append((pts, reason))
    if out and info.signed:
        out.append((-2, "carries an Authenticode signature (not verified)"))
    return out
