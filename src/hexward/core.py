"""Shared primitives: findings, severities, reporting, safe subprocess helper."""

from __future__ import annotations

import enum
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import APP_NAME, __version__

IS_WINDOWS = os.name == "nt"


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


# Log lines, file names and command lines are attacker-controlled. Strip control
# characters so a crafted value cannot inject ANSI escapes into the terminal.
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def clean(text: object, limit: int = 300) -> str:
    s = _CTRL.sub("?", str(text)).replace("\n", " ").replace("\t", " ")
    return s if len(s) <= limit else s[: limit - 3] + "..."


@dataclass
class Finding:
    rule: str
    severity: Severity
    title: str
    target: str = ""
    evidence: list[str] = field(default_factory=list)
    advice: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.name,
            "title": clean(self.title),
            "target": clean(self.target, 1000),
            "evidence": [clean(e) for e in self.evidence],
            "advice": self.advice,
        }


def data_dir() -> Path:
    """Per-user state directory (cache, quarantine, signatures, baseline)."""
    root = os.environ.get(APP_NAME.upper() + "_HOME")
    path = Path(root) if root else Path.home() / ("." + APP_NAME)
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_settings() -> dict:
    """User preferences shared by the app and the CLI (language, canaries, ignore list)."""
    try:
        data = json.loads((data_dir() / "settings.json").read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(**changes) -> dict:
    data = load_settings()
    data.update(changes)
    try:
        path = data_dir() / "settings.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass
    return data


def run_cmd(args: list[str], timeout: float = 30.0) -> str | None:
    """Run a command without a shell; return decoded stdout or None on any failure."""
    try:
        flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 and not proc.stdout:
        return None
    raw = proc.stdout
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("oem" if IS_WINDOWS else "latin-1", errors="replace")


def notify(title: str, body: str) -> None:
    """Best-effort desktop notification; never raises. Text is passed through the
    environment / argv, never interpolated into a script."""
    try:
        flags = 0x08000000 if IS_WINDOWS else 0
        common = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      creationflags=flags)
        if IS_WINDOWS:
            script = (
                "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;"
                "$x=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
                "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
                "$n=$x.GetElementsByTagName('text');"
                "$n.Item(0).AppendChild($x.CreateTextNode($env:HEXWARD_TOAST_TITLE))|Out-Null;"
                "$n.Item(1).AppendChild($x.CreateTextNode($env:HEXWARD_TOAST_BODY))|Out-Null;"
                "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
                "'{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe')"
                ".Show([Windows.UI.Notifications.ToastNotification]::new($x))"
            )
            env = dict(os.environ, HEXWARD_TOAST_TITLE=clean(title, 100), HEXWARD_TOAST_BODY=clean(body, 200))
            subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], env=env, **common)
        elif sys.platform == "darwin":
            subprocess.Popen(["osascript", "-e", "on run argv", "-e",
                              "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run",
                              clean(title, 100), clean(body, 200)], **common)
        else:
            subprocess.Popen(["notify-send", "--app-name", APP_NAME, clean(title, 100), clean(body, 200)], **common)
    except (OSError, ValueError):
        pass


# ---------------------------------------------------------------- reporting

_COLORS = {
    Severity.CRITICAL: "\x1b[1;97;41m",
    Severity.HIGH: "\x1b[1;31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}


def _enable_vt() -> bool:
    if not IS_WINDOWS:
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def want_color(stream, disabled: bool) -> bool:
    if disabled or os.environ.get("NO_COLOR"):
        return False
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    return _enable_vt()


def render_text(findings: list[Finding], color: bool, notes: list[str] | None = None) -> str:
    out: list[str] = []
    ordered = sorted(findings, key=lambda f: (-f.severity, f.rule, f.target))
    for f in ordered:
        tag = f"[{f.severity.name}]"
        if color:
            tag = f"{_COLORS[f.severity]}{tag}\x1b[0m"
        out.append(f"{tag} {clean(f.title)}  ({f.rule})")
        if f.target:
            out.append(f"    target: {clean(f.target, 1000)}")
        for ev in f.evidence:
            out.append(f"    - {clean(ev)}")
        if f.advice:
            out.append(f"    > {f.advice}")
        out.append("")
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    summary = ", ".join(f"{counts[s]} {s.name.lower()}" for s in reversed(Severity) if counts[s])
    out.append(f"{APP_NAME} {__version__}: " + (summary if summary else "no findings"))
    for note in notes or []:
        out.append(f"  {note}")
    return "\n".join(out)


def render_json(findings: list[Finding], notes: list[str] | None = None) -> str:
    ordered = sorted(findings, key=lambda f: (-f.severity, f.rule, f.target))
    return json.dumps(
        {
            "tool": APP_NAME,
            "version": __version__,
            "findings": [f.to_dict() for f in ordered],
            "notes": notes or [],
        },
        indent=2,
        ensure_ascii=False,
    )


def safe_print(text: str, stream=None) -> None:
    """Print without ever raising UnicodeEncodeError on legacy Windows consoles."""
    stream = stream or sys.stdout
    if stream is None:  # windowed app: there is no console
        return
    try:
        stream.write(text + "\n")
    except UnicodeEncodeError:
        enc = getattr(stream, "encoding", None) or "ascii"
        stream.write(text.encode(enc, errors="replace").decode(enc) + "\n")
    try:
        stream.flush()
    except OSError:
        pass
