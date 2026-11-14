"""Integrity guard: baseline + change detection for the things attackers and
misbehaving AI agents modify to gain persistence or widen their own permissions:
agent/MCP configs, shell profiles, SSH keys, hosts, autostart entries, listeners.

`watch` is a polling loop that stats a few dozen files per tick and only hashes
a file when its size or mtime moved, so it costs effectively no CPU.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from .aiguard import AI_PORTS, agent_config_files
from .core import IS_WINDOWS, Finding, Severity, data_dir, load_settings, safe_print, save_settings
from .netinfo import get_listeners
from .sysaudit import autoruns, hosts_path, judge_command, startup_dirs

BASELINE_VERSION = 1


def baseline_path() -> Path:
    return data_dir() / "baseline.json"


def default_files(extra: list[str] | None = None) -> list[Path]:
    home = Path.home()
    files = list(agent_config_files(Path.cwd()))
    files += [home / n for n in (
        ".ssh/authorized_keys", ".ssh/config", ".gitconfig", ".bashrc", ".bash_profile", ".zshrc",
        ".profile", ".npmrc", ".pypirc")]
    if IS_WINDOWS:
        docs = home / "Documents"
        files += [docs / "WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
                  docs / "PowerShell/Microsoft.PowerShell_profile.ps1",
                  docs / "WindowsPowerShell/profile.ps1", docs / "PowerShell/profile.ps1"]
    files.append(hosts_path())
    for item in extra or []:
        p = Path(item).expanduser()
        if p.is_dir():
            try:
                files += sorted(f for f in p.iterdir() if f.is_file())[:500]
            except OSError:
                pass
        else:
            files.append(p)
    seen, out = set(), []
    for f in files:
        key = os.path.normcase(str(f.absolute()))
        if key not in seen:
            seen.add(key)
            out.append(f.absolute())
    return out


def _fingerprint(path: str) -> dict | None:
    """None when the file does not exist or cannot be read."""
    try:
        st = os.stat(path)
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(1 << 20):
                digest.update(chunk)
        return {"sha256": digest.hexdigest(), "size": st.st_size, "mtime": st.st_mtime_ns}
    except OSError:
        return None


def _startup_listing() -> dict[str, list[str]]:
    out = {}
    for d in startup_dirs():
        try:
            out[str(d)] = sorted(e.name for e in d.iterdir() if e.name.lower() != "desktop.ini")
        except OSError:
            pass
    return out


def _listener_keys() -> list[str] | None:
    listeners = get_listeners()
    if listeners is None:
        return None
    # Ephemeral ports churn constantly; track only what matters for exposure.
    return sorted({f"{l.addr}:{l.port} {l.proc}" for l in listeners
                   if not l.loopback or l.port in AI_PORTS})


def snapshot(extra: list[str] | None = None) -> dict:
    files = default_files(extra)
    return {
        "version": BASELINE_VERSION,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "extra": list(extra or []),
        "files": {str(f): _fingerprint(str(f)) for f in files},
        "autoruns": autoruns(),
        "startup": _startup_listing(),
        "listeners": _listener_keys() or [],
    }


def save_baseline(snap: dict) -> Path:
    path = baseline_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(snap, indent=1), encoding="utf-8")
    os.replace(tmp, path)
    return path


def load_baseline() -> dict | None:
    try:
        snap = json.loads(baseline_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(snap, dict) or snap.get("version") != BASELINE_VERSION:
        return None
    return snap


def diff(state: dict, *, check_listeners: bool = True) -> list[Finding]:
    """Compare the live system with `state` and update `state` in place to the
    new reality, so each change is reported exactly once by the watch loop."""
    out: list[Finding] = []
    files: dict = state.setdefault("files", {})
    for path, old in list(files.items()):
        try:
            st = os.stat(path)
            if old and old["size"] == st.st_size and old["mtime"] == st.st_mtime_ns:
                continue
        except OSError:
            if old is None:
                continue
        new = _fingerprint(path)
        if old and new and old["sha256"] == new["sha256"]:
            files[path] = new  # touched but identical
            continue
        if old is None and new is None:
            continue
        files[path] = new
        if old is None:
            out.append(Finding("guard-file-created", Severity.HIGH, "Protected file appeared", path,
                               advice="If you or a tool you trust did not create it, inspect it now."))
        elif new is None:
            out.append(Finding("guard-file-removed", Severity.MEDIUM, "Protected file was removed", path))
        else:
            out.append(Finding("guard-file-changed", Severity.HIGH, "Protected file was modified", path,
                               [f"sha256 {old['sha256'][:16]}... -> {new['sha256'][:16]}..."],
                               "Agent configs, shell profiles and SSH keys decide what runs with your "
                               "rights. Review the change; run `guard init` to accept it."))

    now_runs = autoruns()
    old_runs: dict = state.setdefault("autoruns", {})
    from . import APP_NAME, autostart

    own = autostart.command()
    for key, cmd in now_runs.items():
        if key.endswith("\\" + APP_NAME) and cmd == own:
            continue  # our own "start with Windows" entry, switched on in Settings
        if key not in old_runs or old_runs[key] != cmd:
            sev = judge_command(cmd)[0] or Severity.MEDIUM
            verb = "added" if key not in old_runs else "changed"
            out.append(Finding("guard-autorun", max(sev, Severity.MEDIUM), f"Autostart entry {verb}", key, [cmd]))
    for key in old_runs.keys() - now_runs.keys():
        out.append(Finding("guard-autorun-removed", Severity.LOW, "Autostart entry removed", key))
    state["autoruns"] = now_runs

    now_start = _startup_listing()
    old_start: dict = state.setdefault("startup", {})
    for folder, names in now_start.items():
        for name in sorted(set(names) - set(old_start.get(folder, []))):
            out.append(Finding("guard-startup", Severity.HIGH, "New item in the Startup folder",
                               os.path.join(folder, name)))
    state["startup"] = now_start

    if check_listeners:
        now_l = _listener_keys()
        if now_l is not None:
            for item in sorted(set(now_l) - set(state.get("listeners", []))):
                out.append(Finding("guard-listener", Severity.MEDIUM,
                                   "New network-reachable or AI service listener", item))
            state["listeners"] = now_l
    return out


# ------------------------------------------------------- live protection
# Three cheap real-time checks that run with the watch loop:
#   download shield  - files that appear in Downloads / Desktop are scanned at once
#   removable drives - a newly plugged drive gets its root checked (autorun.inf, executables)
#   ransomware canaries - decoy documents; any change to them means files are being rewritten

CANARY_NAME = "!hexward-canary-do-not-touch.docx"
_CANARY_BODY = (b"hexward ransomware canary. This decoy file is watched by the live guard; "
                b"if it changes, something is rewriting your documents.\r\n") * 40
_PARTIAL = (".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload")
_SHIELD_MAX = 256 * 1024 * 1024


def canary_paths() -> list[Path]:
    home = Path.home()
    return [d / CANARY_NAME for d in (home / "Documents", home / "Pictures") if d.is_dir()]


def set_canaries(on: bool) -> list[str]:
    """Create (hidden) or remove the decoy files and remember the choice."""
    paths = canary_paths()
    for p in paths:
        try:
            p.unlink(missing_ok=True)
            if on:
                p.write_bytes(_CANARY_BODY)
                if IS_WINDOWS:
                    import ctypes

                    ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x2)  # hidden
        except OSError:
            pass
    save_settings(canary=bool(on))
    return [str(p) for p in paths]


def _listing(folder: str) -> dict[str, tuple[int, int]]:
    out = {}
    try:
        with os.scandir(folder) as it:
            for e in it:
                try:
                    if e.is_file(follow_symlinks=False):
                        st = e.stat(follow_symlinks=False)
                        out[e.name] = (st.st_size, st.st_mtime_ns)
                except OSError:
                    pass
    except OSError:
        pass
    return out


def _removable_drives() -> set[str]:
    if not IS_WINDOWS:
        return set()
    try:
        import ctypes

        k32 = ctypes.windll.kernel32
        mask = k32.GetLogicalDrives()
        roots = (chr(65 + i) + ":" + os.sep for i in range(26) if mask >> i & 1)
        return {r for r in roots if k32.GetDriveTypeW(r) == 2}
    except Exception:
        return set()


def new_live_state() -> dict:
    from .scanner import Signatures, user_hotspots

    sigs = Signatures()
    sigs.load_user()
    folders = [d for d in user_hotspots() if os.path.basename(d).lower() in ("downloads", "desktop")]
    return {"sigs": sigs, "dirs": {d: _listing(d) for d in folders}, "drives": _removable_drives(),
            "canary": bool(load_settings().get("canary")), "canary_seen": {}, "canary_hit": set()}


def _scan_new(path: str, size: int, sigs, prefix: str) -> list[Finding]:
    from .scanner import analyze_file

    if size == 0 or size > _SHIELD_MAX:
        return []
    found = analyze_file(path, size, sigs)
    for f in found:
        f.title = f"{prefix}: {f.title}"
    return found


def _check_drive(root: str, sigs) -> list[Finding]:
    out: list[Finding] = []
    files = _listing(root)
    if any(name.lower() == "autorun.inf" for name in files):
        out.append(Finding("usb-autorun", Severity.MEDIUM, "Removable drive carries an autorun.inf", root + "autorun.inf",
                           advice="Classic USB-worm launcher. Do not open the drive by double-click; inspect or delete the file."))
    for name, (size, _mtime) in list(files.items())[:300]:
        try:
            out += _scan_new(os.path.join(root, name), size, sigs, "Removable drive")
        except OSError:
            pass
    return out


def _check_canaries(live: dict) -> list[Finding]:
    out = []
    for p in canary_paths():
        key = str(p)
        if key in live["canary_hit"]:
            continue
        try:
            st = os.stat(key)
            sig = (st.st_size, st.st_mtime_ns)
            if live["canary_seen"].get(key) == sig:
                continue
            if p.read_bytes() == _CANARY_BODY:
                live["canary_seen"][key] = sig
                continue
            what = "was rewritten"
        except OSError:
            what = "was deleted or renamed"
        live["canary_hit"].add(key)
        out.append(Finding(
            "ransomware-canary", Severity.CRITICAL, f"Ransomware-like activity: a decoy document {what}", key,
            advice="If you did not touch this file yourself, something is rewriting your documents right now: "
                   "disconnect from the network, power the PC off and restore from a backup on another device."))
    return out


def live_tick(live: dict) -> list[Finding]:
    out: list[Finding] = []
    now = time.time()
    for folder, known in live["dirs"].items():
        current = _listing(folder)
        for name, sig in current.items():
            if known.get(name) == sig or name.lower().endswith(_PARTIAL):
                continue
            if 0 <= now - sig[1] / 1e9 < 2:
                continue  # still being written; it is picked up on the next tick
            known[name] = sig
            try:
                out += _scan_new(os.path.join(folder, name), sig[0], live["sigs"], "Download shield")
            except OSError:
                pass
        for name in known.keys() - current.keys():
            del known[name]
    drives = _removable_drives()
    for root in sorted(drives - live["drives"]):
        out += _check_drive(root, live["sigs"])
    live["drives"] = drives
    if live["canary"]:
        out += _check_canaries(live)
    return out


def watch(state: dict, interval: float, net_interval: float, log_file: str | None, emit) -> None:
    """Blocking loop; `emit(findings)` is called for every batch of changes."""
    last_net = 0.0
    live = new_live_state()
    while True:
        now = time.monotonic()
        do_net = now - last_net >= net_interval
        if do_net:
            last_net = now
        try:
            found = diff(state, check_listeners=do_net) + live_tick(live)
        except Exception as exc:  # the guard must survive transient failures
            found = [Finding("guard-error", Severity.INFO, f"check failed: {type(exc).__name__}: {exc}")]
        if found:
            emit(found)
            if log_file:
                try:
                    with open(log_file, "a", encoding="utf-8") as fh:
                        for f in found:
                            fh.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), **f.to_dict()},
                                                ensure_ascii=False) + "\n")
                except OSError as exc:
                    safe_print(f"cannot write {log_file}: {exc}")
        time.sleep(interval)
