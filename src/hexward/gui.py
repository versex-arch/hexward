"""Desktop app: the interface is a single HTML page served by a private local
server and shown in a chromeless browser window (Edge/Chrome `--app` mode).

Security model of that server, since a security tool must not open a hole:
  * bound to 127.0.0.1 on a random port - never reachable from the network
  * every URL carries an unguessable per-run token; requests without it get 404
  * the Host header must match, which defeats DNS-rebinding
  * POST bodies must be JSON, which browsers cannot send cross-site without CORS
  * the page renders all finding text with textContent and ships a strict CSP
"""

from __future__ import annotations

import json
import locale
import os
import queue
import secrets
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import APP_NAME, __version__
from .core import IS_WINDOWS, Finding, Severity, data_dir, load_settings, notify, render_json, save_settings

LANGS = ("en", "ru", "kk", "de", "es", "zh")


def load_lang() -> str:
    """The language chosen in Settings, else HEXWARD_LANG, else English."""
    for candidate in (load_settings().get("lang"), os.environ.get("HEXWARD_LANG")):
        if candidate in LANGS:
            return candidate
    return "en"


def _asset(name: str) -> Path:
    return Path(__file__).with_name(name)


def icon_path() -> Path:
    return _asset("hexward.ico")


# ------------------------------------------------------------------ checks
# name -> function(path) returning (findings, notes); run on a worker thread.

def _task_quick(_path):
    from .quick import run_quick

    return run_quick(None)


def _task_system(_path):
    from .netinfo import audit_network, get_listeners
    from .sysaudit import audit_system

    return audit_system() + audit_network(get_listeners()), []


def _task_files(path):
    from . import scanner

    found, stats = scanner.scan([path])
    return found, [stats.note()] + stats.errors[:5]


def _task_logs(path):
    from .logs import analyze_path

    kind, found = analyze_path(path)
    return found, [f"{os.path.basename(path)}: {kind} log"]


def _task_ai(path):
    from .aiguard import audit_ai
    from .netinfo import get_listeners

    return audit_ai(path or None, get_listeners(), probe=True)


def _task_winlog(_path):
    from .winevent import analyze_windows_events

    return analyze_windows_events(), []


def _task_harden(_path):
    from .harden import audit_hardening

    return audit_hardening(), []


TASKS = {"quick": _task_quick, "harden": _task_harden, "system": _task_system, "files": _task_files, "logs": _task_logs,
         "ai": _task_ai, "winlog": _task_winlog}
NEEDS_PATH = {"files", "logs"}


# ------------------------------------------------------------------- state

class AppState:
    def __init__(self):
        self.lock = threading.Lock()
        self.rev = 0
        self.busy = False
        self.task = ""
        self.error = ""
        self.runs: dict[str, dict] = {}       # task -> {findings: [Finding], notes, secs, at}
        self.alerts: list[tuple[str, Finding]] = []
        self.watch_stop: threading.Event | None = None
        self.watch_files = 0
        self.watch_error = ""
        self.lang = load_lang()
        settings = load_settings()
        self.canary = bool(settings.get("canary"))
        self.ignored: set[tuple[str, str]] = {tuple(x) for x in settings.get("ignored", [])
                                              if isinstance(x, list) and len(x) == 2}
        self.activity: list[dict] = []
        self._load_history()
        self.started = time.monotonic()
        self.last_poll = 0.0
        self.bye_at = 0.0
        self.dialogs: queue.Queue = queue.Queue()
        self.can_dialog = False
        self.persistent = False     # keep running after the window closes (background / autostart)
        self.exit_now = False
        self.info: dict = {"defender": None, "firewall": None, "autostart": False, "sigs": 0}
        self.info_at = 0.0

    def bump(self) -> None:
        self.rev += 1

    # -- history: results survive a restart, like any antivirus report log
    def _load_history(self) -> None:
        try:
            saved = json.loads((data_dir() / "history.json").read_text(encoding="utf-8"))
            if "runs" in saved and isinstance(saved.get("activity"), list):
                self.activity = [a for a in saved["activity"] if isinstance(a, dict)][:40]
                saved = saved["runs"]
            for task, run in saved.items():
                if task not in TASKS:
                    continue
                found = [Finding(str(f["rule"]), Severity.parse(f["severity"]), str(f["title"]), str(f.get("target", "")),
                                 [str(e) for e in f.get("evidence", [])], str(f.get("advice", "")))
                         for f in run["findings"]]
                self.runs[task] = {"findings": found, "notes": [str(n) for n in run.get("notes", [])],
                                   "secs": float(run.get("secs", 0)), "at": float(run["at"])}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            self.runs = {}

    def _save_history(self) -> None:
        with self.lock:
            data = {task: {"findings": [f.to_dict() for f in r["findings"] if f is not None],
                           "notes": r["notes"], "secs": r["secs"], "at": r["at"]} for task, r in self.runs.items()}
            data = {"runs": data, "activity": self.activity}
        try:
            path = data_dir() / "history.json"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass

    def _log(self, kind: str, task: str, found: list[Finding]) -> None:
        """Append to the activity journal (caller holds the lock)."""
        worst = max((f.severity for f in found), default=None)
        self.activity = ([{"at": time.time(), "kind": kind, "task": task, "count": len(found),
                           "worst": worst.name if worst is not None else ""}] + self.activity)[:40]

    def _refresh_info(self) -> None:
        """OS protection state for the overview; registry reads, refreshed at most every 30 s."""
        now = time.monotonic()
        if self.info_at and now - self.info_at < 30:
            return
        self.info_at = now
        try:
            from . import autostart
            from .sysaudit import protection_status

            self.info.update(protection_status())
            self.info["autostart"] = autostart.is_enabled()
        except Exception:
            pass

    def _count_signatures(self) -> None:
        from . import scanner

        sigs = scanner.Signatures()
        sigs.load_user()
        with self.lock:
            self.info["sigs"] = len(sigs.hashes)
            self.bump()

    def _hidden(self, f: Finding | None) -> bool:
        return f is None or (f.rule, f.target) in self.ignored

    @staticmethod
    def _view(i: int, f: Finding, stamp: str = "") -> dict:
        d = f.to_dict()
        d.update(id=i, quarantinable=f.rule == "malware-signature", time=stamp)
        return d

    def snapshot(self, known_rev: int = -1) -> dict:
        with self.lock:
            self.last_poll = time.monotonic()
            if known_rev == self.rev:
                return {"rev": self.rev}  # nothing changed: the idle window costs almost nothing
            self._refresh_info()
            return {
                "info": dict(self.info, persistent=self.persistent), "activity": self.activity[:12],
                "rev": self.rev, "version": __version__, "lang": self.lang, "windows": IS_WINDOWS,
                "busy": self.busy, "task": self.task, "error": self.error,
                "watch": {"on": self.watch_stop is not None, "files": self.watch_files, "error": self.watch_error},
                "canary": self.canary, "ignored": len(self.ignored),
                "runs": {name: {"findings": [self._view(i, f) for i, f in enumerate(r["findings"]) if not self._hidden(f)],
                                "notes": r["notes"], "secs": r["secs"], "at": r["at"]}
                         for name, r in self.runs.items()},
                "alerts": [self._view(i, f, stamp) for i, (stamp, f) in enumerate(self.alerts) if not self._hidden(f)],
            }

    # -- checks
    def start(self, task: str, path: str | None) -> str | None:
        """Start a check; returns an error message or None."""
        if task not in TASKS:
            return "unknown task"
        if task in NEEDS_PATH and not (path and os.path.exists(path)):
            return "path does not exist"
        if task == "ai" and path and not os.path.isdir(path):
            return "not a folder"
        with self.lock:
            if self.busy:
                return "a check is already running"
            self.busy, self.task, self.error = True, task, ""
            self.bump()
        threading.Thread(target=self._work, args=(task, path), daemon=True, name="check").start()
        return None

    def _work(self, task: str, path: str | None) -> None:
        began = time.perf_counter()
        try:
            found, notes = TASKS[task](path)
            result, error = {"findings": list(found), "notes": [str(n) for n in notes],
                             "secs": round(time.perf_counter() - began, 1), "at": time.time()}, ""
        except Exception as exc:  # reported in the window; the app keeps running
            result, error = None, f"{type(exc).__name__}: {exc}"
        with self.lock:
            if result is not None:
                self.runs[task] = result
                self._log("check", task, [f for f in result["findings"] if not self._hidden(f)])
        if result is not None:
            self._save_history()  # on disk before the check is reported as finished
        with self.lock:
            self.busy, self.error = False, error
            self.bump()

    def ignore(self, task: str, index: int) -> bool:
        """Hide a finding (by rule + target) from now on - the exclusions list."""
        with self.lock:
            if task == "alerts":
                items = [f for _, f in self.alerts]
            else:
                items = self.runs.get(task, {}).get("findings", [])
            f = items[index] if 0 <= index < len(items) else None
            if f is None:
                return False
            self.ignored.add((f.rule, f.target))
            ignored = sorted(self.ignored)
            self.bump()
        save_settings(ignored=[list(x) for x in ignored])
        return True

    def clear_ignored(self) -> None:
        with self.lock:
            self.ignored.clear()
            self.bump()
        save_settings(ignored=[])

    def set_canary(self, on: bool) -> None:
        from . import guard

        guard.set_canaries(on)
        with self.lock:
            self.canary = bool(on)
            running = self.watch_stop is not None
            self.bump()
        if running:  # restart so the watcher picks the new setting up
            self.set_watch(False)
            self.set_watch(True)

    def quarantine(self, task: str, index: int) -> str | None:
        from . import scanner

        with self.lock:
            items = self.runs.get(task, {}).get("findings", [])
            f = items[index] if 0 <= index < len(items) else None
        if f is None or f.rule != "malware-signature":
            return "only signature matches can be quarantined"
        try:
            scanner.quarantine_file(f.target, f.title)
        except OSError as exc:
            return str(exc)
        with self.lock:
            items[index] = None  # keep the other ids stable
            self.bump()
        self._save_history()
        return None

    # -- live guard
    def set_watch(self, on: bool, remember: bool = False) -> None:
        if remember:  # the user's own choice is restored at the next start
            save_settings(guard=bool(on))
        with self.lock:
            if not on:
                if self.watch_stop is not None:
                    self.watch_stop.set()
                    self.watch_stop = None
                    self.bump()
                return
            if self.watch_stop is not None:
                return
            stop = self.watch_stop = threading.Event()
            self.bump()
        threading.Thread(target=self._watch, args=(stop,), daemon=True, name="guard").start()

    def _watch(self, stop: threading.Event) -> None:
        from . import guard

        try:
            state = guard.load_baseline()
            if state is None:
                state = guard.snapshot()
                guard.save_baseline(state)
            with self.lock:
                self.watch_files = len(state["files"])
                self.watch_error = ""
                self.bump()
            live = guard.new_live_state()
            tick = 0
            while not stop.wait(5.0):
                tick += 1
                found = guard.diff(state, check_listeners=tick % 6 == 0) + guard.live_tick(live)
                if found:
                    stamp = time.strftime("%H:%M:%S")
                    with self.lock:
                        self.alerts = ([(stamp, f) for f in found] + self.alerts)[:300]
                        self._log("alert", "alerts", found)
                        unseen = time.monotonic() - self.last_poll > 5
                        self.bump()
                    self._save_history()
                    if unseen:  # no window is watching: tell the user through the OS
                        worst = max(found, key=lambda f: f.severity)
                        notify(f"{APP_NAME}: {worst.title}", worst.target or f"{len(found)} change(s) detected")
        except Exception as exc:
            with self.lock:
                self.watch_error = f"{type(exc).__name__}: {exc}"
                if self.watch_stop is stop:
                    self.watch_stop = None
                self.bump()

    def set_autostart(self, on: bool) -> str | None:
        from . import autostart

        try:
            autostart.set_enabled(on)
        except OSError as exc:
            return str(exc)
        with self.lock:
            self.info["autostart"] = bool(on)
            self.persistent = self.persistent or bool(on)
            self.bump()
        return None

    def set_lang(self, lang: str) -> bool:
        if lang not in LANGS:
            return False
        with self.lock:
            self.lang = lang
            self.bump()
        save_settings(lang=lang)
        return True

    def accept_baseline(self) -> str | None:
        """Save the current system state as the trusted baseline; restart the guard if it runs."""
        from . import guard

        try:
            guard.save_baseline(guard.snapshot())
        except OSError as exc:
            return str(exc)
        with self.lock:
            running = self.watch_stop is not None
        if running:
            self.set_watch(False)
            self.set_watch(True)
        return None

    def quarantine_action(self, action: str, qid: str) -> dict:
        from . import scanner

        try:
            if action == "restore":
                result = {"ok": True, "path": scanner.quarantine_restore(qid)}
            else:
                scanner.quarantine_delete(qid)
                result = {"ok": True}
        except (ValueError, OSError) as exc:
            return {"ok": False, "error": str(exc)}
        with self.lock:
            self.bump()
        return result

    def report(self, task: str) -> str:
        with self.lock:
            if task == "alerts":
                return render_json([f for _, f in self.alerts])
            run = self.runs.get(task) or {"findings": [], "notes": []}
            return render_json([f for f in run["findings"] if f is not None], run["notes"])

    def should_exit(self) -> bool:
        now = time.monotonic()
        with self.lock:
            if self.exit_now:
                return True
            if self.persistent:
                return False  # background protection outlives the window
            if self.bye_at and now - self.bye_at > 3 and self.last_poll < self.bye_at:
                return True   # window closed (a reload would have polled again)
            if self.last_poll:
                return now - self.last_poll > 180  # background windows are throttled to ~1 poll/min
            return now - self.started > 120       # the window never appeared


# ------------------------------------------------------------------ server

_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'")


def make_server(state: AppState) -> tuple[ThreadingHTTPServer, str]:
    token = secrets.token_urlsafe(24)
    prefix = f"/{token}/"

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:  # no console under pythonw; nothing to log
            pass

        def _send(self, code: int, body: bytes = b"", ctype: str = "application/json", extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def _route(self) -> tuple[str, dict] | None:
            host = self.headers.get("Host", "")
            if host != f"127.0.0.1:{self.server.server_address[1]}":
                return None
            parts = urlsplit(self.path)
            if not parts.path.startswith(prefix):
                return None
            return parts.path[len(prefix):], parse_qs(parts.query)

        def do_GET(self) -> None:
            if self.path == "/favicon.ico":
                try:
                    self._send(200, icon_path().read_bytes(), "image/x-icon")
                except OSError:
                    self._send(404)
                return
            route = self._route()
            if route is None:
                self._send(404)
                return
            path, query = route
            if path == "":
                self._send(200, _asset("ui.html").read_bytes(), "text/html; charset=utf-8",
                           {"Content-Security-Policy": _CSP, "Referrer-Policy": "no-referrer"})
            elif path == "api/state":
                try:
                    known = int((query.get("rev") or ["-1"])[0])
                except ValueError:
                    known = -1
                self._json(state.snapshot(known))
            elif path == "api/quarantine":
                from . import scanner

                self._json({"items": scanner.quarantine_list()})
            elif path == "api/report":
                task = (query.get("task") or [""])[0]
                safe = "".join(c for c in task if c.isalnum())[:20] or "report"
                name = f"{APP_NAME}-{safe}-{time.strftime('%Y%m%d-%H%M')}.json"
                self._send(200, (state.report(task) + "\n").encode("utf-8"), "application/json; charset=utf-8",
                           {"Content-Disposition": f'attachment; filename="{name}"'})
            else:
                self._send(404)

        def do_POST(self) -> None:
            route = self._route()
            if route is None:
                self._send(404)
                return
            path, _ = route
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if not 0 <= length <= 65536:
                self._send(413)
                return
            raw = self.rfile.read(length) if length else b""
            if path == "api/bye":  # sent by navigator.sendBeacon when the window closes
                with state.lock:
                    state.bye_at = time.monotonic()
                self._send(204)
                return
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._send(415)
                return
            try:
                body = json.loads(raw or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                self._send(400)
                return
            if path == "api/run":
                path_arg = body.get("path")
                err = state.start(str(body.get("task")), str(path_arg) if path_arg else None)
                self._json({"ok": err is None, "error": err})
            elif path == "api/watch":
                state.set_watch(bool(body.get("on")), remember=True)
                self._json({"ok": True})
            elif path == "api/autostart":
                err = state.set_autostart(bool(body.get("on")))
                self._json({"ok": err is None, "error": err})
            elif path == "api/quit":
                with state.lock:
                    state.exit_now = True
                self._json({"ok": True})
            elif path == "api/quarantine":
                try:
                    err = state.quarantine(str(body.get("task")), int(body.get("id")))
                except (TypeError, ValueError):
                    err = "bad request"
                self._json({"ok": err is None, "error": err})
            elif path in ("api/qrestore", "api/qdelete"):
                self._json(state.quarantine_action(path[5:], str(body.get("id") or "")))
            elif path == "api/settings":
                self._json({"ok": state.set_lang(str(body.get("lang")))})
            elif path == "api/ignore":
                try:
                    ok = state.ignore(str(body.get("task")), int(body.get("id")))
                except (TypeError, ValueError):
                    ok = False
                self._json({"ok": ok})
            elif path == "api/unignore":
                state.clear_ignored()
                self._json({"ok": True})
            elif path == "api/canary":
                state.set_canary(bool(body.get("on")))
                self._json({"ok": True})
            elif path == "api/baseline":
                err = state.accept_baseline()
                self._json({"ok": err is None, "error": err})
            elif path == "api/pick":
                if not state.can_dialog:
                    self._json({"path": None, "manual": True})
                    return
                reply: queue.Queue = queue.Queue()
                state.dialogs.put(("file" if body.get("kind") == "file" else "dir", reply))
                try:
                    self._json({"path": reply.get(timeout=900), "manual": False})
                except queue.Empty:
                    self._json({"path": None, "manual": False})
            else:
                self._send(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    return server, f"http://127.0.0.1:{server.server_address[1]}{prefix}"


# ------------------------------------------------------------------ window

def _find_browser() -> str | None:
    """A Chromium browser that supports `--app=` (a window without tabs or address bar)."""
    if IS_WINDOWS:
        roots = [os.environ.get(v) for v in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")]
        for rel in ("Microsoft/Edge/Application/msedge.exe", "Google/Chrome/Application/chrome.exe"):
            for root in roots:
                if root and (Path(root) / rel).is_file():
                    return str(Path(root) / rel)
        return None
    if sys.platform == "darwin":
        for app in ("Google Chrome", "Microsoft Edge", "Chromium", "Brave Browser"):
            exe = Path(f"/Applications/{app}.app/Contents/MacOS/{app}")
            if exe.is_file():
                return str(exe)
        return None
    for name in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def open_window(url: str) -> None:
    browser = _find_browser()
    if browser:
        try:
            subprocess.Popen([browser, f"--app={url}", "--window-size=1320,900"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except OSError:
            pass
    import webbrowser

    webbrowser.open(url)


def _instance_file() -> Path:
    return data_dir() / "instance.json"


def running_instance() -> str | None:
    """URL of an already running app (for example the one started with Windows), if it answers."""
    import urllib.request

    try:
        url = str(json.loads(_instance_file().read_text(encoding="utf-8"))["url"])
        if not url.startswith("http://127.0.0.1:"):
            return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url + "api/state?rev=-2", timeout=1.5) as resp:
            return url if resp.status == 200 else None
    except Exception:
        return None


def main(open_browser: bool = True, background: bool = False) -> int:
    existing = running_instance()
    if existing:  # one protection process is enough: just show its window
        if open_browser and not background:
            open_window(existing)
        return 0

    state = AppState()
    settings = load_settings()
    state.persistent = background or state.info.get("autostart", False)
    try:
        from . import autostart

        state.persistent = background or autostart.is_enabled()
    except Exception:
        pass
    server, url = make_server(state)
    threading.Thread(target=server.serve_forever, daemon=True, name="http").start()
    threading.Thread(target=state._count_signatures, daemon=True, name="sigs").start()
    try:
        _instance_file().write_text(json.dumps({"url": url, "pid": os.getpid()}), encoding="utf-8")
    except OSError:
        pass
    if background or settings.get("guard"):
        state.set_watch(True)
    if background:
        pass
    elif open_browser:
        open_window(url)
    elif sys.stdout is not None:
        print(url, flush=True)

    # The main thread owns the native file dialogs (tkinter must stay on one thread).
    root = None
    try:
        import tkinter as tk
        from tkinter import filedialog

        if IS_WINDOWS:
            try:
                import ctypes

                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        root = tk.Tk()
        root.withdraw()
        try:
            root.iconbitmap(str(icon_path()))
        except Exception:
            pass
        state.can_dialog = True
    except Exception:  # no tkinter / no display: the page asks for a typed path instead
        root = None

    try:
        if root is None:
            while not state.should_exit():
                time.sleep(0.5)
        else:
            def tick() -> None:
                try:
                    kind, reply = state.dialogs.get_nowait()
                except queue.Empty:
                    pass
                else:
                    root.attributes("-topmost", True)
                    root.update()
                    if kind == "file":
                        picked = filedialog.askopenfilename(parent=root, title=APP_NAME)
                    else:
                        picked = filedialog.askdirectory(parent=root, title=APP_NAME, mustexist=True)
                    reply.put(os.path.normpath(picked) if picked else None)
                if state.should_exit():
                    root.destroy()
                else:
                    root.after(150 if time.monotonic() - state.last_poll < 10 else 600, tick)

            root.after(150, tick)
            root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        state.set_watch(False)
        server.shutdown()
        try:
            _instance_file().unlink(missing_ok=True)
        except OSError:
            pass
    return 0


# ------------------------------------------------------------- shortcut

def create_shortcut() -> str:
    """Create a desktop launcher that opens the app without a console. Returns its path."""
    from .core import run_cmd

    if IS_WINDOWS:
        pyw = Path(sys.executable).with_name("pythonw.exe")
        if not pyw.is_file():
            raise OSError("pythonw.exe not found next to python.exe")

        def q(value) -> str:
            return "'" + str(value).replace("'", "''") + "'"

        # Windows caches icons by path, so a changed icon keeps showing the old picture.
        # Giving the icon file a name derived from its content makes every new design a new path.
        import hashlib
        import shutil

        source = icon_path()
        icon = data_dir() / f"icon-{hashlib.sha256(source.read_bytes()).hexdigest()[:8]}.ico"
        if not icon.is_file():
            shutil.copyfile(source, icon)

        script = (
            "$d=[Environment]::GetFolderPath('Desktop');"
            f"$p=Join-Path $d {q(APP_NAME + '.lnk')};"
            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($p);"
            f"$s.TargetPath={q(pyw)};$s.Arguments='-m {APP_NAME} gui';"
            f"$s.IconLocation={q(icon)};$s.WorkingDirectory=$env:USERPROFILE;"
            f"$s.Description={q(APP_NAME + ' security toolkit')};$s.Save();Write-Output $p"
        )
        out = run_cmd(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=30)
        if not out or not out.strip():
            raise OSError("could not create the shortcut (PowerShell blocked?)")
        try:
            import ctypes

            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x1000, None, None)  # ask Explorer to redraw icons
        except Exception:
            pass
        return out.strip().splitlines()[-1]
    apps = Path.home() / ".local/share/applications"
    apps.mkdir(parents=True, exist_ok=True)
    path = apps / f"{APP_NAME}.desktop"
    path.write_text(
        f"[Desktop Entry]\nType=Application\nName={APP_NAME}\nComment=Security toolkit\n"
        f"Exec={sys.executable} -m {APP_NAME} gui\nTerminal=false\nCategories=System;Security;\n",
        encoding="utf-8")
    return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
