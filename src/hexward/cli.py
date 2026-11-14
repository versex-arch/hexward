"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import APP_NAME, __version__
from .core import Finding, Severity, render_json, render_text, safe_print, want_color

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _common() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("output")
    g.add_argument("--json", action="store_true", help="machine-readable JSON output")
    g.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    g.add_argument("--min-severity", default="low", choices=[s.name.lower() for s in Severity],
                   help="hide findings below this level (default: low)")
    g.add_argument("--fail-on", default="medium", choices=[s.name.lower() for s in Severity],
                   help="exit with code 1 when a finding at or above this level exists (default: medium)")
    g.add_argument("--no-color", action="store_true")
    return p


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Host security toolkit: log analysis, malware scan, system audit, AI-agent guard.")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("logs", parents=[common], help="analyze auth.log / nginx / apache logs")
    p.add_argument("files", nargs="+", help="log files (.gz/.bz2 supported, '-' for stdin)")
    p.add_argument("--type", default="auto", choices=["auto", "auth", "web"])
    p.add_argument("--threshold", type=int, default=5, help="failed logins before an IP is reported (default 5)")
    p.add_argument("--window", type=int, default=10, help="burst window in minutes (default 10)")
    p.add_argument("--scan-threshold", type=int, default=20, help="4xx responses before an IP counts as scanning")
    p.add_argument("--flood-rpm", type=int, default=300, help="requests per minute that count as a flood")
    p.add_argument("--allow-ip", action="append", default=[], metavar="CIDR", help="never report this address/network")
    p.add_argument("--limit", type=int, default=25, help="max findings per category (default 25)")

    p = sub.add_parser("winlog", parents=[common], help="analyze the Windows Security/System event logs")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--threshold", type=int, default=5)

    p = sub.add_parser("scan", parents=[common], help="scan files for malware (signatures + heuristics)")
    p.add_argument("paths", nargs="*", help="files or folders (default: download/temp/startup folders)")
    p.add_argument("--quarantine", action="store_true", help="quarantine signature matches (never heuristic hits)")
    p.add_argument("--no-cache", action="store_true", help="rescan files already known clean")
    p.add_argument("--thorough", action="store_true", help="fully hash large media files too (slower)")
    p.add_argument("--workers", type=int, default=0, help="threads (default: CPU count, max 8)")
    p.add_argument("--max-size", type=int, default=256, metavar="MB", help="skip larger files (default 256)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="e.g. '*/node_modules/*'")

    sub.add_parser("audit", parents=[common], help="audit persistence, security settings, processes, network")
    sub.add_parser("harden", parents=[common], help="vulnerability scan: weak system settings, account problems, browser hijacks")

    p = sub.add_parser("ai", parents=[common], help="AI-agent guard: exposed model servers, risky agent/MCP config, prompt injection")
    p.add_argument("path", nargs="?", help="workspace to scan for prompt injection (default: current folder)")
    p.add_argument("--probe", action="store_true", help="ask local AI ports (127.0.0.1 only) whether they answer unauthenticated")
    p.add_argument("--no-workspace", action="store_true", help="skip the workspace scan")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="workspace-relative path to skip, e.g. 'tests/*' (repeatable)")

    sub.add_parser("quick", parents=[common], help="everything at once: audit + harden + ai + scan of risky folders")

    p = sub.add_parser("guard", parents=[common], help="integrity baseline and live watch")
    p.add_argument("action", choices=["init", "check", "watch", "canary-on", "canary-off"])
    p.add_argument("--add", action="append", default=[], metavar="PATH", help="extra file/folder to protect (with init)")
    p.add_argument("--interval", type=float, default=5.0, help="seconds between checks (watch)")
    p.add_argument("--net-interval", type=float, default=30.0, help="seconds between listener checks (watch)")
    p.add_argument("--log", metavar="FILE", help="append alerts as JSON lines (watch)")

    p = sub.add_parser("gui", help="open the desktop window")
    p.add_argument("--background", action="store_true",
                   help="no window: keep the live guard running and notify about alerts (used by autostart)")
    p = sub.add_parser("autostart", help="start in the background when you sign in")
    p.add_argument("action", choices=["on", "off", "status"])
    sub.add_parser("shortcut", help="put a desktop shortcut that opens the window without a console")

    p = sub.add_parser("quarantine", help="manage quarantined files")
    p.add_argument("action", choices=["list", "restore", "delete"])
    p.add_argument("id", nargs="?")

    p = sub.add_parser("sigs", help="manage SHA-256 malware signatures")
    p.add_argument("action", choices=["stats", "import"])
    p.add_argument("source", nargs="?", help="file or https:// URL with one SHA-256 per line")
    return parser


def _report(args, findings: list[Finding], notes: list[str]) -> int:
    floor = Severity.parse(args.min_severity)
    shown = [f for f in findings if f.severity >= floor]
    hidden = len(findings) - len(shown)
    if hidden:
        notes = notes + [f"{hidden} finding(s) below '{args.min_severity}' hidden (--min-severity info)"]
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(render_json(shown, notes) if args.json else render_text(shown, False, notes))
                fh.write("\n")
        except OSError as exc:
            safe_print(f"error: cannot write {args.output}: {exc}", sys.stderr)
            return EXIT_ERROR
        safe_print(f"report written to {args.output} ({len(shown)} findings)")
    elif args.json:
        safe_print(render_json(shown, notes))
    else:
        safe_print(render_text(shown, want_color(sys.stdout, args.no_color), notes))
    gate = Severity.parse(args.fail_on)
    return EXIT_FINDINGS if any(f.severity >= gate for f in findings) else EXIT_CLEAN


def cmd_logs(args) -> int:
    from .logs import AllowList, analyze_path

    try:
        allow = AllowList(args.allow_ip)
    except ValueError as exc:
        safe_print(f"error: bad --allow-ip value: {exc}", sys.stderr)
        return EXIT_ERROR
    findings, notes, failed = [], [], 0
    for path in args.files:
        start = time.perf_counter()
        try:
            kind, found = analyze_path(
                path, args.type, threshold=args.threshold, window_min=args.window,
                scan_threshold=args.scan_threshold, flood_rpm=args.flood_rpm, allow=allow, limit=args.limit)
        except (OSError, EOFError) as exc:
            safe_print(f"error: {path}: {exc}", sys.stderr)
            failed += 1
            continue
        findings += found
        notes.append(f"logs: {path} parsed as {kind} in {time.perf_counter() - start:.2f}s")
    code = _report(args, findings, notes)
    return EXIT_ERROR if failed and code == EXIT_CLEAN else code


def cmd_winlog(args) -> int:
    from .winevent import analyze_windows_events

    return _report(args, analyze_windows_events(args.hours, args.threshold), [])


def _scan(args, paths, quarantine=False, **kw):
    from . import scanner

    findings, stats = scanner.scan(paths, progress=sys.stderr.isatty() and not args.json, **kw)
    notes = [stats.note()] + [f"scan: {e}" for e in stats.errors[:10]]
    if quarantine:
        for f in findings:
            if f.rule != "malware-signature":
                continue
            try:
                qid = scanner.quarantine_file(f.target, f.title)
                f.evidence.append(f"QUARANTINED as {qid} (restore: {APP_NAME} quarantine restore {qid})")
            except OSError as exc:
                f.evidence.append(f"quarantine FAILED: {exc}")
    return findings, notes


def cmd_scan(args) -> int:
    from . import scanner

    paths = args.paths or scanner.user_hotspots()
    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        safe_print("error: no such path: " + ", ".join(missing), sys.stderr)
        return EXIT_ERROR
    findings, notes = _scan(args, paths, args.quarantine, use_cache=not args.no_cache, workers=args.workers, thorough=args.thorough,
                            max_size_mb=args.max_size, excludes=args.exclude)
    return _report(args, findings, notes)


def cmd_audit(args) -> int:
    from .netinfo import audit_network, get_listeners
    from .sysaudit import audit_system

    return _report(args, audit_system() + audit_network(get_listeners()), [])


def cmd_harden(args) -> int:
    from .harden import audit_hardening

    return _report(args, audit_hardening(), [])


def cmd_ai(args) -> int:
    from .aiguard import audit_ai
    from .netinfo import get_listeners

    workspace = None if args.no_workspace else (args.path or os.getcwd())
    if workspace and not os.path.isdir(workspace):
        safe_print(f"error: not a folder: {workspace}", sys.stderr)
        return EXIT_ERROR
    findings, notes = audit_ai(workspace, get_listeners(), args.probe, args.exclude)
    return _report(args, findings, notes)


def cmd_quick(args) -> int:
    from .quick import run_quick

    # The prompt-injection scan is for project folders. Started from a system
    # directory or a drive root (e.g. an admin console opens in System32) it
    # would only crawl OS files, so skip it there.
    cwd = os.path.abspath(os.getcwd())
    system_roots = [os.environ.get(v, "") for v in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)")]
    system_roots += ["/usr", "/etc", "/bin", "/System", "/Library"]
    in_system = any(r and os.path.normcase(cwd).startswith(os.path.normcase(os.path.abspath(r)))
                    for r in system_roots)
    # The home folder (or anything above it) is not a project either: crawling the
    # whole profile for prompt injection would take minutes.
    home = os.path.normcase(os.path.abspath(os.path.expanduser("~")))
    above_home = (home + os.sep).startswith(os.path.normcase(cwd).rstrip(os.sep) + os.sep)
    workspace = None if in_system or above_home or os.path.dirname(cwd) == cwd else cwd
    findings, notes = run_quick(workspace, progress=sys.stderr is not None and sys.stderr.isatty() and not args.json)
    if workspace is None:
        notes.append(f"ai: workspace scan skipped ({cwd} is not a project folder) - "
                     f"run `{APP_NAME} ai <project folder>` to check a project")
    return _report(args, findings, notes)


def cmd_guard(args) -> int:
    from . import guard

    if args.action in ("canary-on", "canary-off"):
        paths = guard.set_canaries(args.action == "canary-on")
        verb = "created" if args.action == "canary-on" else "removed"
        safe_print(f"ransomware canaries {verb}: " + (", ".join(paths) or "no Documents/Pictures folder found"))
        return EXIT_CLEAN
    if args.action == "init":
        snap = guard.snapshot(args.add)
        path = guard.save_baseline(snap)
        present = sum(1 for v in snap["files"].values() if v)
        safe_print(f"baseline saved to {path}: {present} existing / {len(snap['files'])} watched files, "
                   f"{len(snap['autoruns'])} autostart entries, {len(snap['listeners'])} listeners")
        return EXIT_CLEAN
    state = guard.load_baseline()
    if state is None:
        safe_print(f"error: no baseline yet - run `{APP_NAME} guard init` first", sys.stderr)
        return EXIT_ERROR
    if args.action == "check":
        return _report(args, guard.diff(state), [f"guard: compared with baseline from {state.get('created')}"])

    color = want_color(sys.stdout, args.no_color)

    def emit(found: list[Finding]) -> None:
        stamp = time.strftime("%H:%M:%S")
        body = render_text(found, color).rsplit("\n", 1)[0]
        safe_print(f"\a--- {stamp} ---\n{body}")

    safe_print(f"watching {len(state['files'])} files, autostart entries and listeners "
               f"every {args.interval:g}s - Ctrl+C to stop")
    try:
        guard.watch(state, max(args.interval, 0.5), args.net_interval, args.log, emit)
    except KeyboardInterrupt:
        safe_print("stopped")
    return EXIT_CLEAN


def cmd_quarantine(args) -> int:
    from . import scanner

    try:
        if args.action == "list":
            items = scanner.quarantine_list()
            for it in items:
                safe_print(f"{it['id']}  {it['time']}  {it['path']}\n    {it['reason']}  sha256 {it['sha256']}")
            safe_print(f"{len(items)} item(s) in quarantine")
            return EXIT_CLEAN
        if not args.id:
            safe_print("error: an id is required (see `quarantine list`)", sys.stderr)
            return EXIT_ERROR
        if args.action == "restore":
            safe_print(f"restored to {scanner.quarantine_restore(args.id)}")
        else:
            scanner.quarantine_delete(args.id)
            safe_print("deleted")
        return EXIT_CLEAN
    except (ValueError, OSError) as exc:
        safe_print(f"error: {exc}", sys.stderr)
        return EXIT_ERROR


def cmd_sigs(args) -> int:
    from . import scanner

    if args.action == "stats":
        sigs = scanner.Signatures()
        sigs.load_user()
        safe_print(f"{len(sigs.hashes)} SHA-256 signatures loaded (version {sigs.version})")
        return EXIT_CLEAN
    if not args.source:
        safe_print("error: give a file or https:// URL", sys.stderr)
        return EXIT_ERROR
    try:
        dest, count = scanner.import_signatures(args.source)
    except (ValueError, OSError) as exc:
        safe_print(f"error: {exc}", sys.stderr)
        return EXIT_ERROR
    safe_print(f"imported {count} signatures into {dest}")
    return EXIT_CLEAN


def cmd_gui(args) -> int:
    from .gui import main as gui_main

    return gui_main(background=args.background)


def cmd_autostart(args) -> int:
    from . import autostart

    try:
        if args.action != "status":
            autostart.set_enabled(args.action == "on")
    except OSError as exc:
        safe_print(f"error: {exc}", sys.stderr)
        return EXIT_ERROR
    safe_print("autostart is " + ("on: " + autostart.command() if autostart.is_enabled() else "off"))
    return EXIT_CLEAN


def cmd_shortcut(args) -> int:
    from .gui import create_shortcut

    try:
        safe_print(f"shortcut created: {create_shortcut()}")
    except OSError as exc:
        safe_print(f"error: {exc}", sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


COMMANDS = {"gui": cmd_gui, "autostart": cmd_autostart, "shortcut": cmd_shortcut, "logs": cmd_logs, "winlog": cmd_winlog, "scan": cmd_scan, "audit": cmd_audit, "harden": cmd_harden, "ai": cmd_ai,
            "quick": cmd_quick, "guard": cmd_guard, "quarantine": cmd_quarantine, "sigs": cmd_sigs}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for stream in (s for s in (sys.stdout, sys.stderr) if s is not None):
        # Piped/redirected output is UTF-8 (JSON consumers expect it); a real
        # console keeps its own code page and unencodable characters degrade to '?'.
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    if not args.command:
        parser.print_help()
        return EXIT_ERROR
    try:
        return COMMANDS[args.command](args)
    except KeyboardInterrupt:
        safe_print("\ninterrupted", sys.stderr)
        return 130
    except BrokenPipeError:
        return EXIT_CLEAN
