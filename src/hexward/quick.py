"""The quick check: system audit, vulnerability scan, AI-agent audit and a scan
of the folders where malware usually lands - run in parallel.

The four parts are independent and mostly wait on other processes
(PowerShell, netstat) or on disk, so running them side by side cuts the wall
time to roughly that of the slowest part.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .core import Finding, Severity


def run_quick(workspace: str | None = None, progress: bool = False) -> tuple[list[Finding], list[str]]:
    from . import scanner
    from .aiguard import audit_ai
    from .harden import audit_hardening
    from .netinfo import audit_network, get_listeners
    from .sysaudit import audit_system

    def network_and_ai() -> tuple[list[Finding], list[str]]:
        listeners = get_listeners()
        found, notes = audit_ai(workspace, listeners)
        return audit_network(listeners) + found, notes

    def guarded(fn, label: str):
        try:
            return fn()
        except Exception as exc:  # one failing part must not lose the others
            failure = [Finding("quick-error", Severity.INFO, f"{label} failed: {type(exc).__name__}: {exc}")]
            return (failure, []) if fn is network_and_ai else failure

    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="quick") as pool:
        system = pool.submit(guarded, audit_system, "system audit")
        hardening = pool.submit(guarded, audit_hardening, "vulnerability scan")
        network = pool.submit(guarded, network_and_ai, "network and AI audit")
        # the file scan stays on the calling thread so Ctrl+C interrupts it cleanly
        scan_found, stats = scanner.scan(scanner.user_hotspots(), progress=progress)
        net_found, notes = network.result()
        findings = system.result() + hardening.result() + net_found + scan_found
    return findings, notes + [stats.note()] + [f"scan: {e}" for e in stats.errors[:5]]
