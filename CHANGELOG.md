# Changelog

## 0.1.1 (pre-release)

First public version (0.1.0 was tagged but never released: its Windows build failed).

- Running `hexward` without a command now opens the window.
- Fixed: enabling "Start with Windows" failed on a profile that had no Run registry key yet.

- Desktop app (`hexward gui`, or the desktop shortcut from `hexward shortcut`): sidebar layout with Overview (protection score), Checks, Findings, Live guard, Quarantine and Settings screens; interface in English, Russian, Kazakh, German, Spanish and Chinese. It is a local page shown in a chromeless Edge/Chrome window, served only on 127.0.0.1 behind a per-run token.
- Log analysis: SSH / sudo auth logs, nginx / apache access logs, Windows event log.
- File scanner: SHA-256 signatures, PE and script heuristics, clean-file cache, quarantine.
- System audit for Windows: persistence, security settings, processes, scheduled tasks, hosts, listeners.
- AI-agent guard: exposed model servers, risky agent / MCP configuration, prompt injection in workspaces.
- Integrity guard: baseline, check and live watch, with a download shield, removable-drive check and opt-in ransomware canaries.
- Vulnerability scan (`hexward harden`): weak Windows settings, account problems, stale updates, browser hijacks.
- Results history and an activity journal kept between launches; ignore list for findings.
- Start with Windows: background mode with desktop notifications, single running instance.
- Faster: parallel quick check, header-only check for large media files, change-only window updates.
- New application icon.

Known limits: no real-time kernel protection (use alongside Microsoft Defender); `audit` is Windows-first;
the released `.exe` files are not code-signed, so Windows SmartScreen / Smart App Control may warn about or block them.
