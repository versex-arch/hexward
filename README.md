# hexward

Host security toolkit in one small CLI: **log analysis, malware scanning, system audit and a guard against misbehaving AI agents**. Pure Python, zero dependencies, Windows / Linux / macOS.

[Русская версия](README.ru.md)

```
pip install .
hexward quick
```

**If Windows says "An Application Control policy has blocked this file":** Smart App Control is blocking the unsigned `pip.exe` / `hexward.exe` launchers. Do not turn it off — run everything through the signed `python.exe` instead:

```
python -m pip install .
python -m hexward quick
```

## Desktop app

```
python -m hexward shortcut
```

This puts a `hexward` shortcut on the desktop. It opens a window with no console, with a sidebar and six screens: Overview (protection score), Checks, Findings, Live guard, Quarantine and Settings. The interface is available in English, Russian, Kazakh, German, Spanish and Chinese; it starts in English and can be changed in Settings (finding texts stay in English for now). Results are kept between launches, and any finding can be ignored from its details (the list is reset in Settings). The window is a local page shown by Edge or Chrome in app mode (no tabs, no address bar); it is served only on 127.0.0.1 behind a random per-run token, so nothing else on the network or in your browser can reach it. `python -m hexward gui` opens the same window.

Prebuilt `hexward.exe` (window) and `hexward-cli.exe` (console) for Windows are on the Releases page. They are not code-signed, so SmartScreen will warn and Smart App Control will block them - use the shortcut above in that case.

## What it does

| Command | What it finds |
|---|---|
| `hexward logs auth.log access.log` | SSH brute force, password spraying, distributed attacks, **successful login after a brute force**, sudo abuse; web scanning, SQLi / XSS / path traversal / command injection / Log4Shell payloads, attack-tool User-Agents, login brute force, floods, sensitive files answered with HTTP 200 |
| `hexward winlog` | Windows event log: failed-logon brute force (4625), cleared audit log, new users, new admins, new services |
| `hexward scan [paths]` | Known malware by SHA-256, plus heuristics: disguised executables, packed / injecting PE files, obfuscated download-and-execute scripts, ransomware and credential-dumping commands |
| `hexward audit` | Autostart entries, Startup scripts, Winlogon / IFEO / AppInit hijacks, Defender / firewall / UAC switched off, risky Defender exclusions, system-process impostors, Office spawning shells, suspicious scheduled tasks, hosts-file tampering, risky network listeners |
| `hexward harden` | Vulnerability scan: stored autologon password, WDigest, SMBv1, Secure Boot off, silent UAC, SmartScreen off, updates disabled or stale, Office macros enabled, accounts without a password, Guest enabled; browser hijacks (system proxy, PAC script, force-installed extensions) |
| `hexward ai [folder]` | Local model servers reachable from the network, agent configs that disable approval, unpinned or plaintext MCP servers, secrets in agent configs, **prompt injection** in a workspace (invisible Unicode, hidden HTML, instruction-override text, poisoned rule files) |
| `hexward guard init / check / watch` | Integrity baseline and live watch over agent configs, shell profiles, SSH keys, hosts, autostart entries and listeners. While watching it is also a **download shield** (new files in Downloads and on the Desktop are scanned at once) and checks newly plugged **USB drives** |
| `hexward guard canary-on / canary-off` | **Ransomware canaries**: hidden decoy documents in Documents and Pictures; if anything rewrites or deletes them the guard raises a critical alert |
| `hexward quick` | `audit` + `harden` + `ai` + a scan of Downloads / Desktop / Temp / Startup |

Every finding has a severity (`info` … `critical`), the evidence, and what to do about it. `--json` and `-o FILE` give machine-readable reports. The exit code is `0` clean, `1` findings at or above `--fail-on` (default `medium`), `2` error, so it drops straight into cron or CI.

## Start with Windows

```
python -m hexward autostart on
```

(or the switch in Settings). hexward then starts in the background at sign-in with the live guard on and reports alerts as desktop notifications; the desktop shortcut opens the window of that same process. `autostart off` removes it, and Settings has an Exit button.

## The AI-agent guard

Coding agents and local models act with your privileges and read untrusted text. Three things go wrong in practice, and `hexward ai` checks each:

1. **Exposure.** Ollama, LM Studio, ComfyUI, Jupyter and similar bind to a port with no authentication. Bound to `0.0.0.0`, anyone on the network can drive the model and its tools. `--probe` asks the local port (127.0.0.1 only) whether it answers without credentials.
2. **Configuration.** Permission bypass modes, unrestricted shell allow-rules, auto-approve switches, repository-supplied MCP servers that start automatically, MCP packages fetched unpinned at every launch, MCP over plain HTTP, API keys in plain text. Covers Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Codex, Gemini CLI, Continue.
3. **Prompt injection.** Text that addresses the agent rather than you: Unicode tag characters (invisible to humans, readable by models — the hidden message is decoded and shown), zero-width and bidirectional tricks, instructions inside HTML comments or invisible elements, and download-and-run commands in rule files such as `CLAUDE.md`, `AGENTS.md`, `.cursorrules`.

`hexward guard watch` then tells you within seconds when an agent (or anything else) rewrites its own permissions, your shell profile, `authorized_keys`, an autostart entry, or opens a new listener.

## Performance

Measured on a laptop, Python 3.13:

- auth logs: ~115,000 lines/s; access logs: ~70,000 lines/s (20,000 if every URL is unique). Single pass, constant memory per client IP.
- `quick` runs its four parts in parallel: about 2 s on a warm cache.
- file scan: ~165 MB/s cold, multithreaded. Large media, disk-image and model-weight files are checked by header only unless you pass `--thorough`. Files already found clean are skipped by path + size + mtime, so a repeat scan of 2,400 files takes under a second.
- `guard watch` stats a few dozen files per tick and hashes only what changed; the idle app window asks the server only "anything new?".
- cloud placeholders (OneDrive) and junctions are skipped, so a scan never triggers downloads or loops.

## Signatures

One built-in signature (the EICAR test file). Bring your own lists — any text file with one SHA-256 per line:

```
hexward sigs import my-hashes.txt
hexward sigs import https://example.org/sha256-list.txt
hexward sigs stats
```

`scan --quarantine` moves **signature** matches into quarantine (stored masked, restorable with `hexward quarantine restore ID`). Heuristic hits are never quarantined automatically.

## What it is not

Being honest about limits is part of a security tool:

- **It is not a replacement for Microsoft Defender or another real-time antivirus.** It has no kernel driver, does not intercept file opens or process starts, and does not scan memory. Run it alongside one.
- Heuristics give false positives and miss things. A `heuristic-*` finding means "look at this", not "this is malware".
- Hash signatures only catch exact known files.
- The scan cache trusts size + mtime. Malware that rewrites a file and forges both back is skipped; use `--no-cache` for a full pass.
- `guard` runs as your user. Anything with the same rights can also rewrite the baseline or stop the watcher. For a hard guarantee run it under a different account.
- Prompt-injection detection is pattern-based. It catches the common techniques, not every phrasing.
- `audit` is Windows-first; Linux and macOS currently get the hosts and network checks (logs, scan, ai and guard are fully cross-platform).

## Development

```
pip install -e .[dev]
pytest
```

Layout: `logs.py` (auth/web), `winevent.py`, `scanner.py` + `heuristics.py`, `sysaudit.py`, `netinfo.py`, `aiguard.py`, `guard.py`, `cli.py`. State lives in `~/.hexward` (override with `HEXWARD_HOME`).

When scanning this repository with `hexward ai`, pass `--exclude "tests/*"`: the tests contain sample attack text on purpose.

## Releasing

Push a tag and GitHub Actions builds the Windows executables and publishes the release (0.x tags are marked as pre-releases):

```
git tag v0.1.0
git push origin v0.1.0
```

## License

MIT
