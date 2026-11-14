"""AI-agent guard.

Three independent checks:
  1. exposure   - local model servers / agent gateways reachable from the network
  2. configs    - coding-agent and MCP configuration that removes human approval,
                  runs unpinned remote code, or stores secrets in plain text
  3. injection  - files in a workspace that try to give orders to an AI agent
                  (hidden Unicode, hidden HTML, instruction-override phrases)
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from .core import IS_WINDOWS, Finding, Severity
from .netinfo import Listener
from .sysaudit import judge_command

# ================================================================ exposure

AI_PORTS = {
    11434: "Ollama", 1234: "LM Studio", 8188: "ComfyUI", 7860: "Gradio UI (text-generation-webui / SD WebUI)",
    5001: "KoboldCpp", 4891: "GPT4All", 1337: "Jan", 8888: "Jupyter", 9997: "Xinference",
    18789: "OpenClaw gateway", 3001: "AnythingLLM", 6333: "Qdrant vector DB",
}
_RE_AI_PROC = re.compile(
    r"^(?:ollama|lm studio|lms|koboldcpp|llama-server|llama-cpp|llamafile|jan|gpt4all|comfyui|"
    r"open-webui|local-ai|localai|vllm|jupyter[\w-]*|anythingllm|msty|openclaw|tabby|text-generation[\w-]*)"
    r"(?:[ ._-].*)?$", re.I)


def _probe(port: int) -> str | None:
    """Ask the local service (127.0.0.1 only) whether it answers API calls without credentials."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for path in ("/api/tags", "/v1/models", "/api/kernels"):
        try:
            with opener.open(f"http://127.0.0.1:{port}{path}", timeout=1.5) as resp:
                if resp.status == 200:
                    return path
        except (urllib.error.URLError, OSError, ValueError):
            continue
    return None


def audit_ai_exposure(listeners: list[Listener] | None, probe: bool = False) -> list[Finding]:
    out: list[Finding] = []
    seen: set[int] = set()
    for l in listeners or []:
        known = AI_PORTS.get(l.port)
        by_name = bool(l.proc and _RE_AI_PROC.match(os.path.splitext(l.proc)[0]))
        if not (known or by_name) or (l.port in seen and l.loopback):
            continue
        service = known if (known and (by_name or not l.proc or l.port in (11434, 1234))) else None
        label = service or (f"AI runtime '{l.proc}'" if by_name else f"possibly {known}")
        evidence = []
        if probe and l.port not in seen:
            hit = _probe(l.port)
            if hit:
                evidence.append(f"GET {hit} answered 200 with no credentials")
        seen.add(l.port)
        if l.loopback:
            out.append(Finding(
                "ai-local-endpoint", Severity.LOW, f"{label} API is listening on localhost", l.label(), evidence,
                "Local-only, but every program on this PC (and, without origin checks, web pages in "
                "your browser) can drive the model. Stop it when not in use."))
        else:
            out.append(Finding(
                "ai-exposed-endpoint", Severity.HIGH,
                f"{label} API is reachable from the network without authentication", l.label(), evidence,
                "Anyone on your network can run prompts, use your GPU, and reach whatever tools the "
                "model has. Bind it to 127.0.0.1 or put an authenticating proxy in front."))
    host = os.environ.get("OLLAMA_HOST", "")
    if host and not host.replace("http://", "").startswith(("127.", "localhost", "[::1]")):
        out.append(Finding("ai-ollama-host", Severity.MEDIUM,
                           "OLLAMA_HOST makes Ollama listen beyond localhost", f"OLLAMA_HOST={host}"))
    if os.environ.get("OLLAMA_ORIGINS", "").strip() == "*":
        out.append(Finding("ai-ollama-origins", Severity.MEDIUM,
                           "OLLAMA_ORIGINS=* lets any website call your local model", "OLLAMA_ORIGINS"))
    return out


# ================================================================= configs

def agent_config_files(workspace: Path | None = None) -> list[Path]:
    """Known agent / MCP configuration files that exist on this machine."""
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home / ".config"))
    if sys.platform == "darwin":
        appdata = home / "Library/Application Support"
    candidates = [
        home / ".claude/settings.json", home / ".claude/settings.local.json", home / ".claude.json",
        home / ".claude/CLAUDE.md",
        appdata / "Claude/claude_desktop_config.json",
        home / ".cursor/mcp.json", home / ".codeium/windsurf/mcp_config.json",
        appdata / "Code/User/mcp.json", appdata / "Code/User/settings.json",
        home / ".gemini/settings.json", home / ".codex/config.toml", home / ".codex/AGENTS.md",
        home / ".continue/config.json", home / ".config/opencode/opencode.json",
        home / ".openclaw/openclaw.json", home / ".aider.conf.yml",
    ]
    if workspace:
        candidates += [workspace / n for n in (
            ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".cursor/mcp.json",
            ".vscode/mcp.json", ".vscode/settings.json", "CLAUDE.md", "AGENTS.md", ".cursorrules")]
    seen, out = set(), []
    for p in candidates:
        key = os.path.normcase(str(p))
        if key not in seen and p.is_file():
            seen.add(key)
            out.append(p)
    return out


def _strip_jsonc(text: str) -> str:
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _load(path: Path):
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if path.suffix == ".toml":
        try:
            import tomllib
        except ImportError:  # Python 3.10
            return None
        return tomllib.loads(text)
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(_strip_jsonc(text))


_RE_SECRET = re.compile(
    r"sk-ant-[\w-]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{32,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{30,}|"
    r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[\w-]{35}|glpat-[\w-]{20,}|hf_[A-Za-z0-9]{30,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_RE_SECRET_KEY = re.compile(r"api[_-]?key|token|secret|passw(?:or)?d|authorization", re.I)
_RE_AUTO_KEY = re.compile(
    r"yolo|auto[_-]?approve|always[_-]?allow|dangerously|skip[_-]?permissions?|bypass[_-]?permissions?|"
    r"auto[_-]?run|auto[_-]?execute|trust[_-]?all", re.I)
_RE_BROAD_ALLOW = re.compile(
    r"^(?:Bash|PowerShell)\((?:sudo|rm|del|curl|wget|iwr|powershell|pwsh|python[\d.]*|py|node|bash|sh|cmd|"
    r"npx|pip|ssh|scp|chmod|eval|iex|reg|schtasks|git push)\b[^)]*\*", re.I)
_LAUNCHERS = {"npx", "bunx", "uvx", "pnpx", "pipx"}


def _redact(value: str) -> str:
    return value[:4] + "***" if len(value) > 4 else "***"


def _walk(node, path: str, visit) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            visit(str(k), v, f"{path}.{k}" if path else str(k))
            _walk(v, f"{path}.{k}" if path else str(k), visit)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                visit("", v, f"{path}[{i}]")
            else:
                _walk(v, f"{path}[{i}]", visit)


def _mcp_findings(name: str, spec: dict, where: str) -> list[Finding]:
    out = []
    target = f"{where} -> MCP server '{name}'"
    url = str(spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or "")
    if url.lower().startswith("http://") and not re.match(r"http://(?:localhost|127\.|\[::1\])", url, re.I):
        out.append(Finding("mcp-plaintext-url", Severity.HIGH,
                           "MCP server is reached over unencrypted HTTP", target, [url],
                           "Tool results and tokens can be read or rewritten in transit. Use https."))
    command = str(spec.get("command") or "")
    args = [str(a) for a in spec.get("args") or [] if isinstance(a, (str, int, float))]
    if not command:
        return out
    full = " ".join([command] + args)
    sev, why = judge_command(full)
    if sev == Severity.HIGH:
        out.append(Finding("mcp-suspicious-command", Severity.HIGH,
                           "MCP server launch command looks malicious", target, [full] + why))
    exe = os.path.splitext(os.path.basename(command.replace("\\", "/")))[0].lower()
    rest = args
    if exe in ("cmd", "powershell", "pwsh", "bash", "sh"):  # `cmd /c npx ...` wrapper
        for i, a in enumerate(args):
            if os.path.splitext(a)[0].lower() in _LAUNCHERS:
                exe, rest = os.path.splitext(a)[0].lower(), args[i + 1:]
                break
    if exe in _LAUNCHERS:
        pkg = next((a for a in rest if not a.startswith("-") and a not in ("run", "dlx", "exec")), "")
        pinned = bool(re.search(r".@\d+\.\d+", pkg) or re.search(r"==\d", pkg))
        if pkg and not pinned and not pkg.startswith((".", "/")) and not re.match(r"[A-Za-z]:\\", pkg):
            out.append(Finding(
                "mcp-unpinned-package", Severity.MEDIUM,
                "MCP server runs an unpinned package downloaded at every start", target, [full],
                f"If '{pkg}' or one of its dependencies is hijacked, the new code runs with your "
                "privileges and your agent's trust. Pin an exact version."))
    return out


def audit_config_file(path: Path) -> list[Finding]:
    where = str(path)
    if path.suffix.lower() in (".md", ".yml", ".yaml", ".cursorrules", ""):
        return []
    try:
        cfg = _load(path)
    except (OSError, ValueError) as exc:
        return [Finding("ai-config-unreadable", Severity.INFO, "Could not parse agent configuration",
                        where, [str(exc)[:200]])]
    if not isinstance(cfg, dict):
        return []
    out: list[Finding] = []

    # --- Claude Code style permissions
    perms = cfg.get("permissions")
    if isinstance(perms, dict):
        if perms.get("defaultMode") == "bypassPermissions":
            out.append(Finding("ai-permissions-bypassed", Severity.HIGH,
                               "Agent runs with all permission prompts bypassed by default", where,
                               ["permissions.defaultMode = bypassPermissions"],
                               "Any prompt injection now executes commands unreviewed. Use the default "
                               "mode, or confine bypass mode to a disposable VM/container."))
        allow = [r for r in perms.get("allow") or [] if isinstance(r, str)]
        total = [r for r in allow if r in ("*", "Bash", "PowerShell", "Bash(*)", "Bash(:*)", "PowerShell(*)")]
        broad = [r for r in allow if _RE_BROAD_ALLOW.match(r)]
        if total:
            out.append(Finding("ai-shell-unrestricted", Severity.HIGH,
                               "Agent may run any shell command without asking", where, total,
                               "Replace it with narrow rules for the specific commands you use."))
        if broad:
            out.append(Finding("ai-shell-broad-allow", Severity.MEDIUM,
                               "Pre-approved shell rules are broad enough to escape the sandbox", where,
                               broad[:8], "Interpreters, downloaders and 'rm' with wildcards allow "
                                          "arbitrary code or deletion. Narrow or remove them."))
        deny = " ".join(str(r) for r in perms.get("deny") or [])
        if allow and ".env" not in deny and "secret" not in deny.lower():
            out.append(Finding("ai-no-secret-deny", Severity.LOW,
                               "No deny rules protect secret files from the agent", where,
                               advice='Add deny rules such as "Read(./.env)", "Read(./.env.*)", '
                                      '"Read(~/.ssh/**)", "Read(~/.aws/**)".'))
    if cfg.get("enableAllProjectMcpServers") is True:
        out.append(Finding("ai-mcp-auto-enable", Severity.MEDIUM,
                           "MCP servers defined by any cloned repository start automatically", where,
                           ["enableAllProjectMcpServers = true"],
                           "A malicious repo can ship a .mcp.json that runs code on open. Turn it off."))
    hooks = cfg.get("hooks")
    if isinstance(hooks, dict):
        cmds: list[str] = []
        _walk(hooks, "", lambda k, v, p: cmds.append(v) if k == "command" and isinstance(v, str) else None)
        bad = [c for c in cmds if judge_command(c)[0] == Severity.HIGH]
        if bad:
            out.append(Finding("ai-hook-suspicious", Severity.HIGH,
                               "Agent hook runs a malicious-looking command", where, bad[:5]))
        elif cmds:
            out.append(Finding("ai-hooks-present", Severity.INFO,
                               f"{len(cmds)} hook command(s) run automatically with the agent", where, cmds[:5],
                               "Hooks are legitimate, but verify you added each of them."))

    # --- Codex
    if cfg.get("sandbox_mode") == "danger-full-access":
        never = cfg.get("approval_policy") == "never"
        out.append(Finding("ai-sandbox-disabled", Severity.HIGH if never else Severity.MEDIUM,
                           "Agent sandbox is disabled" + (" and approvals are never requested" if never else ""),
                           where, ["sandbox_mode = danger-full-access"]))

    # --- generic walk: auto-approve switches, plaintext secrets, MCP servers
    autos: list[str] = []
    secrets: list[str] = []
    servers: list[tuple[str, dict, str]] = []

    def visit(key: str, value, keypath: str) -> None:
        if key and _RE_AUTO_KEY.search(key):
            if value is True or (isinstance(value, str) and value.lower() in ("true", "on", "yes", "always", "all")):
                autos.append(f"{keypath} = {value}")
            elif isinstance(value, list) and value:
                autos.append(f"{keypath} = {len(value)} item(s)")
            elif isinstance(value, dict) and any(v is True for v in value.values()):
                autos.append(f"{keypath} = true for {sum(v is True for v in value.values())} entr(ies)")
        if isinstance(value, str) and len(value) >= 12:
            m = _RE_SECRET.search(value)
            if m:
                secrets.append(f"{keypath}: {_redact(m.group(0))}")
            elif key and _RE_SECRET_KEY.search(key) and len(value) >= 16 \
                    and not value.startswith(("$", "<", "%", "{{", "env:")) and " " not in value:
                secrets.append(f"{keypath}: {_redact(value)}")
        if key in ("mcpServers", "mcp_servers") or (key == "servers" and path.name == "mcp.json"):
            if isinstance(value, dict):
                for name, spec in value.items():
                    if isinstance(spec, dict):
                        servers.append((str(name), spec, keypath))

    _walk(cfg, "", visit)
    if autos:
        out.append(Finding("ai-auto-approve", Severity.MEDIUM,
                           "Auto-approval switches are enabled for the agent", where, autos[:8],
                           "Each one removes a human checkpoint that would stop an injected instruction."))
    if secrets:
        out.append(Finding("ai-plaintext-secret", Severity.MEDIUM,
                           "Secrets are stored in plain text inside an agent configuration", where,
                           secrets[:8], "Any agent or tool that can read this file can leak them. "
                                        "Use environment variables or an OS keychain, then rotate the keys."))
    done: set[str] = set()
    for name, spec, _kp in servers:
        if name not in done:
            done.add(name)
            out += _mcp_findings(name, spec, where)
    return out


# =============================================================== injection

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target",
              ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".next", ".idea"}
_TEXT_EXTS = {".md", ".mdc", ".txt", ".rst", ".html", ".htm", ".xml", ".svg", ".json", ".yaml", ".yml",
              ".toml", ".ini", ".cfg", ".py", ".js", ".ts", ".jsx", ".tsx", ".css", ".sh", ".ps1", ".csv",
              ".java", ".go", ".rs", ".c", ".h", ".cpp", ".cs", ".php", ".rb", ".tex", ".ipynb"}
_RULE_FILES = {"claude.md", "agents.md", "gemini.md", "skill.md", ".cursorrules", ".windsurfrules",
               ".clinerules", "copilot-instructions.md"}
_RE_SECRET_FILE = re.compile(
    r"^(?:\.env(?:\.(?!example|sample|template|dist)[\w.-]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|.+\.(?:pem|key|kdbx|pfx|p12)|"
    r"credentials(?:\.json)?|\.npmrc|\.pypirc|\.netrc|secrets?\.(?:json|ya?ml|toml)|service[-_]account.*\.json)$",
    re.I)

_RE_TAGS = re.compile("[\U000E0020-\U000E007E]{4,}")
_RE_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_RE_ZW = re.compile("[\u200b\u200c\u200d\u2060\u2062\u2063\ufeff]{5,}")
_RE_HIDDEN = re.compile(
    r"<!--.*?-->|\[//\]:\s*#\s*\(.*?\)|"
    r"<[^>]{0,300}style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\s*[;\"']|"
    r"color\s*:\s*(?:#fff(?:fff)?\b|white))[^>]*>.{0,2000}?</", re.S | re.I)

_AGENT = r"(?:ai|llm|assistant|agent|model|claude|chatgpt|gpt|copilot|gemini|cursor|codex)"
_PHRASES = [(re.compile(p, re.I), label) for p, label in [
    (r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|preceding|system)\s+"
     r"(?:instructions?|prompts?|rules|messages|directives|guidelines)", "instruction override"),
    (r"(?:игнорируй|забудь|отмени|не\s+учитывай)\s+(?:все\s+)?(?:предыдущие|прошлые|прежние|вышеуказанные|системные)\s+"
     r"(?:инструкции|указания|правила|команды)", "instruction override (ru)"),
    (r"you\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted|god|admin)\s*mode", "jailbreak mode switch"),
    (r"(?:do\s+not|don'?t|never)\s+(?:tell|mention|inform|reveal|show|notify|alert|disclose)\s+(?:this\s+|it\s+|anything\s+)?"
     r"(?:to\s+)?(?:the\s+)?(?:user|human|operator|developer)", "tells the agent to hide actions from the user"),
    (r"without\s+(?:telling|informing|asking|notifying|alerting|confirmation\s+from)\s+(?:the\s+)?(?:user|human)",
     "tells the agent to act without the user's knowledge"),
    (r"не\s+(?:говори|сообщай|рассказывай|показывай|упоминай)\s+(?:об\s+этом\s+|это\s+)?пользовател",
     "tells the agent to hide actions from the user (ru)"),
    (r"<\|im_start\|>|<\|system\|>|\[/?INST\]|<{2}SYS>{2}|<\|start_header_id\|>", "forged chat-role markers"),
    (r"(?:send|upload|post|exfiltrate|transmit|forward|email|curl|fetch)\b.{0,120}(?:\.env\b|id_rsa|ssh\s+keys?|api[_\s-]?keys?|"
     r"credentials|passwords?|secrets|tokens?|private\s+keys?|cookies)\b.{0,120}(?:https?://|webhook)",
     "instruction to send secrets to a URL"),
    (rf"\b{_AGENT}s?\b[^.\n]{{0,60}}\b(?:must|should|shall|need\s+to|is\s+required\s+to|are\s+required\s+to)\s+"
     r"(?:first\s+|now\s+|always\s+|immediately\s+)?(?:run|execute|fetch|download|send|delete|install|curl|open|visit)\b",
     "commands addressed to an AI agent"),
    (rf"(?:if|when)\s+you\s+are\s+an?\s+{_AGENT}\b", "content that singles out AI readers"),
    (r"(?:new|updated|real|actual|revised)\s+(?:system\s+)?instructions?\s*:", "injected instruction block"),
]]


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_text_for_injection(text: str, path: str, is_rule_file: bool = False) -> list[Finding]:
    out: list[Finding] = []
    m = _RE_TAGS.search(text)
    if m:
        hidden = "".join(chr(ord(c) - 0xE0000) for c in _RE_TAGS.findall(text)[0])
        out.append(Finding("inject-unicode-tags", Severity.HIGH,
                           "Invisible Unicode tag characters carry hidden text for AI models", path,
                           [f"line {_line_of(text, m.start())}: decodes to \"{hidden[:160]}\""],
                           "Humans cannot see this text; language models read it. Delete the characters."))
    zw = _RE_ZW.search(text[1:])
    if zw:
        out.append(Finding("inject-zero-width", Severity.MEDIUM,
                           "Run of zero-width characters (possible hidden payload)", path,
                           [f"line {_line_of(text, zw.start() + 1)}"]))
    bidi = _RE_BIDI.search(text)
    if bidi:
        out.append(Finding("inject-bidi", Severity.MEDIUM,
                           "Bidirectional control characters can make code read differently than it runs",
                           path, [f"line {_line_of(text, bidi.start())}"]))

    hidden_spans = [(h.start(), h.end()) for h in _RE_HIDDEN.finditer(text)] if "<" in text or "[//]" in text else []
    visible, concealed = [], []
    for rx, label in _PHRASES:
        pm = rx.search(text)
        if not pm:
            continue
        note = f"line {_line_of(text, pm.start())}: {label}: \"{pm.group(0)[:100]}\""
        if any(a <= pm.start() < b for a, b in hidden_spans):
            concealed.append(note)
        else:
            visible.append(note)
    if concealed:
        out.append(Finding("inject-hidden-instructions", Severity.HIGH,
                           "Instructions for AI agents hidden from human readers", path, concealed + visible,
                           "Text in comments/invisible elements is still read by agents. Remove it and "
                           "find out who added it."))
    elif visible:
        out.append(Finding("inject-instructions", Severity.HIGH if is_rule_file else Severity.MEDIUM,
                           "Text that tries to give orders to an AI agent", path, visible,
                           "Do not let an agent process this file unsupervised."))
    if is_rule_file:
        sev, why = judge_command(text)
        if sev == Severity.HIGH:
            out.append(Finding("inject-rules-backdoor", Severity.HIGH,
                               "Agent instruction file contains download/execute commands", path, why,
                               "Rule files are obeyed automatically; this one may be poisoned."))
    return out


def _holds_secret(path: str, low_name: str) -> bool:
    """A .pem is usually a public CA bundle; it is a secret only with a private key inside."""
    if not low_name.endswith(".pem"):
        return True
    try:
        with open(path, "rb") as fh:
            return b"PRIVATE KEY" in fh.read(256 * 1024)
    except OSError:
        return False


def scan_workspace(root: str, max_files: int = 100_000, excludes: list[str] | None = None,
                   budget_s: float = 120.0) -> tuple[list[Finding], int]:
    """Scan a folder for prompt injection and agent-readable secrets. Returns (findings, files read)."""
    findings: list[Finding] = []
    secrets: list[str] = []
    read = 0
    deadline = time.monotonic() + budget_s
    patterns = [p.replace("\\", "/").lower() for p in excludes or []]
    stack = [root]
    while stack and read < max_files and time.monotonic() < deadline:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if patterns:
                    rel = os.path.relpath(e.path, root).replace("\\", "/").lower()
                    if any(fnmatch.fnmatchcase(rel, p) for p in patterns):
                        continue
                if e.is_dir(follow_symlinks=False):
                    if e.name not in _SKIP_DIRS:
                        stack.append(e.path)
                    continue
                low = e.name.lower()
                if _RE_SECRET_FILE.match(low):
                    if len(secrets) < 12 and _holds_secret(e.path, low):
                        secrets.append(e.path)
                    continue
                ext = os.path.splitext(low)[1]
                is_rule = low in _RULE_FILES or ext == ".mdc"
                if not (is_rule or ext in _TEXT_EXTS or (ext == "" and low in ("readme", "license"))):
                    continue
                if e.stat(follow_symlinks=False).st_size > 2 * 1024 * 1024:
                    continue
                with open(e.path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
                read += 1
                findings += scan_text_for_injection(text, e.path, is_rule)
            except OSError:
                continue
    if stack:  # stopped early: say so instead of pretending the folder is clean
        findings.append(Finding(
            "ai-scan-incomplete", Severity.INFO,
            f"Workspace scan stopped after {read} files (time or file limit) - point it at a smaller project folder", root))
    if secrets:
        findings.append(Finding(
            "ai-readable-secrets", Severity.LOW,
            "Secret files sit where a coding agent working in this folder can read them", root, secrets,
            "Add deny rules for them in the agent's settings, or keep secrets outside the workspace."))
    return findings, read


def audit_ai(workspace: str | None, listeners: list[Listener] | None, probe: bool = False,
             excludes: list[str] | None = None) -> tuple[list[Finding], list[str]]:
    findings = audit_ai_exposure(listeners, probe)
    ws = Path(workspace).resolve() if workspace else None
    configs = agent_config_files(ws)
    for cfg in configs:
        try:
            findings += audit_config_file(cfg)
        except Exception as exc:  # an odd config must not abort the whole audit
            findings.append(Finding("ai-config-error", Severity.INFO,
                                    f"Internal error while checking a config: {type(exc).__name__}: {exc}", str(cfg)))
    notes = [f"ai: {len(configs)} agent config file(s) checked"]
    if ws:
        found, read = scan_workspace(str(ws), excludes=excludes)
        findings += found
        notes.append(f"ai: {read} text file(s) scanned for prompt injection in {ws}")
    return findings, notes
