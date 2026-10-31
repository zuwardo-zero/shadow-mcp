"""Risk evaluation and scoring engine for discovered MCP servers and AI processes."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from shadow_mcp.models import (
    BENIGN_ENV_KEY_RE,
    SENSITIVE_ENV_KEY_RE,
    DiscoveredProcess,
    FindingCategory,
    MCPServerConfig,
    RiskFinding,
    RiskLevel,
    _looks_like_env_reference,
)

HIGH_CONFIDENCE_SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("GitHub Token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("HuggingFace Token", re.compile(r"\bhf_[A-Za-z0-9]{25,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe Key", re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{16,}\b")),
    ("JWT Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PRIVATE )?KEY-----")),
    ("Database Connection URI with Password", re.compile(r"\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp)://[^:/\s]+:[^@\s]+@[^\s]+", re.IGNORECASE)),
)

SHELL_EXEC_PATTERNS = re.compile(
    r"(server-shell|mcp-shell|server-commands|mcp-server-commands|mcp-exec|server-terminal|iterm-mcp|bash-mcp|terminal-mcp|hexstrike|kali-mcp)",
    re.IGNORECASE,
)

FILESYSTEM_PATTERNS = re.compile(
    r"(server-filesystem|mcp-filesystem|filesystem-mcp|fs-mcp)",
    re.IGNORECASE,
)

BROWSER_NETWORK_PATTERNS = re.compile(
    r"(@playwright/mcp|server-puppeteer|server-fetch|mcp-server-fetch|browserbase|browser-use|puppeteer-mcp|firecrawl)",
    re.IGNORECASE,
)

DATABASE_PATTERNS = re.compile(
    r"(server-postgres|server-sqlite|mcp-server-sqlite|mysql-mcp|supabase-mcp|mongodb-mcp|redis-mcp|dbhub)",
    re.IGNORECASE,
)

SENSITIVE_PATHS = {
    "/",
    "/etc",
    "/root",
    "/var",
    "/home",
    "/Users",
    "~",
    "C:\\",
    "C:/",
    "C:\\Windows",
    "C:/Windows",
    "C:\\Users",
    "C:/Users",
}


def evaluate_server_risk(server: MCPServerConfig) -> MCPServerConfig:
    """Run all static analysis rules against an MCPServerConfig and populate its risk score."""
    findings: list[RiskFinding] = []

    findings.extend(_check_permissive_tools(server))
    findings.extend(_check_endpoints_and_auth(server))
    findings.extend(_check_package_pinning(server))
    findings.extend(_check_sensitive_env(server))
    findings.extend(_check_privilege_context(server))
    findings.extend(_check_risky_patterns(server))
    findings.extend(_check_compound_risks(server, findings))

    raw_score = sum(f.points for f in findings)
    capped_score = min(100, raw_score)
    server.findings = findings
    server.risk_score = capped_score
    server.risk_level = RiskLevel.from_score(capped_score)
    return server


def evaluate_process_risk(proc: DiscoveredProcess) -> DiscoveredProcess:
    """Evaluate a running AI agent or MCP server process for operational risk."""
    findings: list[RiskFinding] = []
    cmd_lower = proc.cmdline.lower()

    if proc.user in ("root", "0", "SYSTEM", "Administrator", "NT AUTHORITY\\SYSTEM"):
        findings.append(
            RiskFinding(
                rule_id="PROC-PRIV-001",
                category=FindingCategory.HIGH_PRIVILEGE,
                points=40,
                title="AI Agent or MCP process running as root/Administrator",
                detail=f"Process PID {proc.pid} ({proc.command}) is executing under privileged user '{proc.user}'.",
                remediation="Run MCP servers and AI agents under a dedicated unprivileged user account.",
            )
        )

    if "--dangerously-skip-permissions" in cmd_lower or "--yolo" in cmd_lower or "--no-sandbox" in cmd_lower:
        findings.append(
            RiskFinding(
                rule_id="PROC-PATTERN-001",
                category=FindingCategory.RISKY_PATTERN,
                points=35,
                title="Permission or sandbox bypass flag active on running agent",
                detail=f"Command line contains autonomous bypass flag: '{proc.cmdline}'.",
                remediation="Remove permission bypass flags or isolate autonomous agents inside an ephemeral container/VM.",
            )
        )

    if "0.0.0.0" in cmd_lower or "--host 0.0.0.0" in cmd_lower:
        findings.append(
            RiskFinding(
                rule_id="PROC-NET-001",
                category=FindingCategory.UNAUTHENTICATED_ENDPOINT,
                points=30,
                title="Service bound to all network interfaces (0.0.0.0)",
                detail=f"Process PID {proc.pid} exposes an interface beyond localhost.",
                remediation="Bind local AI/MCP services strictly to 127.0.0.1.",
            )
        )

    if SHELL_EXEC_PATTERNS.search(proc.cmdline):
        findings.append(
            RiskFinding(
                rule_id="PROC-TOOL-001",
                category=FindingCategory.PERMISSIVE_TOOLS,
                points=30,
                title="Running shell/command execution MCP server",
                detail=f"Process '{proc.command}' provides direct shell or command execution capabilities.",
                remediation="Ensure human-in-the-loop approval is enforced for all command executions.",
            )
        )

    if "@latest" in cmd_lower:
        findings.append(
            RiskFinding(
                rule_id="PROC-PKG-001",
                category=FindingCategory.UNPINNED_PACKAGE,
                points=10,
                title="Running unpinned @latest package",
                detail="Process was launched using a mutable '@latest' package tag.",
                remediation="Pin the MCP server package to an immutable semantic version.",
            )
        )

    if not findings:
        findings.append(
            RiskFinding(
                rule_id="PROC-INFO-001",
                category=FindingCategory.PERMISSIVE_TOOLS,
                points=5,
                title="Active AI Agent / MCP Server Process",
                detail=f"Active process matched signature: {proc.matched_signature}.",
                remediation="Verify that this running agent is authorized and expected.",
            )
        )

    raw_score = sum(f.points for f in findings)
    proc.findings = findings
    proc.risk_score = min(100, raw_score)
    proc.risk_level = RiskLevel.from_score(proc.risk_score)
    return proc


def _check_permissive_tools(server: MCPServerConfig) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    full_cmd = server.full_command
    cmd_and_name = f"{server.name} {full_cmd}"

    # 1. Shell / arbitrary command execution servers
    if SHELL_EXEC_PATTERNS.search(cmd_and_name):
        findings.append(
            RiskFinding(
                rule_id="MCP-TOOL-001",
                category=FindingCategory.PERMISSIVE_TOOLS,
                points=35,
                title="Unrestricted shell or command execution MCP server",
                detail=f"Server '{server.name}' exposes OS command or shell execution ('{full_cmd}').",
                remediation="Restrict allowed commands via an allowlist or run inside a sandboxed container.",
            )
        )

    # 2. Filesystem access + broad path check
    if FILESYSTEM_PATTERNS.search(cmd_and_name) or "filesystem" in server.name.lower():
        broad_paths = [a for a in server.args if _is_broad_filesystem_path(a)]
        if broad_paths:
            findings.append(
                RiskFinding(
                    rule_id="MCP-TOOL-002",
                    category=FindingCategory.PERMISSIVE_TOOLS,
                    points=35,
                    title="Filesystem MCP server mounted on broad or sensitive root path",
                    detail=f"Server grants file read/write access to high-impact directory: {', '.join(broad_paths)}.",
                    remediation="Scope filesystem MCP servers to a single project subdirectory rather than home or root.",
                )
            )
        else:
            findings.append(
                RiskFinding(
                    rule_id="MCP-TOOL-003",
                    category=FindingCategory.PERMISSIVE_TOOLS,
                    points=10,
                    title="Scoped filesystem access capability enabled",
                    detail="Server provides local filesystem read/write tools scoped to a directory.",
                    remediation="Verify that mounted directories contain no SSH keys, dotfiles, or credentials.",
                )
            )

    # 3. Browser automation / network fetch capabilities
    if BROWSER_NETWORK_PATTERNS.search(cmd_and_name):
        findings.append(
            RiskFinding(
                rule_id="MCP-TOOL-004",
                category=FindingCategory.PERMISSIVE_TOOLS,
                points=15,
                title="Browser automation or external network fetch capability",
                detail=f"Server '{server.name}' can browse arbitrary URLs or interact with web sessions, increasing indirect prompt injection risk.",
                remediation="Use isolated browser profiles (--isolated) and avoid sharing authenticated session cookies.",
            )
        )

    # 4. Direct database access
    if DATABASE_PATTERNS.search(cmd_and_name):
        findings.append(
            RiskFinding(
                rule_id="MCP-TOOL-005",
                category=FindingCategory.PERMISSIVE_TOOLS,
                points=20,
                title="Direct database query/mutation capability",
                detail=f"Server '{server.name}' connects directly to a datastore.",
                remediation="Connect using a read-only database role unless write operations are strictly required.",
            )
        )

    return findings


def _check_endpoints_and_auth(server: MCPServerConfig) -> list[RiskFinding]:
    findings: list[RiskFinding] = []

    candidate_urls: list[str] = []
    if server.url:
        candidate_urls.append(server.url)
    for arg in server.args:
        if arg.startswith(("http://", "https://", "ws://", "wss://")):
            candidate_urls.append(arg)

    has_auth_header = any(
        k.lower() in ("authorization", "x-api-key", "api-key", "x-auth-token")
        for k in server.headers
    )
    has_auth_env = any(SENSITIVE_ENV_KEY_RE.search(k) for k in server.env)

    for raw_url in candidate_urls:
        parsed = urlparse(raw_url)
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        query = (parsed.query or "").lower()

        is_localhost = host in ("localhost", "127.0.0.1", "::1")
        is_wildcard_bind = host == "0.0.0.0"

        if "overrideaccess=true" in query or "skipauth=true" in query or "auth=false" in query:
            findings.append(
                RiskFinding(
                    rule_id="MCP-AUTH-001",
                    category=FindingCategory.UNAUTHENTICATED_ENDPOINT,
                    points=35,
                    title="Authentication bypass parameter in MCP endpoint URL",
                    detail=f"Endpoint URL '{raw_url}' explicitly enables access override or auth bypass in query parameters.",
                    remediation="Remove authentication bypass query flags and enforce token-based authentication.",
                )
            )

        if is_wildcard_bind:
            findings.append(
                RiskFinding(
                    rule_id="MCP-AUTH-002",
                    category=FindingCategory.UNAUTHENTICATED_ENDPOINT,
                    points=30,
                    title="MCP endpoint bound to all interfaces (0.0.0.0)",
                    detail=f"Endpoint '{raw_url}' binds to 0.0.0.0, exposing the server on local networks.",
                    remediation="Bind local MCP servers to 127.0.0.1.",
                )
            )
        elif not is_localhost and scheme in ("http", "ws"):
            findings.append(
                RiskFinding(
                    rule_id="MCP-AUTH-003",
                    category=FindingCategory.UNAUTHENTICATED_ENDPOINT,
                    points=25,
                    title="Unencrypted HTTP/WS connection to remote MCP endpoint",
                    detail=f"Remote endpoint '{raw_url}' transmits tool calls and context over cleartext {scheme.upper()}.",
                    remediation="Enforce HTTPS/WSS (TLS) for all non-localhost MCP connections.",
                )
            )

        if server.url and not has_auth_header and not has_auth_env:
            pts = 15 if is_localhost else 25
            findings.append(
                RiskFinding(
                    rule_id="MCP-AUTH-004",
                    category=FindingCategory.UNAUTHENTICATED_ENDPOINT,
                    points=pts,
                    title="Remote/HTTP MCP endpoint configured without authentication headers",
                    detail=f"Endpoint '{raw_url}' defines no Authorization headers or API key environment variables.",
                    remediation="Configure bearer tokens or mutual authentication on HTTP/SSE MCP servers.",
                )
            )

    return findings


def _check_package_pinning(server: MCPServerConfig) -> list[RiskFinding]:
    """Evaluate package version pinning with low standalone weights so npx/@latest alone stay LOW."""
    findings: list[RiskFinding] = []
    cmd = (server.command or "").strip()
    args = server.args
    full_cmd = server.full_command

    if "@latest" in full_cmd or ":latest" in full_cmd:
        findings.append(
            RiskFinding(
                rule_id="MCP-PKG-001",
                category=FindingCategory.UNPINNED_PACKAGE,
                points=10,
                title="Package explicitly pinned to mutable 'latest' tag",
                detail=f"Command '{full_cmd}' pulls a mutable 'latest' release on launch.",
                remediation="Pin the package or container image to a verified semantic version or digest.",
            )
        )
        return findings

    base_cmd = cmd.replace("\\", "/").split("/")[-1].lower().removesuffix(".exe").removesuffix(".cmd")
    is_dynamic_runner = base_cmd in ("npx", "uvx", "bunx") or (
        base_cmd == "pnpm" and args and args[0] == "dlx"
    )

    if is_dynamic_runner:
        pkg_token = _extract_package_token(base_cmd, args)
        if pkg_token and not _is_version_pinned(pkg_token):
            findings.append(
                RiskFinding(
                    rule_id="MCP-PKG-002",
                    category=FindingCategory.UNPINNED_PACKAGE,
                    points=8,
                    title="Dynamic package runner executes unpinned package",
                    detail=f"Runner '{base_cmd}' executes '{pkg_token}' without an explicit version pin.",
                    remediation=f"Specify an exact version when invoking {base_cmd} (e.g., {pkg_token}@x.y.z).",
                )
            )

    return findings


def _check_sensitive_env(server: MCPServerConfig) -> list[RiskFinding]:
    findings: list[RiskFinding] = []

    for key, val in server.env.items():
        val_str = str(val).strip()
        if not val_str or _looks_like_env_reference(val_str):
            continue

        matched_secret_type = None
        for label, pattern in HIGH_CONFIDENCE_SECRET_VALUE_PATTERNS:
            if pattern.search(val_str):
                matched_secret_type = label
                break

        if matched_secret_type:
            findings.append(
                RiskFinding(
                    rule_id="MCP-ENV-001",
                    category=FindingCategory.SENSITIVE_ENV,
                    points=30,
                    title=f"Hardcoded {matched_secret_type} in plaintext config",
                    detail=f"Environment variable '{key}' stores a live-formatted secret in '{server.source_path}'.",
                    remediation="Inject secrets at runtime via OS keychain, 1Password CLI (op://), or environment interpolation (${VAR}).",
                )
            )
            continue

        if (
            SENSITIVE_ENV_KEY_RE.search(key)
            and not BENIGN_ENV_KEY_RE.match(key)
            and not _is_placeholder_value(val_str)
        ):
            findings.append(
                RiskFinding(
                    rule_id="MCP-ENV-002",
                    category=FindingCategory.SENSITIVE_ENV,
                    points=20,
                    title="Hardcoded sensitive credential in environment block",
                    detail=f"Environment variable '{key}' contains a hardcoded secret value in plaintext JSON.",
                    remediation="Remove plaintext credentials from config files and reference system environment variables instead.",
                )
            )

    joined_args = " ".join(server.args)
    for label, pattern in HIGH_CONFIDENCE_SECRET_VALUE_PATTERNS:
        if pattern.search(joined_args):
            findings.append(
                RiskFinding(
                    rule_id="MCP-ENV-003",
                    category=FindingCategory.SENSITIVE_ENV,
                    points=30,
                    title=f"Secret ({label}) passed directly in command-line arguments",
                    detail="Command-line arguments are globally visible to all local users via the process table (ps/procfs).",
                    remediation="Pass credentials via environment variables or credential files with 0600 permissions.",
                )
            )
            break

    return findings


def _check_privilege_context(server: MCPServerConfig) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    cmd = (server.command or "").replace("\\", "/").split("/")[-1].strip().lower()
    args = [a.lower() for a in server.args]
    full_lower = server.full_command.lower()

    if cmd in ("sudo", "su", "doas", "pkexec", "runas", "gsudo") or re.search(r"\b(sudo|doas|pkexec)\s+", full_lower):
        findings.append(
            RiskFinding(
                rule_id="MCP-PRIV-001",
                category=FindingCategory.HIGH_PRIVILEGE,
                points=40,
                title="MCP server executed with elevated root/admin privileges",
                detail=f"Server '{server.name}' invokes privilege escalation in command '{server.full_command}'.",
                remediation="Never run MCP servers as root/Administrator; grant minimum required group or file permissions instead.",
            )
        )

    is_container_cmd = cmd in ("docker", "podman") or any(t in args for t in ("docker", "podman"))
    if is_container_cmd:
        if "--privileged" in args:
            findings.append(
                RiskFinding(
                    rule_id="MCP-PRIV-002",
                    category=FindingCategory.HIGH_PRIVILEGE,
                    points=40,
                    title="Containerized MCP server runs with --privileged flag",
                    detail="The '--privileged' flag disables container isolation and grants full host kernel capabilities.",
                    remediation="Remove '--privileged' and drop all unnecessary Linux capabilities (--cap-drop=ALL).",
                )
            )
        if any("docker.sock" in a or "podman.sock" in a for a in args):
            findings.append(
                RiskFinding(
                    rule_id="MCP-PRIV-003",
                    category=FindingCategory.HIGH_PRIVILEGE,
                    points=40,
                    title="Container runtime socket mounted inside MCP server container",
                    detail="Mounting docker.sock/podman.sock provides root-equivalent host takeover capability.",
                    remediation="Avoid mounting the container socket or use a restricted read-only socket proxy.",
                )
            )
        if "--network=host" in args or ("--network" in args and "host" in args):
            findings.append(
                RiskFinding(
                    rule_id="MCP-PRIV-004",
                    category=FindingCategory.HIGH_PRIVILEGE,
                    points=20,
                    title="Containerized MCP server uses host networking (--network=host)",
                    detail="Host networking bypasses container network namespace isolation.",
                    remediation="Use bridge networking and explicitly publish only required localhost ports.",
                )
            )

    return findings


def _check_risky_patterns(server: MCPServerConfig) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    full_cmd = server.full_command
    full_lower = full_cmd.lower()

    # 1. Auto-approve / alwaysAllow tool execution
    if server.always_allow:
        if "*" in server.always_allow or len(server.always_allow) >= 5:
            findings.append(
                RiskFinding(
                    rule_id="MCP-PAT-001",
                    category=FindingCategory.RISKY_PATTERN,
                    points=25,
                    title="Broad autonomous tool execution enabled (alwaysAllow)",
                    detail=f"Server '{server.name}' auto-approves {len(server.always_allow)} tool(s) ({', '.join(server.always_allow[:5])}) without user confirmation.",
                    remediation="Clear 'alwaysAllow' / 'autoApprove' lists for state-changing or sensitive tools.",
                )
            )
        else:
            findings.append(
                RiskFinding(
                    rule_id="MCP-PAT-002",
                    category=FindingCategory.RISKY_PATTERN,
                    points=12,
                    title="Partial tool auto-approval enabled (alwaysAllow)",
                    detail=f"Tools configured to bypass human confirmation: {', '.join(server.always_allow)}.",
                    remediation="Ensure only strictly read-only, low-risk tools are included in alwaysAllow.",
                )
            )

    # 2. Dangerous CLI flags
    if any(
        flag in full_lower
        for flag in (
            "--dangerously-skip-permissions",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--allow-all",
            "--unsafe",
            "--trust-all",
        )
    ):
        findings.append(
            RiskFinding(
                rule_id="MCP-PAT-003",
                category=FindingCategory.RISKY_PATTERN,
                points=25,
                title="Dangerous sandbox or permission bypass flag in arguments",
                detail=f"Command arguments disable built-in safety boundaries: '{full_cmd}'.",
                remediation="Remove '--no-sandbox' or '--dangerously-skip-permissions' flags.",
            )
        )

    # 3. Raw shell wrapper with inline command (-c / /c) or remote pipe
    if re.search(r"\b(curl|wget|iwr|invoke-webrequest)\b.*\|\s*(sh|bash|zsh|python|pwsh|powershell|iex)", full_lower):
        findings.append(
            RiskFinding(
                rule_id="MCP-PAT-004",
                category=FindingCategory.RISKY_PATTERN,
                points=45,
                title="Remote script piped directly into shell interpreter",
                detail=f"Server command downloads and executes unverified remote code: '{full_cmd}'.",
                remediation="Download, verify checksums, and inspect server binaries locally before configuring.",
            )
        )
    else:
        base_cmd = (server.command or "").replace("\\", "/").split("/")[-1].lower()
        if base_cmd in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe") and any(
            a.lower() in ("-c", "/c", "-command", "-encodedcommand", "-enc") for a in server.args
        ):
            findings.append(
                RiskFinding(
                    rule_id="MCP-PAT-005",
                    category=FindingCategory.RISKY_PATTERN,
                    points=15,
                    title="Inline shell wrapper invocation",
                    detail=f"Server spawns an intermediate shell interpreter ('{server.command}') to run commands.",
                    remediation="Invoke the target binary or runtime directly without wrapping in 'sh -c' or 'cmd /c'.",
                )
            )

    return findings


def _check_compound_risks(
    server: MCPServerConfig, existing_findings: list[RiskFinding]
) -> list[RiskFinding]:
    """Identify dangerous multi-factor combinations that warrant CRITICAL escalation."""
    compound: list[RiskFinding] = []
    rule_ids = {f.rule_id for f in existing_findings}
    categories = {f.category for f in existing_findings}

    # Combination 1: Unpinned dynamic package + privileged/destructive capability (root, shell, root fs)
    has_unpinned = FindingCategory.UNPINNED_PACKAGE in categories
    has_destructive_cap = bool(
        rule_ids & {"MCP-TOOL-001", "MCP-TOOL-002", "MCP-PRIV-001", "MCP-PRIV-002", "MCP-PRIV-003"}
    )
    if has_unpinned and has_destructive_cap:
        compound.append(
            RiskFinding(
                rule_id="MCP-COMP-001",
                category=FindingCategory.RISKY_PATTERN,
                points=15,
                title="Unpinned package combined with privileged or unrestricted host capability",
                detail="Executing an unpinned package with root/filesystem/shell access magnifies supply-chain impact.",
                remediation="Pin the exact package version and isolate filesystem or shell scope.",
            )
        )

    # Combination 2: High-impact execution (shell, root fs, database) + autonomous approval or hardcoded secret
    has_dangerous_tool = bool(rule_ids & {"MCP-TOOL-001", "MCP-TOOL-002", "MCP-TOOL-005"})
    has_autonomy_or_secret_or_priv = bool(
        rule_ids & {"MCP-PAT-001", "MCP-PAT-003", "MCP-ENV-001", "MCP-PRIV-001", "MCP-PRIV-002", "MCP-PRIV-003"}
    )
    if has_dangerous_tool and has_autonomy_or_secret_or_priv and "MCP-COMP-001" not in {c.rule_id for c in compound}:
        compound.append(
            RiskFinding(
                rule_id="MCP-COMP-002",
                category=FindingCategory.RISKY_PATTERN,
                points=10,
                title="High-impact capability combined with autonomous execution or hardcoded credentials",
                detail=f"Server '{server.name}' pairs state-changing tools with bypassed approval gates, elevated privileges, or hardcoded secrets.",
                remediation="Enforce human-in-the-loop confirmation and least-privilege credentials for sensitive tools.",
            )
        )

    return compound


def _is_broad_filesystem_path(arg: str) -> bool:
    raw = arg.strip()
    if not raw or raw.startswith("-"):
        return False
    norm = raw.replace("\\", "/")
    cleaned = norm.rstrip("/")
    if not cleaned:
        return raw in ("/", "\\")
    if cleaned in SENSITIVE_PATHS or raw in SENSITIVE_PATHS:
        return True
    # Windows drive roots like C: or D:\
    if re.match(r"^[a-zA-Z]:$", cleaned):
        return True
    # Direct user home directories: /home/<user>, /Users/<user>, C:/Users/<user>
    parts = [p for p in cleaned.split("/") if p]
    if len(parts) == 2 and parts[0] in ("home", "Users"):
        return True
    if len(parts) == 3 and re.match(r"^[a-zA-Z]:$", parts[0]) and parts[1].lower() == "users":
        return True
    if cleaned.lower().endswith((".ssh", ".aws", ".gnupg", ".kube")):
        return True
    return False


def _extract_package_token(runner: str, args: list[str]) -> str | None:
    skip_next = False
    for idx, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if runner == "pnpm" and idx == 0 and arg == "dlx":
            continue
        if arg in ("-y", "--yes", "--quiet", "-q", "--no-install"):
            continue
        if arg in ("-p", "--package", "--from"):
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _is_version_pinned(pkg_token: str) -> bool:
    """Return True if an npm or PyPI package specifier includes an explicit version pin."""
    if pkg_token.startswith(("./", "../", "/")) or re.match(r"^[a-zA-Z]:[/\\]", pkg_token):
        return True
    if pkg_token.startswith("@"):
        rest = pkg_token[1:]
        if "@" in rest:
            ver = rest.split("@", 1)[1]
            return bool(ver) and ver.lower() != "latest"
        return False
    if "==" in pkg_token:
        ver = pkg_token.split("==", 1)[1]
        return bool(ver)
    if "@" in pkg_token:
        ver = pkg_token.split("@", 1)[1]
        return bool(ver) and ver.lower() != "latest"
    return False


def _is_placeholder_value(val: str) -> bool:
    lower = val.strip().lower()
    placeholders = {
        "your_api_key",
        "your-api-key",
        "your_token_here",
        "insert_key_here",
        "changeme",
        "replace_me",
        "todo",
        "xxx",
        "xxxx",
        "none",
        "null",
        "true",
        "false",
        "<api_key>",
        "<token>",
        "example",
        "dummy",
        "test",
    }
    if lower in placeholders:
        return True
    if lower.startswith(("your_", "your-", "<", "replace_", "insert_", "todo_")):
        return True
    return False
