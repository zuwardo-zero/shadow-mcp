"""Discovery engine for local MCP client configurations and running AI agent processes."""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any

from shadow_mcp.models import ConfigParseWarning, DiscoveredProcess, MCPServerConfig


@dataclass(frozen=True)
class ClientSignature:
    """Known MCP client configuration file location pattern."""

    client_name: str
    relative_paths: tuple[str, ...]


# Well-known locations across Linux, macOS, and Windows relative to user home
HOME_CLIENT_SIGNATURES: tuple[ClientSignature, ...] = (
    ClientSignature(
        "Claude Desktop",
        (
            ".config/Claude/claude_desktop_config.json",
            "Library/Application Support/Claude/claude_desktop_config.json",
            "AppData/Roaming/Claude/claude_desktop_config.json",
        ),
    ),
    ClientSignature(
        "Claude Code",
        (
            ".claude.json",
            ".claude/mcp.json",
            ".claude/settings.json",
            ".claude/settings.local.json",
        ),
    ),
    ClientSignature(
        "Cursor",
        (
            ".cursor/mcp.json",
            ".config/Cursor/User/globalStorage/cursor.mcp/mcp.json",
            "Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json",
            "AppData/Roaming/Cursor/User/globalStorage/cursor.mcp/mcp.json",
        ),
    ),
    ClientSignature(
        "Windsurf",
        (
            ".codeium/windsurf/mcp_config.json",
            ".config/Windsurf/mcp_config.json",
            "Library/Application Support/Windsurf/mcp_config.json",
            "AppData/Roaming/Windsurf/mcp_config.json",
        ),
    ),
    ClientSignature(
        "VS Code",
        (
            ".config/Code/User/mcp.json",
            ".config/Code/User/settings.json",
            "Library/Application Support/Code/User/mcp.json",
            "Library/Application Support/Code/User/settings.json",
            "AppData/Roaming/Code/User/mcp.json",
            "AppData/Roaming/Code/User/settings.json",
        ),
    ),
    ClientSignature(
        "Cline (VS Code)",
        (
            ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            ".vscode-server/data/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            "AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        ),
    ),
    ClientSignature(
        "Roo Code (VS Code)",
        (
            ".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json",
            ".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
            ".vscode-server/data/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
            "Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
            "AppData/Roaming/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        ),
    ),
    ClientSignature(
        "Continue",
        (
            ".continue/config.json",
        ),
    ),
    ClientSignature(
        "Zed",
        (
            ".config/zed/settings.json",
            "Library/Application Support/Zed/settings.json",
            "AppData/Roaming/Zed/settings.json",
        ),
    ),
    ClientSignature(
        "Generic MCP",
        (
            ".mcp.json",
            "mcp.json",
            ".config/mcp/mcp.json",
        ),
    ),
)

WORKSPACE_CONFIG_PATTERNS: tuple[tuple[str, str], ...] = (
    (".mcp.json", "Workspace MCP"),
    ("mcp.json", "Workspace MCP"),
    ("claude_desktop_config.json", "Claude Desktop (Workspace)"),
    ("cline_mcp_settings.json", "Cline (Workspace)"),
    ("mcp_config.json", "Windsurf (Workspace)"),
    (".cursor/mcp.json", "Cursor (Workspace)"),
    (".vscode/mcp.json", "VS Code (Workspace)"),
    (".continue/config.json", "Continue (Workspace)"),
)

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "impvenv",
    "certipy-venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "go",
    ".cache",
    ".local",
    ".npm",
    ".cargo",
    ".rustup",
    "Library",
    "AppData",
}

MAX_CONFIG_FILE_BYTES = 10 * 1024 * 1024  # 10 MB upper bound for config files


@dataclass(frozen=True)
class ProcessSignature:
    """Signature for identifying running MCP servers and AI coding agents."""

    label: str
    pattern: re.Pattern[str]


PROCESS_SIGNATURES: tuple[ProcessSignature, ...] = (
    ProcessSignature(
        "Official MCP Server (@modelcontextprotocol)",
        re.compile(r"@modelcontextprotocol/server-[a-zA-Z0-9_-]+", re.IGNORECASE),
    ),
    ProcessSignature(
        "Playwright MCP Server",
        re.compile(r"@playwright/mcp|mcp-server-playwright", re.IGNORECASE),
    ),
    ProcessSignature(
        "Python MCP Server (mcp-server-* / fastmcp)",
        re.compile(
            r"(\bmcp-server-[a-zA-Z0-9_-]+|\bfastmcp\b|\bmcp\s+(?:run|dev|install)\b|"
            r"\bpython[0-9.]*\s+-m\s+[a-zA-Z0-9_.]*mcp[a-zA-Z0-9_.]*)",
            re.IGNORECASE,
        ),
    ),
    ProcessSignature(
        "Node/Deno/Bun Wrapper MCP Server",
        re.compile(
            r"\b(?:npx|uvx|bunx|pnpm\s+dlx|yarn\s+dlx|deno\s+run)\b[^\n]*\bmcp\b",
            re.IGNORECASE,
        ),
    ),
    ProcessSignature(
        "Dockerized MCP Server",
        re.compile(
            r"\b(?:docker|podman)\s+(?:run|exec)\b[^\n]*\bmcp[a-zA-Z0-9_./:-]*",
            re.IGNORECASE,
        ),
    ),
    ProcessSignature(
        "Custom MCP Script (*mcp*.py / *mcp*.js / *mcp*.ts)",
        re.compile(
            r"\b(?:python[0-9.]*|node|tsx|ts-node|bun|deno)\b[^\n]*\b[\w./\\-]*mcp[\w.-]*\.(?:py|js|ts|mjs|cjs)\b",
            re.IGNORECASE,
        ),
    ),
    ProcessSignature(
        "MCP Inspector / Gateway / Proxy",
        re.compile(
            r"\b(?:mcp-inspector|mcp-proxy|supergateway|mcpo|mcp-bridge)\b",
            re.IGNORECASE,
        ),
    ),
    ProcessSignature(
        "Ollama Local LLM Runner",
        re.compile(r"\bollama(?:\.exe)?\s+(?:serve|run)\b", re.IGNORECASE),
    ),
    ProcessSignature(
        "Claude Code CLI Agent",
        re.compile(
            r"(?:@anthropic-ai/claude-code|\bclaude(?:\.exe)?\b\s+(?:--dangerously-skip-permissions|--mcp-config|mcp\s+serve))",
            re.IGNORECASE,
        ),
    ),
    ProcessSignature(
        "Autonomous AI Coding Agent (Aider / OpenHands / Goose / Codex)",
        re.compile(
            r"\b(?:aider|openhands|goose\s+(?:session|run)|@openai/codex)\b",
            re.IGNORECASE,
        ),
    ),
)

# Fallback pattern matched against the binary/command name (`comm`) when `args` is truncated
TRUNCATED_COMM_SIGNATURE = ProcessSignature(
    "MCP Server Binary (Truncated Command Line)",
    re.compile(r"^(?:mcp-server-[a-zA-Z0-9_-]*|fastmcp|mcp-proxy|mcp-inspector)$", re.IGNORECASE),
)


def strip_jsonc_comments(text: str) -> str:
    """Strip UTF-8 BOM, // and /* */ comments, and trailing commas from JSONC text safely."""
    text = text.replace("\ufeff", "")

    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escape = False

    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] not in ("\n", "\r"):
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                if i + 1 < n:
                    i += 2
                else:
                    i = n
                continue

        out.append(ch)
        i += 1

    cleaned = "".join(out)
    # Remove trailing commas before } or ] (including nested trailing commas)
    prev = None
    while prev != cleaned:
        prev = cleaned
        cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
    return cleaned


def load_json_or_jsonc(path: Path) -> Any:
    """Parse standard JSON or JSON-with-comments (JSONC) with defensive size & emptiness checks."""
    try:
        stat = path.stat()
    except OSError as exc:
        raise OSError(f"Cannot stat file: {exc}") from exc

    if stat.st_size > MAX_CONFIG_FILE_BYTES:
        raise ValueError(f"Config file exceeds maximum size limit ({stat.st_size} bytes)")

    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    if not raw.strip():
        return {}

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        cleaned = strip_jsonc_comments(raw)
        if not cleaned.strip():
            return {}
        return json.loads(cleaned)


def infer_client_from_path(path: Path | PurePath | str) -> str:
    """Guess client name from file path across POSIX and Windows path conventions."""
    p_norm = str(path).replace("\\", "/").lower()
    if "saoudrizwan.claude-dev" in p_norm or "cline" in p_norm and "roo-cline" not in p_norm:
        return "Cline"
    if "rooveterinaryinc" in p_norm or "roo-cline" in p_norm:
        return "Roo Code"
    if "claude_desktop" in p_norm or "/claude/" in p_norm:
        return "Claude Desktop"
    if "/.claude/" in p_norm or p_norm.endswith("/.claude.json") or p_norm == ".claude.json":
        return "Claude Code"
    if "cursor" in p_norm:
        return "Cursor"
    if "windsurf" in p_norm or "codeium" in p_norm:
        return "Windsurf"
    if "continue" in p_norm:
        return "Continue"
    if "/zed/" in p_norm or "zed/settings.json" in p_norm:
        return "Zed"
    if "vscode" in p_norm or "/code/" in p_norm:
        return "VS Code"
    return "Generic MCP Config"


def parse_mcp_config_file(
    path: Path, client_name: str | None = None
) -> tuple[list[MCPServerConfig], ConfigParseWarning | None]:
    """Extract all MCPServerConfig definitions from a JSON/JSONC config file."""
    resolved_client = client_name or infer_client_from_path(path)
    try:
        data = load_json_or_jsonc(path)
    except PermissionError as exc:
        return [], ConfigParseWarning(
            path=str(path),
            client=resolved_client,
            error=f"Permission denied reading config: {exc}",
        )
    except Exception as exc:
        return [], ConfigParseWarning(
            path=str(path),
            client=resolved_client,
            error=f"Failed to parse JSON config: {exc}",
        )

    if data is None:
        return [], None

    if not isinstance(data, dict):
        return [], ConfigParseWarning(
            path=str(path),
            client=resolved_client,
            error="Root JSON element is not an object",
        )

    servers: list[MCPServerConfig] = []

    # 1. Standard "mcpServers" dict (Claude Desktop, Cursor, Windsurf, Cline, Roo, .mcp.json)
    if isinstance(data.get("mcpServers"), dict):
        for name, srv_data in data["mcpServers"].items():
            if isinstance(srv_data, dict):
                servers.append(_build_server_config(name, resolved_client, path, srv_data))

    # 2. VS Code "mcp" -> "servers" or top-level "servers"
    mcp_block = data.get("mcp")
    if isinstance(mcp_block, dict) and isinstance(mcp_block.get("servers"), dict):
        for name, srv_data in mcp_block["servers"].items():
            if isinstance(srv_data, dict):
                servers.append(_build_server_config(name, resolved_client, path, srv_data))
    elif isinstance(data.get("servers"), dict) and "mcpServers" not in data:
        for name, srv_data in data["servers"].items():
            if isinstance(srv_data, dict):
                servers.append(_build_server_config(name, resolved_client, path, srv_data))

    # 3. Zed "context_servers"
    if isinstance(data.get("context_servers"), dict):
        for name, srv_data in data["context_servers"].items():
            if isinstance(srv_data, dict):
                cmd_obj = srv_data.get("command")
                if isinstance(cmd_obj, dict):
                    normalized = {
                        **srv_data,
                        "command": cmd_obj.get("path"),
                        "args": cmd_obj.get("args", []),
                        "env": cmd_obj.get("env", {}),
                    }
                    servers.append(_build_server_config(name, resolved_client, path, normalized))
                else:
                    servers.append(_build_server_config(name, resolved_client, path, srv_data))

    # 4. Continue "experimental.modelContextProtocolServers" or "mcpServers" list
    exp = data.get("experimental")
    if isinstance(exp, dict) and isinstance(exp.get("modelContextProtocolServers"), list):
        for idx, item in enumerate(exp["modelContextProtocolServers"]):
            if isinstance(item, dict):
                t_block = item.get("transport", item)
                if isinstance(t_block, dict):
                    name = item.get("name") or t_block.get("name") or f"continue-mcp-{idx + 1}"
                    servers.append(_build_server_config(str(name), resolved_client, path, t_block))

    if isinstance(data.get("mcpServers"), list):
        for idx, item in enumerate(data["mcpServers"]):
            if isinstance(item, dict):
                name = item.get("name") or f"mcp-server-{idx + 1}"
                servers.append(_build_server_config(str(name), resolved_client, path, item))

    # 5. Claude Code project-scoped MCP servers inside ~/.claude.json ("projects" -> path -> "mcpServers")
    if isinstance(data.get("projects"), dict):
        for proj_path, proj_cfg in data["projects"].items():
            if isinstance(proj_cfg, dict) and isinstance(proj_cfg.get("mcpServers"), dict):
                for name, srv_data in proj_cfg["mcpServers"].items():
                    if isinstance(srv_data, dict):
                        norm_proj = str(proj_path).replace("\\", "/").rstrip("/")
                        proj_leaf = norm_proj.split("/")[-1] if norm_proj else str(proj_path)
                        scoped_name = f"{name} ({proj_leaf})"
                        servers.append(
                            _build_server_config(scoped_name, resolved_client, path, srv_data)
                        )

    return servers, None


def _build_server_config(
    name: str, client: str, source_path: Path, raw: dict[str, Any]
) -> MCPServerConfig:
    command_raw = raw.get("command")
    command: str | None = None
    extra_lead_args: list[str] = []

    if isinstance(command_raw, str):
        command = command_raw.strip() or None
    elif isinstance(command_raw, list) and command_raw:
        # Handle configs where "command" is specified as an array ["npx", "-y", ...]
        command = str(command_raw[0]).strip() or None
        extra_lead_args = [str(x) for x in command_raw[1:] if x is not None]

    raw_args = raw.get("args", [])
    if isinstance(raw_args, list):
        args = extra_lead_args + [str(a) for a in raw_args if a is not None]
    elif isinstance(raw_args, str) and raw_args.strip():
        args = extra_lead_args + raw_args.strip().split()
    else:
        args = extra_lead_args

    raw_env = raw.get("env", {})
    env = (
        {str(k): ("" if v is None else str(v)) for k, v in raw_env.items()}
        if isinstance(raw_env, dict)
        else {}
    )

    url_raw = raw.get("url") or raw.get("serverUrl") or raw.get("endpoint")
    url = str(url_raw).strip() if isinstance(url_raw, (str, int, float)) and str(url_raw).strip() else None

    raw_headers = raw.get("headers", {})
    headers = (
        {str(k): ("" if v is None else str(v)) for k, v in raw_headers.items()}
        if isinstance(raw_headers, dict)
        else {}
    )

    transport = str(raw.get("type") or raw.get("transport") or "").strip().lower()
    if not transport:
        transport = "http/sse" if (url and not command) else "stdio"

    disabled = bool(raw.get("disabled", False))

    always_allow_raw = (
        raw.get("alwaysAllow")
        or raw.get("autoApprove")
        or raw.get("allowedTools")
        or []
    )
    always_allow = (
        [str(x) for x in always_allow_raw if x is not None]
        if isinstance(always_allow_raw, list)
        else []
    )

    tools_raw = raw.get("tools", [])
    declared_tools = (
        [str(t) for t in tools_raw if t is not None] if isinstance(tools_raw, list) else []
    )

    return MCPServerConfig(
        name=str(name),
        client=client,
        source_path=str(source_path),
        transport=transport,
        command=command,
        args=args,
        env=env,
        url=url,
        headers=headers,
        disabled=disabled,
        always_allow=always_allow,
        declared_tools=declared_tools,
        raw_config=raw,
    )


def _get_windows_env_roots() -> list[Path]:
    """Return additional Windows APPDATA / LOCALAPPDATA roots when running on Windows."""
    roots: list[Path] = []
    for env_var in ("APPDATA", "LOCALAPPDATA", "USERPROFILE"):
        val = os.environ.get(env_var)
        if val:
            try:
                p = Path(val)
                if p.exists() and p not in roots:
                    roots.append(p)
            except OSError:
                pass
    return roots


def discover_configs(
    extra_paths: list[Path] | None = None,
    workspace_dirs: list[Path] | None = None,
    include_home: bool = True,
    max_depth: int = 3,
) -> tuple[list[MCPServerConfig], list[str], list[ConfigParseWarning], int]:
    """Scan standard client locations, workspace directories, and explicit paths."""
    candidate_files: list[tuple[Path, str]] = []
    seen_paths: set[Path] = set()
    locations_checked = 0

    def _add_candidate(p: Path, client_label: str) -> None:
        try:
            resolved = p.expanduser().resolve()
        except OSError:
            resolved = p.expanduser()
        if resolved in seen_paths:
            return
        try:
            is_file = resolved.is_file()
        except OSError:
            is_file = False
        if is_file:
            seen_paths.add(resolved)
            candidate_files.append((resolved, client_label))

    if include_home:
        home = Path.home()
        for sig in HOME_CLIENT_SIGNATURES:
            for rel in sig.relative_paths:
                locations_checked += 1
                _add_candidate(home / rel, sig.client_name)

        # Also check Windows APPDATA/LOCALAPPDATA directly if set
        for win_root in _get_windows_env_roots():
            for sig in HOME_CLIENT_SIGNATURES:
                for rel in sig.relative_paths:
                    if rel.startswith("AppData/Roaming/"):
                        sub = rel.removeprefix("AppData/Roaming/")
                        locations_checked += 1
                        _add_candidate(win_root / sub, sig.client_name)

    search_roots = list(workspace_dirs or [])
    if not search_roots and include_home:
        cwd = Path.cwd()
        search_roots.append(cwd)

    for root in search_roots:
        try:
            exists = root.exists()
        except OSError:
            exists = False
        if not exists:
            continue
        if root.is_file():
            locations_checked += 1
            _add_candidate(root, infer_client_from_path(root))
            continue

        # Direct workspace patterns
        for rel_pat, label in WORKSPACE_CONFIG_PATTERNS:
            locations_checked += 1
            _add_candidate(root / rel_pat, label)

        # Bounded recursive search for *mcp*.json and claude_desktop_config.json
        for found_path in _walk_for_mcp_configs(root, max_depth=max_depth):
            locations_checked += 1
            _add_candidate(found_path, infer_client_from_path(found_path))

    for custom in extra_paths or []:
        locations_checked += 1
        try:
            is_file = custom.is_file()
            is_dir = custom.is_dir()
        except OSError:
            is_file = False
            is_dir = False

        if is_file:
            _add_candidate(custom, infer_client_from_path(custom))
        elif is_dir:
            for rel_pat, label in WORKSPACE_CONFIG_PATTERNS:
                _add_candidate(custom / rel_pat, label)
            for found_path in _walk_for_mcp_configs(custom, max_depth=max_depth):
                _add_candidate(found_path, infer_client_from_path(found_path))

    all_servers: list[MCPServerConfig] = []
    config_files_found: list[str] = []
    warnings: list[ConfigParseWarning] = []

    for file_path, client_label in candidate_files:
        servers, warning = parse_mcp_config_file(file_path, client_label)
        if warning is not None:
            warnings.append(warning)
        if servers or _is_dedicated_mcp_filename(file_path.name):
            config_files_found.append(str(file_path))
        all_servers.extend(servers)

    return all_servers, config_files_found, warnings, locations_checked


def _is_dedicated_mcp_filename(filename: str) -> bool:
    lower = filename.lower()
    return (
        "mcp" in lower
        or lower == "claude_desktop_config.json"
        or lower == "cline_mcp_settings.json"
    )


def _walk_for_mcp_configs(root: Path, max_depth: int = 3) -> list[Path]:
    """Bounded directory walk looking for MCP config files without following noisy trees."""
    matches: list[Path] = []
    try:
        root_resolved = root.resolve()
    except OSError:
        return matches

    for dirpath, dirnames, filenames in os.walk(root_resolved, topdown=True):
        current = Path(dirpath)
        try:
            rel_parts = current.relative_to(root_resolved).parts
        except ValueError:
            rel_parts = ()

        if len(rel_parts) >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [
                d
                for d in dirnames
                if d not in SKIP_DIRS
                and not (
                    d.startswith(".")
                    and d not in {".cursor", ".vscode", ".claude", ".continue", ".codeium"}
                )
            ]

        for fname in filenames:
            lower = fname.lower()
            if lower in {
                ".mcp.json",
                "mcp.json",
                "mcp_config.json",
                "claude_desktop_config.json",
                "cline_mcp_settings.json",
            } or (
                lower.endswith("mcp.json")
                or lower.endswith("-mcp.json")
                or lower.endswith("_mcp.json")
            ):
                matches.append(current / fname)

    return matches


def discover_running_processes() -> list[DiscoveredProcess]:
    """Inspect running processes for AI agents and MCP server command lines."""
    raw_procs = _list_os_processes()
    discovered: list[DiscoveredProcess] = []
    current_pid = os.getpid()

    for pid, user, comm, cmdline in raw_procs:
        if pid == current_pid:
            continue
        if "shadow_mcp" in cmdline or "shadow-mcp" in cmdline:
            continue

        matched_label: str | None = None
        for sig in PROCESS_SIGNATURES:
            if sig.pattern.search(cmdline):
                matched_label = sig.label
                break

        # Fallback: check executable/command name when process args are truncated
        if matched_label is None and TRUNCATED_COMM_SIGNATURE.pattern.search(comm):
            matched_label = TRUNCATED_COMM_SIGNATURE.label

        if matched_label is not None:
            discovered.append(
                DiscoveredProcess(
                    pid=pid,
                    user=user,
                    command=comm,
                    cmdline=cmdline,
                    matched_signature=matched_label,
                )
            )

    return discovered


def _read_linux_proc_cmdline(pid: int) -> str | None:
    """Read full NUL-separated command line from /proc/<pid>/cmdline on Linux if available."""
    proc_path = Path(f"/proc/{pid}/cmdline")
    try:
        raw = proc_path.read_bytes()
    except OSError:
        return None
    if not raw:
        return None
    parts = [p.decode("utf-8", errors="replace") for p in raw.rstrip(b"\x00").split(b"\x00")]
    full = " ".join(p for p in parts if p).strip()
    return full or None


def _list_os_processes() -> list[tuple[int, str, str, str]]:
    """Return list of (pid, user, command, cmdline) across Linux, macOS, and Windows."""
    sys_name = platform.system().lower()
    if sys_name in ("linux", "darwin"):
        try:
            res = subprocess.run(
                ["ps", "-eo", "pid=,user=,comm=,args=", "-ww"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode != 0 or not res.stdout:
                res = subprocess.run(
                    ["ps", "-eo", "pid=,user=,comm=,args="],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            if res.returncode == 0 and res.stdout:
                procs = _parse_ps_output(res.stdout)
                if sys_name == "linux":
                    enriched: list[tuple[int, str, str, str]] = []
                    for pid, user, comm, cmdline in procs:
                        proc_cmd = _read_linux_proc_cmdline(pid)
                        if proc_cmd and len(proc_cmd) > len(cmdline):
                            cmdline = proc_cmd
                        enriched.append((pid, user, comm, cmdline))
                    return enriched
                return procs
        except Exception:
            pass

    if sys_name == "windows":
        # Prefer PowerShell / CIM to get full CommandLine on Windows; fall back to tasklist
        try:
            ps_cmd = (
                "Get-CimInstance Win32_Process | "
                "Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                parsed_cim = _parse_windows_cim_json(res.stdout)
                if parsed_cim:
                    return parsed_cim
        except Exception:
            pass

        try:
            res = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH", "/V"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout:
                return _parse_tasklist_output(res.stdout)
        except Exception:
            pass

    return []


def _parse_ps_output(stdout: str) -> list[tuple[int, str, str, str]]:
    results: list[tuple[int, str, str, str]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 3)
        if len(parts) < 3:
            continue
        pid_str, user, comm = parts[0], parts[1], parts[2]
        cmdline = parts[3] if len(parts) > 3 else comm
        try:
            pid = int(pid_str)
        except ValueError:
            continue
        results.append((pid, user, comm, cmdline))
    return results


def _parse_windows_cim_json(stdout: str) -> list[tuple[int, str, str, str]]:
    """Parse PowerShell Get-CimInstance Win32_Process JSON output."""
    try:
        data = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []

    results: list[tuple[int, str, str, str]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            pid = int(item.get("ProcessId", 0))
        except (ValueError, TypeError):
            continue
        if pid <= 0:
            continue
        comm = str(item.get("Name") or "unknown")
        cmdline = str(item.get("CommandLine") or comm)
        results.append((pid, "unknown", comm, cmdline))
    return results


def _parse_tasklist_output(stdout: str) -> list[tuple[int, str, str, str]]:
    import csv
    import io

    results: list[tuple[int, str, str, str]] = []
    reader = csv.reader(io.StringIO(stdout))
    for row in reader:
        if len(row) < 2:
            continue
        comm = row[0]
        try:
            pid = int(row[1])
        except ValueError:
            continue
        user = row[6] if len(row) > 6 else "unknown"
        cmdline = f"{comm} {row[-1]}".strip() if len(row) > 8 else comm
        results.append((pid, user, comm, cmdline))
    return results
