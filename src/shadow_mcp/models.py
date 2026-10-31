"""Core data models for Shadow MCP discovery and risk evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    """Categorical severity levels mapped from numeric risk scores."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: int) -> RiskLevel:
        if score >= 75:
            return cls.CRITICAL
        if score >= 50:
            return cls.HIGH
        if score >= 25:
            return cls.MEDIUM
        return cls.LOW


class FindingCategory(str, Enum):
    """Security risk domain categories."""

    PERMISSIVE_TOOLS = "Overly Permissive Tools & Capabilities"
    UNAUTHENTICATED_ENDPOINT = "Missing Authentication / Open Endpoints"
    UNPINNED_PACKAGE = "Unpinned or Mutable Package Versions"
    SENSITIVE_ENV = "Sensitive Environment Variables & Secrets"
    HIGH_PRIVILEGE = "High-Privilege Execution Context"
    RISKY_PATTERN = "Known Risky Execution Patterns"


# Non-secret environment variable names that commonly appear in MCP configs
BENIGN_ENV_KEY_RE = re.compile(
    r"^(PATH|HOME|USER|LOGNAME|SHELL|LANG|LC_[A-Z_]+|TERM|TZ|TMPDIR|TEMP|TMP|"
    r"NODE_ENV|NODE_OPTIONS|NODE_PATH|NPM_CONFIG_[A-Z0-9_]+|"
    r"PYTHONUNBUFFERED|PYTHONPATH|PYTHONIOENCODING|PYTHONDONTWRITEBYTECODE|VIRTUAL_ENV|"
    r"UV_[A-Z0-9_]+|FASTMCP_[A-Z0-9_]+|MCP_TRANSPORT|MCP_TIMEOUT|"
    r"PORT|HOST|BIND_HOST|LOG_LEVEL|DEBUG|VERBOSE|COLOR|NO_COLOR|CI|"
    r"HTTP_PROXY|HTTPS_PROXY|NO_PROXY|SSL_CERT_FILE|SSL_CERT_DIR|REQUESTS_CA_BUNDLE)$",
    re.IGNORECASE,
)

SENSITIVE_ENV_KEY_RE = re.compile(
    r"(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|"
    r"AUTH|CREDENTIAL|CONN[_-]?STR|DATABASE[_-]?URL|DSN|BEARER|COOKIE|SESSION|"
    r"WEBHOOK|SIGNING[_-]?KEY|ENCRYPTION[_-]?KEY|CLIENT[_-]?SECRET)",
    re.IGNORECASE,
)

# Patterns for redacting inline secrets inside URLs, DSNs, Bearer headers, and CLI flags
_URI_CRED_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s@]+:)([^@\s]+)(@[^\s]+)"
)
_BEARER_RE = re.compile(
    r"\b(Bearer|Basic|Token)\s+([A-Za-z0-9._~+/-]+=*)", re.IGNORECASE
)
_INLINE_SECRET_TOKEN_RE = re.compile(
    r"\b("
    r"sk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{16,}|"
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{25,}|"
    r"github_pat_[A-Za-z0-9_]{25,}|"
    r"glpat-[A-Za-z0-9_-]{20,}|"
    r"hf_[A-Za-z0-9]{25,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")\b"
)


@dataclass(frozen=True)
class RiskFinding:
    """A single security risk observation attached to an MCP server or process."""

    rule_id: str
    category: FindingCategory
    points: int
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "points": self.points,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class MCPServerConfig:
    """Represents a discovered MCP server configuration entry."""

    name: str
    client: str
    source_path: str
    transport: str = "stdio"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    disabled: bool = False
    always_allow: list[str] = field(default_factory=list)
    declared_tools: list[str] = field(default_factory=list)
    raw_config: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    findings: list[RiskFinding] = field(default_factory=list)

    @property
    def full_command(self) -> str:
        if self.url and not self.command:
            return self.url
        parts = [self.command or ""] + self.args
        return " ".join(p for p in parts if p).strip()

    @property
    def redacted_env(self) -> dict[str, str]:
        """Return environment dictionary with sensitive values masked and safe config preserved."""
        redacted: dict[str, str] = {}
        for k, v in self.env.items():
            val_str = str(v) if not isinstance(v, str) else v
            redacted[k] = redact_env_value(k, val_str)
        return redacted

    @property
    def redacted_headers(self) -> dict[str, str]:
        """Return HTTP headers dictionary with authorization/API key values masked."""
        return {k: redact_env_value(k, str(v)) for k, v in self.headers.items()}

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "client": self.client,
            "source_path": self.source_path,
            "transport": self.transport,
            "command": self.command,
            "args": [redact_inline_secrets(a) for a in self.args],
            "env_keys": list(self.env.keys()),
            "env_redacted": self.redacted_env,
            "url": redact_inline_secrets(self.url) if self.url else None,
            "headers_redacted": self.redacted_headers,
            "disabled": self.disabled,
            "always_allow": self.always_allow,
            "declared_tools": self.declared_tools,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "findings": [f.to_dict() for f in self.findings],
        }
        if include_raw:
            data["raw_config"] = self.raw_config
        return data


@dataclass
class DiscoveredProcess:
    """Represents a running OS process matching AI agent or MCP server signatures."""

    pid: int
    user: str
    command: str
    cmdline: str
    matched_signature: str
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    findings: list[RiskFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "user": self.user,
            "command": self.command,
            "cmdline": redact_inline_secrets(self.cmdline),
            "matched_signature": self.matched_signature,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ConfigParseWarning:
    """Warning generated when a candidate config file is malformed or unreadable."""

    path: str
    client: str
    error: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "client": self.client,
            "error": self.error,
        }


@dataclass
class ScanReport:
    """Aggregated scan output containing servers, running processes, and warnings."""

    hostname: str
    platform_name: str
    timestamp: str
    scanned_locations: int
    config_files_found: list[str] = field(default_factory=list)
    servers: list[MCPServerConfig] = field(default_factory=list)
    processes: list[DiscoveredProcess] = field(default_factory=list)
    warnings: list[ConfigParseWarning] = field(default_factory=list)

    @property
    def summary_counts(self) -> dict[str, int]:
        counts = {
            "total_servers": len(self.servers),
            "total_processes": len(self.processes),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for srv in self.servers:
            counts[srv.risk_level.value.lower()] += 1
        for proc in self.processes:
            counts[proc.risk_level.value.lower()] += 1
        return counts

    @property
    def highest_risk_level(self) -> RiskLevel:
        levels = [s.risk_level for s in self.servers] + [p.risk_level for p in self.processes]
        if RiskLevel.CRITICAL in levels:
            return RiskLevel.CRITICAL
        if RiskLevel.HIGH in levels:
            return RiskLevel.HIGH
        if RiskLevel.MEDIUM in levels:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def to_dict(self, verbose: bool = False) -> dict[str, Any]:
        return {
            "metadata": {
                "hostname": self.hostname,
                "platform": self.platform_name,
                "timestamp": self.timestamp,
                "scanned_locations": self.scanned_locations,
                "config_files_found": self.config_files_found,
            },
            "summary": {
                **self.summary_counts,
                "highest_risk_level": self.highest_risk_level.value,
            },
            "servers": [s.to_dict(include_raw=verbose) for s in self.servers],
            "processes": [p.to_dict() for p in self.processes],
            "warnings": [w.to_dict() for w in self.warnings],
        }


def _looks_like_env_reference(val: str) -> bool:
    """Return True if value looks like a dynamic env placeholder rather than a hardcoded secret."""
    v = val.strip()
    if not v:
        return False
    return (
        (v.startswith("${") and v.endswith("}"))
        or (v.startswith("$") and len(v) > 1 and " " not in v)
        or (v.startswith("%") and v.endswith("%") and len(v) > 2 and " " not in v)
        or (v.startswith("{{") and v.endswith("}}"))
        or v.startswith(("env:", "op://", "vault:", "aws-ssm:", "keychain:", "secretref:"))
    )


def _mask_token(token: str) -> str:
    if len(token) > 8:
        return f"{token[:3]}***{token[-2:]}"
    if token:
        return "***"
    return ""


def redact_inline_secrets(text: str) -> str:
    """Redact embedded passwords in URIs, Bearer tokens, and known API key patterns in a string."""
    if not text:
        return text

    # 1. Redact user:password@host in connection URIs
    result = _URI_CRED_RE.sub(
        lambda m: f"{m.group(1)}{_mask_token(m.group(2))}{m.group(3)}", text
    )

    # 2. Redact Bearer / Basic / Token headers
    result = _BEARER_RE.sub(
        lambda m: f"{m.group(1)} {_mask_token(m.group(2))}", result
    )

    # 3. Redact known token signatures inline
    result = _INLINE_SECRET_TOKEN_RE.sub(lambda m: _mask_token(m.group(1)), result)
    return result


def redact_env_value(key: str, val: str) -> str:
    """Smart redaction for environment variable and header key-value pairs."""
    stripped = val.strip()
    if not stripped:
        return ""
    if _looks_like_env_reference(stripped):
        return stripped

    # Always redact embedded URI credentials or inline secret tokens
    inline_redacted = redact_inline_secrets(stripped)
    if inline_redacted != stripped:
        return inline_redacted

    # Preserve benign operational settings (LOG_LEVEL=info, NODE_ENV=production, PORT=3000, etc.)
    if BENIGN_ENV_KEY_RE.match(key) and not SENSITIVE_ENV_KEY_RE.search(key):
        return stripped
    if stripped.lower() in ("true", "false", "1", "0", "yes", "no", "debug", "info", "warn", "error", "production", "development"):
        return stripped
    if stripped.isdigit() and len(stripped) <= 6 and not SENSITIVE_ENV_KEY_RE.search(key):
        return stripped

    # Mask any value whose key looks sensitive or whose value looks like an opaque secret
    if SENSITIVE_ENV_KEY_RE.search(key) or len(stripped) >= 16:
        return _mask_token(stripped)

    return _mask_token(stripped)
