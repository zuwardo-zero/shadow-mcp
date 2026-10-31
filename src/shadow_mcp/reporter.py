"""Terminal table, summary, JSON, and YAML formatters for Shadow MCP scan results."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from shadow_mcp.models import (
    DiscoveredProcess,
    MCPServerConfig,
    RiskLevel,
    ScanReport,
    redact_inline_secrets,
)


class Ansi:
    """ANSI escape sequences with NO_COLOR and non-TTY fallback."""

    def __init__(self, enabled: bool | None = None) -> None:
        if enabled is None:
            no_color = os.environ.get("NO_COLOR") is not None
            is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
            enabled = is_tty and not no_color
        self.enabled = enabled

    def wrap(self, text: str, code: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self.wrap(text, "1")

    def dim(self, text: str) -> str:
        return self.wrap(text, "2")

    def cyan(self, text: str) -> str:
        return self.wrap(text, "36")

    def green(self, text: str) -> str:
        return self.wrap(text, "32")

    def yellow(self, text: str) -> str:
        return self.wrap(text, "33")

    def red(self, text: str) -> str:
        return self.wrap(text, "31")

    def bright_red(self, text: str) -> str:
        return self.wrap(text, "1;31")

    def risk_badge(self, level: RiskLevel, score: int | None = None) -> str:
        label = f"{level.value}" if score is None else f"{level.value} ({score})"
        if level == RiskLevel.CRITICAL:
            return self.bright_red(label)
        if level == RiskLevel.HIGH:
            return self.red(label)
        if level == RiskLevel.MEDIUM:
            return self.yellow(label)
        return self.green(label)


def render_json(report: ScanReport, verbose: bool = False) -> str:
    """Serialize ScanReport to formatted JSON."""
    return json.dumps(report.to_dict(verbose=verbose), indent=2)


def render_yaml(report: ScanReport, verbose: bool = False) -> str:
    """Serialize ScanReport to clean YAML without requiring external libraries."""
    data = report.to_dict(verbose=verbose)
    try:
        import yaml  # type: ignore

        return str(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    except ImportError:
        return _to_yaml(data)


def _to_yaml(obj: Any, indent: int = 0) -> str:
    """Lightweight recursive YAML serializer using standard library only."""
    pad = "  " * indent
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, str):
        if (
            not obj
            or any(c in obj for c in (":", "#", "\n", '"', "'", "{", "}", "[", "]", "&", "*", "?", "|", ">", "%", "@", "`"))
            or obj.strip() != obj
            or obj.lower() in ("true", "false", "null", "yes", "no")
        ):
            return json.dumps(obj)
        return obj
    if isinstance(obj, list):
        if not obj:
            return "[]"
        lines: list[str] = []
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                nested = _to_yaml(item, indent + 1)
                first_line, *rest = nested.splitlines()
                lines.append(f"{pad}- {first_line.lstrip()}")
                lines.extend(rest)
            else:
                lines.append(f"{pad}- {_to_yaml(item, indent + 1)}")
        return "\n".join(lines)
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        lines = []
        for k, v in obj.items():
            key_str = str(k)
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{key_str}:")
                lines.append(_to_yaml(v, indent + 1))
            else:
                lines.append(f"{pad}{key_str}: {_to_yaml(v, indent + 1)}")
        return "\n".join(lines)
    return json.dumps(str(obj))


def render_summary(report: ScanReport, color: bool | None = None) -> str:
    """Render a concise executive posture summary for terminal review."""
    ansi = Ansi(color)
    counts = report.summary_counts
    lines: list[str] = []

    lines.append(ansi.bold("SHADOW MCP - EXECUTIVE SECURITY SUMMARY"))
    lines.append("=" * 56)
    lines.append(f"Host:               {report.hostname} ({report.platform_name})")
    lines.append(f"Scan Timestamp:     {report.timestamp}")
    lines.append(f"Locations Checked:  {report.scanned_locations}")
    lines.append(f"Config Files Found: {len(report.config_files_found)}")
    lines.append(f"MCP Servers Found:  {counts['total_servers']}")
    lines.append(f"Active Processes:   {counts['total_processes']}")
    lines.append(
        f"Overall Posture:    {ansi.risk_badge(report.highest_risk_level)}"
    )
    lines.append("-" * 56)
    lines.append(
        "Risk Breakdown:     "
        f"{ansi.bright_red('CRITICAL: ' + str(counts['critical']))} | "
        f"{ansi.red('HIGH: ' + str(counts['high']))} | "
        f"{ansi.yellow('MEDIUM: ' + str(counts['medium']))} | "
        f"{ansi.green('LOW: ' + str(counts['low']))}"
    )

    risky_servers = [
        s for s in sorted(report.servers, key=lambda x: x.risk_score, reverse=True)
        if s.risk_score >= 25
    ]
    if risky_servers:
        lines.append("")
        lines.append(ansi.bold("Priority Findings:"))
        for srv in risky_servers[:5]:
            top_reason = srv.findings[0].title if srv.findings else "No issues detected"
            badge = ansi.risk_badge(srv.risk_level, srv.risk_score)
            lines.append(f"  * [{badge}] {ansi.bold(srv.name)} ({srv.client}) -> {top_reason}")
    else:
        lines.append("")
        lines.append(ansi.green("No Medium, High, or Critical risk MCP servers detected."))

    return "\n".join(lines)


def render_table_report(
    report: ScanReport, verbose: bool = False, color: bool | None = None
) -> str:
    """Render full formatted terminal report with inventory tables and risk justifications."""
    ansi = Ansi(color)
    out: list[str] = []

    out.append(ansi.bold("Shadow MCP - AI Agent & MCP Server Risk Scanner"))
    out.append(
        ansi.dim(
            f"Host: {report.hostname} ({report.platform_name}) | "
            f"Scanned {report.scanned_locations} paths | "
            f"Found {len(report.config_files_found)} config file(s)"
        )
    )
    out.append("")

    # Section 1: Configured MCP Servers
    out.append(ansi.bold(f"Configured MCP Servers ({len(report.servers)})"))
    if not report.servers:
        out.append(ansi.dim("  No MCP server configurations discovered."))
    else:
        sorted_servers = sorted(
            report.servers, key=lambda s: (s.risk_score, s.name), reverse=True
        )
        out.append(_format_servers_table(sorted_servers, ansi))

        if verbose:
            out.append("")
            out.append(ansi.bold("Detailed Server Findings & Remediations"))
            for srv in sorted_servers:
                out.extend(_format_server_details(srv, ansi))
        else:
            flagged = [s for s in sorted_servers if s.findings]
            if flagged:
                out.append("")
                out.append(ansi.bold("Risk Justifications (run with --verbose for remediation details)"))
                for srv in flagged:
                    badge = ansi.risk_badge(srv.risk_level, srv.risk_score)
                    reasons = "; ".join(f"{f.title} (+{f.points})" for f in srv.findings)
                    out.append(f"  - {ansi.bold(srv.name)} [{badge}]: {reasons}")

    out.append("")

    # Section 2: Running Processes
    out.append(ansi.bold(f"Running AI Agents & MCP Processes ({len(report.processes)})"))
    if not report.processes:
        out.append(ansi.dim("  No active AI agent or MCP server processes detected."))
    else:
        sorted_procs = sorted(
            report.processes, key=lambda p: (p.risk_score, p.pid), reverse=True
        )
        out.append(_format_processes_table(sorted_procs, ansi))

    # Section 3: Warnings
    if report.warnings:
        out.append("")
        out.append(ansi.yellow(f"Configuration Parse Warnings ({len(report.warnings)})"))
        for w in report.warnings:
            out.append(f"  ! {w.client} ({w.path}): {w.error}")

    # Footer Summary
    counts = report.summary_counts
    out.append("")
    out.append(
        f"Summary: {counts['total_servers']} server(s), {counts['total_processes']} process(es) | "
        f"{ansi.bright_red(str(counts['critical']) + ' Critical')}, "
        f"{ansi.red(str(counts['high']) + ' High')}, "
        f"{ansi.yellow(str(counts['medium']) + ' Medium')}, "
        f"{ansi.green(str(counts['low']) + ' Low')}"
    )

    return "\n".join(out)


def _format_servers_table(servers: list[MCPServerConfig], ansi: Ansi) -> str:
    headers = ["SERVER", "CLIENT", "TRANSPORT", "COMMAND / ENDPOINT", "RISK", "TOP JUSTIFICATION"]
    rows: list[list[str]] = []
    raw_risk_levels: list[RiskLevel] = []

    for srv in servers:
        name = _truncate(srv.name + (" (disabled)" if srv.disabled else ""), 24)
        client = _truncate(srv.client, 18)
        transport = _truncate(srv.transport, 10)
        cmd_str = _truncate(redact_inline_secrets(srv.full_command) or "(none)", 36)
        risk_str = f"{srv.risk_level.value} ({srv.risk_score})"
        sorted_findings = sorted(srv.findings, key=lambda f: f.points, reverse=True)
        top_just = (
            _truncate(sorted_findings[0].title, 44)
            if sorted_findings
            else "No high-risk patterns detected"
        )
        rows.append([name, client, transport, cmd_str, risk_str, top_just])
        raw_risk_levels.append(srv.risk_level)

    return _draw_box_table(headers, rows, ansi, risk_col_idx=4, risk_levels=raw_risk_levels)


def _format_processes_table(procs: list[DiscoveredProcess], ansi: Ansi) -> str:
    headers = ["PID", "USER", "SIGNATURE", "COMMAND LINE", "RISK"]
    rows: list[list[str]] = []
    raw_risk_levels: list[RiskLevel] = []

    for p in procs:
        rows.append(
            [
                str(p.pid),
                _truncate(p.user, 12),
                _truncate(p.matched_signature, 30),
                _truncate(p.cmdline, 46),
                f"{p.risk_level.value} ({p.risk_score})",
            ]
        )
        raw_risk_levels.append(p.risk_level)

    return _draw_box_table(headers, rows, ansi, risk_col_idx=4, risk_levels=raw_risk_levels)


def _format_server_details(srv: MCPServerConfig, ansi: Ansi) -> list[str]:
    lines: list[str] = []
    badge = ansi.risk_badge(srv.risk_level, srv.risk_score)
    lines.append(f"  [{badge}] {ansi.bold(srv.name)} ({srv.client})")
    lines.append(f"    Source:    {srv.source_path}")
    lines.append(f"    Transport: {srv.transport}")
    lines.append(f"    Command:   {redact_inline_secrets(srv.full_command) or '(none)'}")
    if srv.env:
        env_preview = ", ".join(f"{k}={v}" for k, v in srv.redacted_env.items())
        lines.append(f"    Env Vars:  {env_preview}")
    if srv.always_allow:
        lines.append(f"    AutoAllow: {', '.join(srv.always_allow)}")
    if not srv.findings:
        lines.append(f"    Findings:  {ansi.green('None (0 pts)')}")
    else:
        lines.append("    Findings:")
        for f in sorted(srv.findings, key=lambda x: x.points, reverse=True):
            lines.append(
                f"      * [{f.rule_id}] (+{f.points} pts) {ansi.bold(f.title)} [{f.category.value}]"
            )
            lines.append(f"        Detail:      {redact_inline_secrets(f.detail)}")
            lines.append(f"        Remediation: {ansi.cyan(f.remediation)}")
    return lines


def _draw_box_table(
    headers: list[str],
    rows: list[list[str]],
    ansi: Ansi,
    risk_col_idx: int | None = None,
    risk_levels: list[RiskLevel] | None = None,
) -> str:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            if len(val) > col_widths[idx]:
                col_widths[idx] = len(val)

    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header_cells = [ansi.bold(headers[i].ljust(col_widths[i])) for i in range(len(headers))]
    header_line = "| " + " | ".join(header_cells) + " |"

    lines = [sep, header_line, sep]
    for r_idx, row in enumerate(rows):
        formatted_cells: list[str] = []
        for c_idx, cell in enumerate(row):
            padded = cell.ljust(col_widths[c_idx])
            if risk_col_idx == c_idx and risk_levels is not None:
                lvl = risk_levels[r_idx]
                if lvl == RiskLevel.CRITICAL:
                    padded = ansi.bright_red(padded)
                elif lvl == RiskLevel.HIGH:
                    padded = ansi.red(padded)
                elif lvl == RiskLevel.MEDIUM:
                    padded = ansi.yellow(padded)
                else:
                    padded = ansi.green(padded)
            formatted_cells.append(padded)
        lines.append("| " + " | ".join(formatted_cells) + " |")
    lines.append(sep)
    return "\n".join(lines)


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
