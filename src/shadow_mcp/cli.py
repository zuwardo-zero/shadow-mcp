"""Command-line interface for Shadow MCP."""

from __future__ import annotations

import argparse
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from shadow_mcp import __version__
from shadow_mcp.analyzer import evaluate_process_risk, evaluate_server_risk
from shadow_mcp.discovery import discover_configs, discover_running_processes
from shadow_mcp.models import RiskLevel, ScanReport
from shadow_mcp.reporter import (
    render_json,
    render_summary,
    render_table_report,
    render_yaml,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser supporting both default scan and explicit 'scan' subcommand."""
    parser = argparse.ArgumentParser(
        prog="shadow-mcp",
        description=(
            "Offline-first CLI scanner that discovers local AI agents and "
            "Model Context Protocol (MCP) servers and assigns practical security risk scores."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"shadow-mcp {__version__}",
    )

    _add_scan_arguments(parser)
    return parser


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "command",
        nargs="?",
        default="scan",
        choices=["scan"],
        help="Subcommand to execute (default: scan).",
    )
    parser.add_argument(
        "-p",
        "--path",
        action="append",
        default=[],
        metavar="PATH",
        help="Additional file or directory path to scan for MCP configs (can be repeated).",
    )
    parser.add_argument(
        "--no-home",
        action="store_true",
        help="Skip scanning default user home AI client configuration paths.",
    )
    parser.add_argument(
        "--no-processes",
        action="store_true",
        help="Skip scanning running OS processes.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        metavar="N",
        help="Maximum directory recursion depth when searching workspaces (default: 3).",
    )

    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Emit full scan results as structured JSON.",
    )
    output_group.add_argument(
        "--yaml",
        action="store_true",
        help="Emit full scan results as structured YAML.",
    )
    output_group.add_argument(
        "--summary",
        action="store_true",
        help="Emit a concise human-readable executive summary.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Include full finding descriptions, remediation steps, and raw config details.",
    )
    parser.add_argument(
        "--min-risk",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Filter displayed servers and processes by minimum risk level (default: low).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 1 if any discovered item meets or exceeds this risk level (useful for CI/CD).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output.",
    )


_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def run_scan(args: argparse.Namespace) -> ScanReport:
    """Execute config discovery, process discovery, and risk scoring."""
    extra_paths = [Path(p) for p in args.path]
    include_home = not args.no_home

    # If user explicitly supplied --path and --no-home, only scan those paths
    workspace_dirs: list[Path] = []
    if include_home and not extra_paths:
        workspace_dirs.append(Path.cwd())

    servers, config_files, warnings, locations_checked = discover_configs(
        extra_paths=extra_paths,
        workspace_dirs=workspace_dirs,
        include_home=include_home,
        max_depth=args.max_depth,
    )

    for srv in servers:
        evaluate_server_risk(srv)

    processes = []
    if not args.no_processes:
        processes = discover_running_processes()
        for proc in processes:
            evaluate_process_risk(proc)

    min_level = RiskLevel(args.min_risk.upper())
    min_rank = _RISK_ORDER[min_level]

    filtered_servers = [s for s in servers if _RISK_ORDER[s.risk_level] >= min_rank]
    filtered_procs = [p for p in processes if _RISK_ORDER[p.risk_level] >= min_rank]

    return ScanReport(
        hostname=socket.gethostname(),
        platform_name=f"{platform.system()} {platform.release()}",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        scanned_locations=locations_checked,
        config_files_found=config_files,
        servers=filtered_servers,
        processes=filtered_procs,
        warnings=warnings,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning POSIX exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    report = run_scan(args)
    color_override = False if args.no_color else None

    if args.json:
        print(render_json(report, verbose=args.verbose))
    elif args.yaml:
        print(render_yaml(report, verbose=args.verbose))
    elif args.summary:
        print(render_summary(report, color=color_override))
    else:
        print(render_table_report(report, verbose=args.verbose, color=color_override))

    if args.fail_on:
        threshold = RiskLevel(args.fail_on.upper())
        if _RISK_ORDER[report.highest_risk_level] >= _RISK_ORDER[threshold]:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
