"""Unit tests for Shadow MCP discovery, risk scoring, and output formatting."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shadow_mcp.analyzer import evaluate_process_risk, evaluate_server_risk
from shadow_mcp.cli import main
from shadow_mcp.discovery import (
    _parse_ps_output,
    _parse_tasklist_output,
    _parse_windows_cim_json,
    discover_configs,
    discover_running_processes,
    infer_client_from_path,
    parse_mcp_config_file,
    strip_jsonc_comments,
)
from shadow_mcp.models import (
    DiscoveredProcess,
    FindingCategory,
    MCPServerConfig,
    RiskLevel,
    ScanReport,
    redact_env_value,
    redact_inline_secrets,
)
from shadow_mcp.reporter import (
    render_json,
    render_summary,
    render_table_report,
    render_yaml,
)


def _fake_openai_key() -> str:
    return "sk-proj-" + "1234567890abcdefghijklmnopqrstuvwxyzABCDEF"


def _fake_github_token() -> str:
    return "ghp_" + "1234567890abcdefghijklmnopqrstuvwx"


def _fake_gitlab_token() -> str:
    return "glpat-" + "1234567890abcdefghijkl"


class TestDiscoveryAndParsing(unittest.TestCase):
    """Verify config file parsing across standard MCP schemas, JSONC, and edge cases."""

    def test_strip_jsonc_comments_and_trailing_commas(self) -> None:
        raw_jsonc = """
        \ufeff{
          // Single-line comment with http://example.com inside string test
          "mcpServers": {
            "demo": {
              "command": "npx", /* inline block comment */
              "args": ["http://localhost:8000",],
            },
          },
        }
        """
        cleaned = strip_jsonc_comments(raw_jsonc)
        parsed = json.loads(cleaned)
        self.assertIn("mcpServers", parsed)
        self.assertEqual(parsed["mcpServers"]["demo"]["args"], ["http://localhost:8000"])
        self.assertTrue(strip_jsonc_comments("{\n/* unterminated comment").startswith("{"))

    def test_empty_and_whitespace_configs_handled_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_path = Path(tmpdir) / "mcp.json"
            empty_path.write_text("   \n\t  ", encoding="utf-8")
            servers, warning = parse_mcp_config_file(empty_path)
            self.assertEqual(servers, [])
            self.assertIsNone(warning)

            comments_only = Path(tmpdir) / "comments.json"
            comments_only.write_text("// only a comment\n/* nothing else */", encoding="utf-8")
            servers2, warning2 = parse_mcp_config_file(comments_only)
            self.assertEqual(servers2, [])
            self.assertIsNone(warning2)

    def test_permission_error_and_missing_files_degrade_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_file = Path(tmpdir) / "does_not_exist.json"
            servers, files, warnings, _ = discover_configs(
                extra_paths=[missing_file],
                include_home=False,
            )
            self.assertEqual(servers, [])
            self.assertEqual(files, [])
            self.assertEqual(warnings, [])

            if os.name == "posix" and os.geteuid() != 0:
                locked = Path(tmpdir) / "locked_mcp.json"
                locked.write_text('{"mcpServers": {}}', encoding="utf-8")
                locked.chmod(0o000)
                try:
                    srv_locked, warn_locked = parse_mcp_config_file(locked)
                    self.assertEqual(srv_locked, [])
                    self.assertIsNotNone(warn_locked)
                    assert warn_locked is not None
                    self.assertIn("Permission denied", warn_locked.error)
                finally:
                    locked.chmod(0o600)

    def test_defensive_command_list_and_null_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "mcp.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "array-cmd": {
                                "command": ["npx", "-y"],
                                "args": ["@modelcontextprotocol/server-memory@0.6.2", None],
                                "env": {"EMPTY_VAL": None, "PORT": 8080},
                                "alwaysAllow": None,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            servers, warning = parse_mcp_config_file(cfg_path)
            self.assertIsNone(warning)
            self.assertEqual(len(servers), 1)
            srv = servers[0]
            self.assertEqual(srv.command, "npx")
            self.assertEqual(srv.args, ["-y", "@modelcontextprotocol/server-memory@0.6.2"])
            self.assertEqual(srv.env["EMPTY_VAL"], "")
            self.assertEqual(srv.env["PORT"], "8080")

    def test_windows_path_client_inference(self) -> None:
        win_claude = r"C:\Users\Alice\AppData\Roaming\Claude\claude_desktop_config.json"
        win_cline = r"C:\Users\Alice\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json"
        win_zed = r"C:\Users\Alice\AppData\Roaming\Zed\settings.json"
        self.assertEqual(infer_client_from_path(win_claude), "Claude Desktop")
        self.assertEqual(infer_client_from_path(win_cline), "Cline")
        self.assertEqual(infer_client_from_path(win_zed), "Zed")

    def test_parse_standard_claude_and_cursor_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "claude_desktop_config.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "fs": {
                                "command": "npx",
                                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                                "env": {"API_KEY": "secret123"},
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            servers, warning = parse_mcp_config_file(cfg_path)
            self.assertIsNone(warning)
            self.assertEqual(len(servers), 1)
            srv = servers[0]
            self.assertEqual(srv.name, "fs")
            self.assertEqual(srv.client, "Claude Desktop")
            self.assertEqual(srv.command, "npx")
            self.assertEqual(srv.env["API_KEY"], "secret123")

    def test_parse_vscode_and_zed_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vscode_path = Path(tmpdir) / "settings.json"
            vscode_path.write_text(
                json.dumps(
                    {
                        "mcp": {
                            "servers": {
                                "vscode-git": {
                                    "command": "uvx",
                                    "args": ["mcp-server-git==1.0.0"],
                                }
                            }
                        },
                        "context_servers": {
                            "zed-postgres": {
                                "command": {
                                    "path": "npx",
                                    "args": ["@modelcontextprotocol/server-postgres@0.6.2"],
                                    "env": {"PG_URL": "${PG_URL}"},
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            servers, warning = parse_mcp_config_file(vscode_path, "VS Code")
            self.assertIsNone(warning)
            self.assertEqual(len(servers), 2)
            names = {s.name for s in servers}
            self.assertEqual(names, {"vscode-git", "zed-postgres"})

    def test_malformed_config_degrades_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = Path(tmpdir) / "mcp.json"
            bad_path.write_text("{broken json", encoding="utf-8")
            servers, warning = parse_mcp_config_file(bad_path)
            self.assertEqual(servers, [])
            self.assertIsNotNone(warning)
            assert warning is not None
            self.assertIn("Failed to parse JSON", warning.error)

    def test_discover_configs_on_example_directory(self) -> None:
        examples_dir = Path(__file__).resolve().parent.parent / "examples"
        servers, files, warnings, checked = discover_configs(
            extra_paths=[examples_dir],
            include_home=False,
        )
        self.assertGreaterEqual(len(files), 3)
        self.assertEqual(len(warnings), 0)
        self.assertEqual(len(servers), 8)
        self.assertGreater(checked, 0)

        by_name = {s.name: evaluate_server_risk(s) for s in servers}
        self.assertEqual(by_name["privileged-docker-shell"].risk_level, RiskLevel.CRITICAL)
        self.assertEqual(by_name["remote-unencrypted-api"].risk_level, RiskLevel.CRITICAL)
        self.assertEqual(by_name["filesystem-root"].risk_level, RiskLevel.HIGH)
        self.assertEqual(by_name["github-integration"].risk_level, RiskLevel.MEDIUM)
        self.assertEqual(by_name["postgres-prod"].risk_level, RiskLevel.HIGH)
        self.assertEqual(by_name["playwright-browser"].risk_level, RiskLevel.HIGH)
        self.assertEqual(by_name["safe-docs-reader"].risk_level, RiskLevel.LOW)
        self.assertEqual(by_name["memory-local"].risk_level, RiskLevel.LOW)


class TestRiskScoringEngine(unittest.TestCase):
    """Verify risk scoring rules, categories, and severity thresholds."""

    def test_low_risk_pinned_server_with_env_reference(self) -> None:
        srv = MCPServerConfig(
            name="memory-safe",
            client="Claude Desktop",
            source_path="/tmp/claude_desktop_config.json",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-memory@0.6.2"],
            env={"OPENAI_API_KEY": "${OPENAI_API_KEY}"},
        )
        evaluate_server_risk(srv)
        self.assertEqual(srv.risk_score, 0)
        self.assertEqual(srv.risk_level, RiskLevel.LOW)
        self.assertEqual(len(srv.findings), 0)

    def test_false_positive_reduction_for_legitimate_npx_and_latest(self) -> None:
        srv_latest = MCPServerConfig(
            name="memory-latest",
            client="Claude Desktop",
            source_path="/tmp/claude.json",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-memory@latest"],
        )
        evaluate_server_risk(srv_latest)
        self.assertEqual(srv_latest.risk_level, RiskLevel.LOW)
        self.assertEqual(srv_latest.risk_score, 10)

        srv_scoped_fs = MCPServerConfig(
            name="scoped-fs-unpinned",
            client="Cursor",
            source_path="/tmp/mcp.json",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/home/dev/project/src"],
        )
        evaluate_server_risk(srv_scoped_fs)
        self.assertEqual(srv_scoped_fs.risk_level, RiskLevel.LOW)
        self.assertEqual(srv_scoped_fs.risk_score, 18)

    def test_critical_risk_privileged_shell_with_secrets(self) -> None:
        srv = MCPServerConfig(
            name="root-shell",
            client="Cline",
            source_path="/tmp/cline_mcp_settings.json",
            command="sudo",
            args=[
                "docker",
                "run",
                "--privileged",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "mcp-server-shell@latest",
            ],
            env={"OPENAI_API_KEY": _fake_openai_key()},
            always_allow=["exec", "write", "delete", "net", "admin"],
        )
        evaluate_server_risk(srv)
        self.assertEqual(srv.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(srv.risk_score, 100)
        categories = {f.category for f in srv.findings}
        self.assertIn(FindingCategory.HIGH_PRIVILEGE, categories)
        self.assertIn(FindingCategory.PERMISSIVE_TOOLS, categories)
        self.assertIn(FindingCategory.SENSITIVE_ENV, categories)
        self.assertIn(FindingCategory.RISKY_PATTERN, categories)

    def test_unauthenticated_remote_http_and_auth_override(self) -> None:
        srv = MCPServerConfig(
            name="remote-mcp",
            client="Cursor",
            source_path="/tmp/mcp.json",
            transport="http",
            url="http://192.168.1.25:3000/api/mcp?overrideAccess=true",
        )
        evaluate_server_risk(srv)
        self.assertEqual(srv.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(srv.risk_score, 85)
        rule_ids = {f.rule_id for f in srv.findings}
        self.assertIn("MCP-AUTH-001", rule_ids)
        self.assertIn("MCP-AUTH-003", rule_ids)
        self.assertIn("MCP-AUTH-004", rule_ids)

    def test_filesystem_root_path_and_unpinned_package(self) -> None:
        srv = MCPServerConfig(
            name="fs-root",
            client="Claude Desktop",
            source_path="/tmp/claude.json",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem@latest", "/"],
        )
        evaluate_server_risk(srv)
        self.assertEqual(srv.risk_level, RiskLevel.HIGH)
        self.assertEqual(srv.risk_score, 60)
        rule_ids = {f.rule_id for f in srv.findings}
        self.assertIn("MCP-TOOL-002", rule_ids)
        self.assertIn("MCP-PKG-001", rule_ids)
        self.assertIn("MCP-COMP-001", rule_ids)

    def test_secret_redaction_preserves_safety(self) -> None:
        gh_tok = _fake_github_token()
        gl_tok = _fake_gitlab_token()
        srv = MCPServerConfig(
            name="secret-srv",
            client="Cursor",
            source_path="/tmp/mcp.json",
            command="node",
            args=["server.js", f"--token={gh_tok}"],
            url="http://admin:SuperSecret99@db.example.com:5432/prod",
            headers={"Authorization": f"Bearer {gl_tok}"},
            env={
                "GITHUB_TOKEN": gh_tok,
                "REF_TOKEN": "${MY_ENV_TOKEN}",
                "WIN_REF": "%MY_WIN_SECRET%",
                "DATABASE_URL": "postgresql://postgres:MyDbPass123!@localhost:5432/app",
                "NODE_ENV": "production",
                "LOG_LEVEL": "info",
                "PORT": "3000",
                "SHORT": "abcd",
            },
        )
        redacted = srv.redacted_env
        self.assertEqual(redacted["GITHUB_TOKEN"], "ghp***wx")
        self.assertEqual(redacted["REF_TOKEN"], "${MY_ENV_TOKEN}")
        self.assertEqual(redacted["WIN_REF"], "%MY_WIN_SECRET%")
        self.assertIn("postgresql://postgres:MyD***3!@localhost:5432/app", redacted["DATABASE_URL"])
        self.assertEqual(redacted["NODE_ENV"], "production")
        self.assertEqual(redacted["LOG_LEVEL"], "info")
        self.assertEqual(redacted["PORT"], "3000")
        self.assertEqual(redacted["SHORT"], "***")

        serialized = srv.to_dict()
        self.assertNotIn(gh_tok, json.dumps(serialized))
        self.assertNotIn("SuperSecret99", json.dumps(serialized))
        self.assertNotIn(gl_tok, json.dumps(serialized))
        self.assertIn("Bearer glp***kl", serialized["headers_redacted"]["Authorization"])

        raw_cmd = f"python server.py --api-key {_fake_openai_key()}"
        self.assertNotIn(_fake_openai_key(), redact_inline_secrets(raw_cmd))
        self.assertEqual(redact_env_value("DEBUG", "true"), "true")

    def test_process_detection_and_risk_scoring(self) -> None:
        ps_sample = (
            "  101 root     mcp-server-git  /usr/bin/python3 -m mcp_server_git\n"
            "  202 alice    mcp-server-fs\n"
        )
        parsed_ps = _parse_ps_output(ps_sample)
        self.assertEqual(len(parsed_ps), 2)
        self.assertEqual(parsed_ps[1], (202, "alice", "mcp-server-fs", "mcp-server-fs"))

        cim_sample = json.dumps(
            [
                {
                    "ProcessId": 4412,
                    "Name": "node.exe",
                    "CommandLine": "node.exe C:\\mcp\\custom_mcp_server.js",
                }
            ]
        )
        parsed_cim = _parse_windows_cim_json(cim_sample)
        self.assertEqual(len(parsed_cim), 1)
        self.assertEqual(parsed_cim[0][0], 4412)

        tasklist_sample = '"node.exe","1234","Console","1","25,000 K","Running","WORKSTATION\\alice","0:00:02","npx @modelcontextprotocol/server-memory"\n'
        parsed_tl = _parse_tasklist_output(tasklist_sample)
        self.assertEqual(len(parsed_tl), 1)
        self.assertEqual(parsed_tl[0][0], 1234)

        mock_procs = [
            (1111, "alice", "python3", "python3 -m mcp_server_sqlite --db test.db"),
            (2222, "alice", "mcp-server-fs", "mcp-server-fs"),
            (3333, "root", "docker", "docker run --rm mcp/filesystem /"),
            (4444, "alice", "bash", "bash"),
        ]
        with patch("shadow_mcp.discovery._list_os_processes", return_value=mock_procs):
            found = discover_running_processes()
        self.assertEqual({p.pid for p in found}, {1111, 2222, 3333})

        proc = DiscoveredProcess(
            pid=9999,
            user="root",
            command="claude",
            cmdline="claude --dangerously-skip-permissions --host 0.0.0.0",
            matched_signature="Claude Code CLI Agent",
        )
        evaluate_process_risk(proc)
        self.assertEqual(proc.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(proc.risk_score, 100)


class TestReportersAndCLI(unittest.TestCase):
    """Verify JSON, YAML, summary, and table outputs plus CLI exit codes."""

    def _sample_report(self) -> ScanReport:
        srv = MCPServerConfig(
            name="test-server",
            client="Cursor",
            source_path="/tmp/mcp.json",
            command="npx",
            args=["@playwright/mcp@latest"],
        )
        evaluate_server_risk(srv)
        return ScanReport(
            hostname="test-host",
            platform_name="Linux",
            timestamp="2026-10-31T00:00:00Z",
            scanned_locations=12,
            config_files_found=["/tmp/mcp.json"],
            servers=[srv],
            processes=[],
            warnings=[],
        )

    def test_render_json_and_yaml(self) -> None:
        report = self._sample_report()
        json_out = render_json(report, verbose=True)
        parsed = json.loads(json_out)
        self.assertEqual(parsed["summary"]["total_servers"], 1)
        self.assertEqual(parsed["servers"][0]["risk_level"], "MEDIUM")

        yaml_out = render_yaml(report, verbose=False)
        self.assertIn("hostname: test-host", yaml_out)
        self.assertIn("risk_level: MEDIUM", yaml_out)

    def test_render_summary_and_table(self) -> None:
        report = self._sample_report()
        summary_out = render_summary(report, color=False)
        self.assertIn("SHADOW MCP - EXECUTIVE SECURITY SUMMARY", summary_out)
        self.assertIn("test-server", summary_out)

        table_out = render_table_report(report, verbose=True, color=False)
        self.assertIn("Configured MCP Servers (1)", table_out)
        self.assertIn("MCP-PKG-001", table_out)

    def test_cli_fail_on_exit_code(self) -> None:
        examples_dir = Path(__file__).resolve().parent.parent / "examples"
        rc_fail = main(
            [
                "scan",
                "--no-home",
                "--no-processes",
                "--path",
                str(examples_dir),
                "--fail-on",
                "high",
                "--summary",
                "--no-color",
            ]
        )
        self.assertEqual(rc_fail, 1)


if __name__ == "__main__":
    unittest.main()
