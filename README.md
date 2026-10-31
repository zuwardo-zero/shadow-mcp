# Shadow MCP

Shadow MCP is a lightweight, offline-first command-line tool that discovers AI agents and Model Context Protocol (MCP) servers configured or running on a machine, builds a complete inventory, and assigns practical security risk scores.

Developers and engineers are rapidly connecting AI coding assistants (Claude Desktop, Cursor, VS Code, Windsurf, Cline, Roo Code, Continue, and Zed) to local and remote systems through Model Context Protocol (MCP) servers. Because MCP configurations live in scattered dot files and application support directories, security teams and workstation owners do not have enough visibility into what tools an AI agent can invoke.

In practice, many local MCP setups introduce severe security exposure:
* Servers running with `sudo` or mounting `/var/run/docker.sock` inside privileged containers.
* Filesystem servers granted read and write access to `/` or the entire user home directory.
* Plaintext API keys, GitHub tokens, and production database connection strings hardcoded in JSON files.
* Packages executed directly from npm or PyPI using mutable `@latest` tags without version pinning.
* Remote HTTP/SSE endpoints running over cleartext HTTP or with authentication bypass parameters enabled.
* Autonomous execution (`alwaysAllow` or `--dangerously-skip-permissions`) removing human approval gates.

Shadow MCP solves this problem by scanning standard client paths, project workspaces, and active OS processes in under a second with zero external network calls and zero third-party runtime dependencies.

## Features

* **Multi-Client Config Discovery**: Automatically inspects standard configuration paths across Linux, macOS, and Windows for Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Roo Code, Continue, Zed, and workspace `.mcp.json` files.
* **JSON and JSONC Support**: Parses standard JSON as well as JSON with comments (`//` and `/* */`) and trailing commas used by VS Code and Cline configurations.
* **Live Process Detection**: Enumerates active OS processes (`ps` on Linux/macOS, `tasklist` on Windows) to identify running MCP servers, local LLM runners, and autonomous CLI agents.
* **Static Risk Scoring Engine**: Evaluates every discovered server and process across six security domains, producing a 0 to 100 risk score, a severity level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and remediation guidance.
* **Automatic Secret Redaction**: Detects live credential formats (OpenAI, Anthropic, GitHub, Slack, AWS, Stripe, private keys, and database URIs) and masks secret values in terminal and exported reports.
* **Flexible Output Formats**: Supports formatted terminal tables, executive summaries (`--summary`), structured JSON (`--json`), and structured YAML (`--yaml`), plus CI/CD exit code gating (`--fail-on`).
* **Strictly Offline & Zero Dependencies**: Built entirely on the Python 3.10+ standard library. No telemetry and no network requests.

## Installation

Clone the repository and install in editable or standard mode:

```bash
git clone https://github.com/zuwardo-zero/shadow-mcp.git
cd shadow-mcp
pip install -e .
```

Because Shadow MCP uses only the Python standard library, you can also run it directly from source without installing any packages:

```bash
PYTHONPATH=src python3 -m shadow_mcp
```

## Usage Examples

Run a default scan across your user profile, current workspace, and running processes:

```bash
shadow-mcp
```

Scan specific directories or configuration files (for example, the bundled demo configurations):

```bash
shadow-mcp scan --no-home --no-processes --path examples
```

### Sample Terminal Output

```text
Shadow MCP - AI Agent & MCP Server Risk Scanner
Host: workstation-01 (Linux 6.8.0) | Scanned 1 paths | Found 3 config file(s)

Configured MCP Servers (8)
+-------------------------+--------------------+-----------+--------------------------------------+----------------+----------------------------------------------+
| SERVER                  | CLIENT             | TRANSPORT | COMMAND / ENDPOINT                   | RISK           | TOP JUSTIFICATION                            |
+-------------------------+--------------------+-----------+--------------------------------------+----------------+----------------------------------------------+
| privileged-docker-shell | Cline (Workspace)  | stdio     | sudo docker run --rm --privileged... | CRITICAL (100) | MCP server executed with elevated root/ad... |
| remote-unencrypted-api  | Cursor             | sse       | http://192.168.1.50:8080/mcp/sse?... | CRITICAL (85)  | Authentication bypass parameter in MCP en... |
| postgres-prod           | Cursor             | stdio     | uvx mcp-server-postgres==0.4.1       | HIGH (60)      | Hardcoded Database Connection URI with Pa... |
| filesystem-root         | Claude Desktop ... | stdio     | npx -y @modelcontextprotocol/serv... | HIGH (60)      | Filesystem MCP server mounted on broad or... |
| playwright-browser      | Cursor             | stdio     | pnpm dlx @playwright/mcp@latest -... | HIGH (50)      | Dangerous sandbox or permission bypass fl... |
| github-integration      | Claude Desktop ... | stdio     | npx -y @modelcontextprotocol/serv... | MEDIUM (38)    | Hardcoded GitHub Token in plaintext config   |
| safe-docs-reader        | Cline (Workspace)  | stdio     | npx -y @modelcontextprotocol/serv... | LOW (10)       | Scoped filesystem access capability enabled  |
| memory-local            | Claude Desktop ... | stdio     | npx -y @modelcontextprotocol/serv... | LOW (0)        | No high-risk patterns detected               |
+-------------------------+--------------------+-----------+--------------------------------------+----------------+----------------------------------------------+

Risk Justifications (run with --verbose for remediation details)
  - privileged-docker-shell [CRITICAL (100)]: Unrestricted shell or command execution MCP server (+35); Package explicitly pinned to mutable 'latest' tag (+10); Hardcoded OpenAI API Key in plaintext config (+30); MCP server executed with elevated root/admin privileges (+40); Containerized MCP server runs with --privileged flag (+40); Container runtime socket mounted inside MCP server container (+40); Broad autonomous tool execution enabled (alwaysAllow) (+25); Unpinned package combined with privileged or unrestricted host capability (+15)
  - remote-unencrypted-api [CRITICAL (85)]: Authentication bypass parameter in MCP endpoint URL (+35); Unencrypted HTTP/WS connection to remote MCP endpoint (+25); Remote/HTTP MCP endpoint configured without authentication headers (+25)
  - postgres-prod [HIGH (60)]: Direct database query/mutation capability (+20); Hardcoded Database Connection URI with Password in plaintext config (+30); High-impact capability combined with autonomous execution or hardcoded credentials (+10)
  - filesystem-root [HIGH (60)]: Filesystem MCP server mounted on broad or sensitive root path (+35); Package explicitly pinned to mutable 'latest' tag (+10); Unpinned package combined with privileged or unrestricted host capability (+15)
  - playwright-browser [HIGH (50)]: Browser automation or external network fetch capability (+15); Package explicitly pinned to mutable 'latest' tag (+10); Dangerous sandbox or permission bypass flag in arguments (+25)
  - github-integration [MEDIUM (38)]: Dynamic package runner executes unpinned package (+8); Hardcoded GitHub Token in plaintext config (+30)
  - safe-docs-reader [LOW (10)]: Scoped filesystem access capability enabled (+10)

Running AI Agents & MCP Processes (0)
  No active AI agent or MCP server processes detected.

Summary: 8 server(s), 0 process(es) | 2 Critical, 3 High, 1 Medium, 2 Low
```

### Executive Summary Output (`--summary`)

```bash
shadow-mcp scan --path examples --summary
```

```text
SHADOW MCP - EXECUTIVE SECURITY SUMMARY
========================================================
Host:               workstation-01 (Linux 6.8.0)
Scan Timestamp:     2026-10-31T21:47:37Z
Locations Checked:  1
Config Files Found: 3
MCP Servers Found:  8
Active Processes:   0
Overall Posture:    CRITICAL
--------------------------------------------------------
Risk Breakdown:     CRITICAL: 2 | HIGH: 3 | MEDIUM: 1 | LOW: 2

Priority Findings:
  * [CRITICAL (100)] privileged-docker-shell (Cline) -> Unrestricted shell or command execution MCP server
  * [CRITICAL (85)] remote-unencrypted-api (Cursor) -> Authentication bypass parameter in MCP endpoint URL
  * [HIGH (60)] filesystem-root (Claude Desktop) -> Filesystem MCP server mounted on broad or sensitive root path
  * [HIGH (60)] postgres-prod (Cursor) -> Direct database query/mutation capability
  * [HIGH (50)] playwright-browser (Cursor) -> Browser automation or external network fetch capability
```

### Verbose Remediation Output and Structured Exports

```bash
# Detailed findings with rule IDs, redacted env vars, and remediation advice
shadow-mcp scan --path examples --verbose

# Export as JSON or YAML for SIEM / compliance pipelines
shadow-mcp scan --json > mcp_inventory.json
shadow-mcp scan --yaml > mcp_inventory.yaml

# Filter by minimum risk level and fail CI pipeline if HIGH or CRITICAL servers exist
shadow-mcp scan --min-risk medium --fail-on high
```

## Risk Scoring Methodology

Each discovered MCP server or running process starts with a score of `0`. Static analysis rules evaluate the configuration across six security categories plus compound risk escalations. Standalone use of `npx`, `uvx`, or `@latest` is weighted lightly so legitimate setups remain `LOW` unless paired with high-impact capabilities, authentication bypasses, or hardcoded secrets. The total score is capped at `100` and mapped to four risk tiers:

| Risk Level | Score Range | Interpretation |
| :--- | :--- | :--- |
| **CRITICAL** | `75 - 100` | Dangerous multi-factor combinations such as `sudo` + shell execution, privileged containers mounting `docker.sock`, or unauthenticated cleartext remote endpoints with auth bypass flags. |
| **HIGH** | `50 - 74` | Serious exposure such as root filesystem mounts (`/`), database access paired with hardcoded production credentials, or browser automation running with `--no-sandbox`. |
| **MEDIUM** | `25 - 49` | Moderate risk such as a hardcoded API token on a standard integration or unpinned packages combined with external network tools. |
| **LOW** | `0 - 24` | Scoped, least-privilege servers using runtime secret references (`${VAR}`), or standard `npx`/`@latest` runners without high-risk capabilities. |

### Rule Categories and Weights

1. **High-Privilege Execution Context (`MCP-PRIV-*`)**:
   * `sudo` / `doas` / `pkexec` / `runas` invocation (`+40`)
   * Docker/Podman `--privileged` flag (`+40`) or mounted `docker.sock`/`podman.sock` (`+40`)
   * Container `--network=host` namespace sharing (`+20`)
2. **Overly Permissive Tools & Capabilities (`MCP-TOOL-*`)**:
   * Shell or OS command execution servers (`+35`)
   * Filesystem servers mounted on `/`, `/etc`, `/home/<user>`, `C:\`, or `~/.ssh` (`+35`)
   * Scoped project filesystem access (`+10`)
   * Browser automation or external URL fetch capabilities (`+15`)
   * Direct database query capabilities (`+20`)
3. **Missing Authentication / Open Endpoints (`MCP-AUTH-*`)**:
   * Explicit auth bypass flags in endpoint URLs such as `overrideAccess=true` (`+35`)
   * Binding to `0.0.0.0` (`+30`)
   * Unencrypted `http://` or `ws://` remote endpoints (`+25`)
   * Missing authentication headers/tokens on HTTP/SSE endpoints (`+15` local, `+25` remote)
4. **Sensitive Environment Variables & Secrets (`MCP-ENV-*`)**:
   * High-confidence live credentials (OpenAI `sk-`, Anthropic `sk-ant-`, GitHub `ghp_`, GitLab `glpat-`, HuggingFace `hf_`, AWS `AKIA`, Slack `xoxb-`, JWTs, private keys, and database URIs with passwords) (`+30`)
   * Generic hardcoded secret environment variables (`+20`)
   * Secrets passed directly in command-line arguments visible in `ps` (`+30`)
5. **Known Risky Patterns & Compound Escalations (`MCP-PAT-*` / `MCP-COMP-*`)**:
   * Remote script piping (`curl ... | sh` or `iwr ... | iex`) (`+45`)
   * Broad `alwaysAllow` / `autoApprove` tool lists (`+25` for 5+ tools or `*`, `+12` for 1-4 tools)
   * Sandbox or permission bypass flags (`--dangerously-skip-permissions`, `--no-sandbox`) (`+25`)
   * Inline shell wrappers (`sh -c`, `cmd /c`, `powershell -Command`) (`+15`)
   * Compound risk: unpinned package paired with privileged/root/shell capability (`+15`), or high-impact tool paired with autonomous execution or hardcoded credentials (`+10`)
6. **Unpinned or Mutable Package Versions (`MCP-PKG-*`)**:
   * Explicit `@latest` or `:latest` tag (`+10`)
   * Dynamic runner (`npx`, `uvx`, `pnpm dlx`, `bunx`) executing an unpinned package (`+8`)

## Architecture Notes

Shadow MCP uses a clean `src/` layout divided into four single-responsibility modules:

```text
shadow-mcp/
├── pyproject.toml
├── README.md
├── examples/
│   ├── claude_desktop_config.json
│   ├── cline_mcp_settings.json
│   └── cursor_mcp.json
├── src/
│   └── shadow_mcp/
│       ├── __init__.py
│       ├── __main__.py
│       ├── models.py      # Dataclasses for servers, processes, findings, and secret redaction
│       ├── discovery.py   # Cross-platform path resolution, JSON/JSONC parser, OS process scanner
│       ├── analyzer.py    # Static analysis rules and additive risk scoring engine
│       ├── reporter.py    # ANSI table renderer, executive summary, JSON and YAML serializers
│       └── cli.py         # Argparse CLI entrypoint and exit code handling
└── tests/
    └── test_shadow_mcp.py # Unit test suite covering discovery, scoring, redaction, and CLI
```

Key design decisions:
* **Zero Runtime Dependencies**: Security auditing tools should be easy to run on locked-down hosts or inside CI runners without pulling dozens of transitive packages. Everything from JSONC comment stripping to YAML serialization and ASCII box tables is implemented with the Python standard library.
* **Safe by Default**: Discovered secrets are never printed in cleartext. `MCPServerConfig.redacted_env` masks sensitive values while preserving environment variable references like `${GITHUB_TOKEN}` so analysts can distinguish hardcoded secrets from safe runtime injection.
* **Graceful Degradation**: Missing directories, permission errors, and malformed JSON files never crash the scan. Unreadable files are recorded as structured `ConfigParseWarning` entries.

## Running Tests

Run the test suite using `unittest` or `pytest`:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Limitations

* **Static Configuration Analysis**: Shadow MCP inspects declared commands, arguments, environment blocks, and URLs in configuration files. It does not dynamically start MCP servers or send JSON-RPC `tools/list` requests over `stdio`, as launching untrusted servers during a security audit could trigger side effects.
* **Process Visibility**: Unprivileged users on hardened Linux systems (`hidepid=2`) may only see processes owned by their own UID unless the scan is run with elevated permissions.
* **Custom Wrapper Scripts**: If an MCP configuration invokes a custom local shell script (`./run_server.sh`), Shadow MCP flags the script execution pattern if applicable but does not recursively parse the contents of external scripts.