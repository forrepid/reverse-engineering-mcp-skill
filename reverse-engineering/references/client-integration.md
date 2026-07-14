# MCP client integration

Research date: 2026-07-14. Read this reference before generating or merging
client configurations. Client schemas change independently; recheck the linked
primary documentation before publishing a release.

## Contents

1. Server model
2. Generate configurations
3. Environment contract
4. Client locations and verification
5. Merge rules
6. Security rules
7. Primary documentation

## Server model

The project can expose three independent stdio servers:

- `reverse-engineering-companion`: portable file analysis and plan tools from
  `scripts/re_mcp_server.py`. It exposes no apply/write/debug/eval tool.
- `ida-pro-idalib`: upstream `idalib-mcp` for live IDA databases. It requires
  IDA/idapro activation and an explicit database on analysis calls.
- `ghidra-mcp`: optional upstream `bridge_mcp_ghidra.py`; it forwards MCP calls
  to the loopback Ghidra plugin endpoint and requires an active Program.

The config renderer includes the companion always and includes idalib only
when `--idalib-mcp` identifies an existing executable with the exact basename
`idalib-mcp` or `idalib-mcp.exe`. Ghidra is included only when
`--ghidra-bridge` identifies the exact upstream bridge basename; its
`--ghidra-server` URL must be loopback.

## Generate configurations

Run from `reverse-engineering/`:

~~~powershell
python scripts/re_cli.py client-profiles
python scripts/re_cli.py client-configs `
  --output-dir artifacts/client-configs `
  --python "C:\Path\To\Python\python.exe" `
  --idalib-mcp "C:\Path\To\Scripts\idalib-mcp.exe" `
  --ghidra-bridge "C:\Path\To\GhidraMCP\bridge_mcp_ghidra.py" `
  --ghidra-server "http://127.0.0.1:8080/" `
  --env-file .env
~~~

The command emits eight client fragments and `manifest.json`. It never edits a
client's real settings. Existing generated files fail closed unless `--force`
is supplied. Validate the companion separately:

~~~powershell
& "C:\Path\To\Python\python.exe" scripts/re_mcp_server.py --check
~~~

Generate only selected clients with `--clients codex claude-code zed`. Omit
`--idalib-mcp` for a portable companion-only pack.

## Environment contract

No variable is required and the companion uses no API key or secret. Generated
configs now include nine explicit, validated values under each companion stdio
`env` field: mode, log level, maximum file/region/scan sizes, optional allowed
sample roots, provider registry, provider timeout, and provider-output limit.
The manifest records the same non-secret values under
`companion_environment`.

Start from `.env.example`, validate with `env-check`, then pass `--env-file` to
the renderer. Use repeated `--env NAME=VALUE` arguments for reviewed overrides.
The renderer rejects unknown names and does not auto-load `.env`. Read
`environment-variables.md` for all defaults, limits, PowerShell examples, and
client-specific env syntax.

## Client locations and verification

### OpenAI Codex CLI, desktop, and IDE extension

- Format: TOML tables under `[mcp_servers.<name>]`.
- User target: `~/.codex/config.toml`.
- Project target: `.codex/config.toml` in a trusted project.
- Merge `codex.config.toml`; do not replace unrelated existing tables.
- Alternative companion command:

~~~text
codex mcp add reverse-engineering-companion -- <python> <absolute>/re_mcp_server.py
codex mcp add ida-pro-idalib -- <idalib-mcp.exe> --stdio --max-workers 4
codex mcp add ghidra-mcp -- <python> <absolute>/bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
codex mcp list
~~~

The Codex CLI, desktop app, and IDE extension share this configuration. Restart
the app/extension after editing and use `/mcp` or the MCP server settings page.

### Claude Code

- Format: top-level `mcpServers` in JSON.
- Project target: `.mcp.json`; project servers require trust approval.
- Local/user configuration is normally managed by `claude mcp add` and stored
  in `~/.claude.json`.
- Merge `claude-code.mcp.json`, then run `claude mcp list` and `/mcp`.
- CLI equivalent:

~~~text
claude mcp add --transport stdio --scope project reverse-engineering-companion -- <python> <absolute>/re_mcp_server.py
~~~

Keep the `--` separator so server arguments are not parsed as Claude options.

### Qwen Code

- Format: top-level `mcpServers` in JSON.
- User target: `~/.qwen/settings.json`.
- Project target: `.qwen/settings.json`.
- Merge `qwen-code.settings.json`; retain `trust: false` so calls can prompt.
- Restart the project session and use `/mcp` to review discovery and tools.

The generated entry sets finite discovery/tool timeouts. Project-level local
commands require approval in current Qwen Code releases.

### Visual Studio Code

- Format: top-level `servers`, with local entries using `type: "stdio"`.
- Workspace target: `.vscode/mcp.json`.
- User target: run `MCP: Open User Configuration` from the Command Palette.
- Merge `vscode.mcp.json`; use `MCP: List Servers` to start, stop, inspect logs,
  or reset trust.

Do not enable MCP sandbox claims on Windows: current VS Code documentation
states that its MCP sandbox feature is not available there.

### Microsoft Visual Studio

- Prerequisite: Visual Studio 2022 17.14 with current servicing, or a newer
  supported Visual Studio release with GitHub Copilot Agent mode.
- Format: top-level `servers` in `.mcp.json`/`mcp.json`.
- User target: `%USERPROFILE%\.mcp.json`.
- Solution targets include `.mcp.json` and `.vs\mcp.json`.
- Merge `visual-studio.mcp.json`, save it, select Agent mode, then review and
  enable the server tools in Copilot Chat.

Visual Studio also discovers `.vscode\mcp.json`, but keep one authoritative
solution entry to avoid precedence confusion.

### Zed

- Format: top-level `context_servers` in Zed `settings.json`.
- Open `Settings -> AI -> MCP Servers`, choose `Add Local Server`, or open the
  settings file and merge `zed.settings.json`.
- Confirm the server indicator is green. Keep
  `agent.tool_permissions.default` at `confirm` unless every tool is reviewed.

Zed can forward configured MCP servers to external ACP agents, but terminal
agents may still read their own native MCP files.

### Google Antigravity IDE and CLI

- Format: top-level `mcpServers` in `mcp_config.json`.
- User target: `~/.gemini/config/mcp_config.json`.
- Workspace target: `.agents/mcp_config.json`.
- In the IDE use `MCP Servers -> Manage MCP Servers -> View raw config`; in the
  CLI use `/mcp` to review state and logs.
- Merge `antigravity.mcp_config.json`. Remote servers use `serverUrl`, but this
  project uses local stdio `command`/`args`.

### Kimi Code CLI

- Format: top-level `mcpServers` in JSON.
- User target: `~/.kimi-code/mcp.json` or `$KIMI_CODE_HOME/mcp.json`.
- Project target: `.kimi-code/mcp.json`.
- Merge `kimi.mcp.json`; run `/mcp-config` to review and `/mcp` for status.
- Keep `enabledTools`/`disabledTools` and normal approval rules narrowly scoped;
  do not use YOLO mode for reverse-engineering tools.

## Merge rules

1. Back up the existing client configuration.
2. Parse both files with the client's editor/schema support.
3. Merge only the server entries; never discard unrelated settings.
4. Review every absolute executable/script path and optional environment value.
5. Keep companion, idalib, and Ghidra bridge as separate server identities.
6. Approve the repository/client configuration before the first process start.
7. Verify tool discovery and confirm companion reports `writes_exposed: false`.
8. For idalib, open/select the intended database and wait for auto-analysis.

## Security rules

- A project MCP file can execute a local command at startup. Treat it as code.
- The companion needs no credential. Never add API keys or IDA license data to
  its generated `env` object.
- Do not commit machine-specific paths, credentials, IDA licenses, IDB files,
  proprietary samples, or API tokens.
- Keep client trust prompts and per-tool approval enabled.
- Do not auto-approve unknown tools merely because the server connected.
- Do not expose this stdio companion through an unauthenticated network bridge.
- Re-run config generation after moving Python, the project, or idalib-mcp.
- Generated config means “syntactically rendered”, not “installed or trusted”.

## Primary documentation

- [Codex MCP](https://developers.openai.com/codex/mcp/)
- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Qwen Code MCP](https://qwenlm.github.io/qwen-code-docs/en/users/features/mcp/)
- [VS Code MCP](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
- [Visual Studio MCP](https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio)
- [Zed MCP](https://zed.dev/docs/ai/mcp)
- [Google Antigravity MCP](https://antigravity.google/docs/mcp)
- [Kimi Code MCP](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/mcp.html)
