# Ghidra 12.1.2 + GhidraMCP engineering build

Read this reference before building, installing, enabling, or repairing the
pinned Ghidra integration. It is version-specific by design.

## Validated components

- Ghidra `12.1.2 PUBLIC`, build `20260605`.
- Microsoft OpenJDK `21.0.11` (Ghidra 12.1.2 requires Java 21).
- Apache Maven `3.9.12`.
- LaurieWired/GhidraMCP commit
  `27f316f80139e2d5dec882519a1bdf4aa46ac04c`.
- Project patch: `assets/ghidra-mcp/GhidraMCP-12.1.2.patch`.

The published GhidraMCP 1.4 archive was built for Ghidra 11.3.2, so this
project does not install that binary into Ghidra 12.1.2. It rebuilds the pinned
source against the exact 12.1.2 JARs.

## Patch contract

The reviewed patch performs five bounded changes:

1. updates the eight Maven system dependency versions to 12.1.2;
2. updates `extension.properties` to 12.1.2;
3. empties the legacy `Module.manifest` entries rejected by Ghidra 12.1.2;
4. binds the plugin HTTP surface to `127.0.0.1` and requires a per-install
   bearer token on every request;
5. adds `/health` and the classified `ghidra_health` MCP tool; the Python bridge
   forwards `RE_GHIDRA_TOKEN` on GET and POST requests, and `--profile
   `read_only` omits every non-read tool. The opt-in `read_write` profile keeps
   only read plus reviewed rename/comment/type tools; patch, debugger, and
   arbitrary script tools remain absent. The current/default profile preserves
   upstream tool exposure.

Apply it only to the pinned commit:

~~~powershell
git clone https://github.com/LaurieWired/GhidraMCP.git C:\Tools\GhidraMCP
git -C C:\Tools\GhidraMCP checkout 27f316f80139e2d5dec882519a1bdf4aa46ac04c
git -C C:\Tools\GhidraMCP apply --ignore-space-change "<project>\assets\ghidra-mcp\GhidraMCP-12.1.2.patch"
Copy-Item "<project>\assets\ghidra-mcp\bridge_mcp_ghidra.py" `
  "C:\Tools\GhidraMCP\bridge_mcp_ghidra.py" -Force
~~~

## Build and install

The installer refuses a different upstream commit, a different Ghidra version,
a non-empty reviewed manifest, a missing loopback bind, or missing Ghidra JARs.
It runs the Maven HTTP-auth integration test and requires its passing Surefire
report before it returns success. The test binds an ephemeral loopback listener
and verifies missing/wrong bearer credentials get 401 while the correct token
gets 200. The installer never deletes an extension tree.

~~~powershell
& "<project>\scripts\install_ghidra_mcp.ps1" `
  -GhidraHome "C:\Users\beessy\Tools\ghidra_12.1.2_PUBLIC" `
  -Source "C:\Users\beessy\Tools\GhidraMCP" `
  -JavaHome "C:\Program Files\Microsoft\jdk-21.0.11.10-hotspot" `
  -MavenHome "C:\Users\beessy\Tools\apache-maven-3.9.12" `
  -Install
~~~

Generate a cryptographically random token (32+ characters), store it outside
source control, set `RE_GHIDRA_TOKEN` in the Codex/client launch environment,
and pass the same value to the Ghidra JVM as `-Dghidra.mcp.token=...`. The
plugin refuses to start without it. Never put the token in generated MCP config
or repository files. The command prints the effective commit and SHA-256 of the
generated ZIP/JAR.
The installed extension is
`<GhidraHome>\Ghidra\Extensions\GhidraMCP`.

For an isolated authentication smoke test, use a separate copy of the Ghidra
distribution and replace that copy's `Ghidra\Extensions\GhidraMCP` with the
reviewed build. Ghidra rejects duplicate module names if `GhidraMCP` exists in
both the install-wide and per-user extension directories. Launch the copy with
an absolute `-Dapplication.settingsdir=<temporary directory>` and
`-Dghidra.mcp.token=...` in `GHIDRA_GUI_JAVA_OPTIONS`, plus a temporary
`USERPROFILE`, `APPDATA`, and `LOCALAPPDATA`. On this Windows installation the
default user settings layout is `%APPDATA%\ghidra\ghidra_12.1.2_PUBLIC`; setting
`USERPROFILE` alone does not isolate it. Open a new temporary project and a
trusted test Program in CodeBrowser before running the live verifier.

Use the reviewed `assets/ghidra-mcp/bridge_mcp_ghidra.py` with the matching
patched Java extension. Generated MCP configs preserve upstream behavior by
default. To remove mutation tools, use `--host-profile read_only`; config
generation checks the selected bridge's filter and CLI profile implementation.
The health route and all other plugin routes require bearer auth even on
loopback; loopback is not an authentication boundary against local processes.

## One-time CodeBrowser activation

1. Start Ghidra and open or create a project.
2. Open a program in CodeBrowser.
3. Choose `File -> Configure`, locate `GhidraMCPPlugin`, enable it, and save the
   tool configuration.
4. Restart that CodeBrowser tool.
5. Verify the health endpoint through the authenticated MCP bridge;
   unauthenticated direct HTTP requests must receive 401. `program=none` means
   the plugin is alive but no Program is active.

After this one-time tool configuration, the MCP client starts the Python bridge
over stdio. Opening a configured CodeBrowser supplies the local HTTP plugin.

## Codex registration on this workstation

The global Codex configuration has three separate enabled servers:

- `reverse-engineering-companion` — 19 safe local tools with all nine env vars;
- `ida-pro-idalib` — upstream IDA stdio MCP;
- `ghidra-mcp` — patched 28-tool Python bridge to `127.0.0.1:8080`.
  Set `RE_GHIDRA_TOKEN` before launching Codex; generated configs contain only
  an environment-variable reference, not the secret itself.

Restart Codex or start a new task after registration so it rediscovers server
tools. Check with `codex mcp list`.

## Validation performed

- Maven unit/package build passed against the installed 12.1.2 JARs.
- Ghidra headless imported a trusted x86-64 PE and saved it successfully.
- `RESkillExportSelection.java` compiled and produced bounded JSON in a
  no-analysis headless smoke test.
- Bridge MCP initialize/list passed with 28 tools and zero unknown tools or
  resources.
- `GhidraMCPPlugin` was enabled in the CodeBrowser Developer package and the
  tool configuration was saved for later CodeBrowser launches.
- With the trusted `python.exe` Program open, the pre-auth `/health` returned `status=ok`
  and `program=python.exe`. Actual stdio MCP calls to `ghidra_health`,
  `list_functions`, and `get_current_function` all succeeded.
- 2026-10-01 authenticated E2E passed on a separate Ghidra 12.1.2 distribution
  clone with an absolute temporary `application.settingsdir`; the normal
  Ghidra install was not modified. A CodeBrowser project imported and
  statically analyzed `Hermes-Setup (1).exe`; the executable was never run.
  Only `GhidraMCPPlugin` was enabled in the CodeBrowser tool configuration.
- After saving and reopening CodeBrowser, the plugin listened on
  `127.0.0.1:8080`. Direct HTTP auth returned 401 for missing credentials,
  401 for wrong credentials, and 200 for the protected token. The live verifier
  then completed MCP initialize/tools/list/resources and read-only
  `ghidra_health`, `list_functions`, and `get_current_function` calls.
- Live `read_only` coverage: 16 tools, 0 resources, 13/17 capabilities
  (0.7647), zero unknown tools/resources; the active Program matched and the
  function listing was non-empty. The verifier passes the token to its bridge
  child process without logging or persisting it. `doctor` separately reported
  Ghidra 12.1.2, installed extension, valid loopback, authenticated live plugin,
  active Program, and `live_host_claim=true`.
- An earlier GUI attempt used global `%APPDATA%` settings and reached a stale
  pre-auth plugin. The verifier rejected its 200/200/200 result as expected;
  that failed attempt is not counted as auth evidence. The corrected isolated
  run above is the authoritative result.

Repeat the live check on another workstation with:

~~~powershell
& "<project>\.venv\Scripts\python.exe" scripts\verify_ghidra_mcp.py `
  --bridge "C:\Path\To\GhidraMCP\bridge_mcp_ghidra.py" `
  --ghidra-server "http://127.0.0.1:8080/" `
  --profile read_only `
  --expected-program "sample.exe"
~~~

For a non-mutating live capability report, run the probe against the bridge:

~~~powershell
# Load the value from the configured local PowerShell SecretManagement vault.
$secureToken = Get-Secret -Name GhidraMcpToken -AsPlainText
if (-not $secureToken) { throw 'Store GhidraMcpToken in the local vault first.' }
$env:RE_GHIDRA_TOKEN = $secureToken
$secureToken = $null
python scripts\probe_mcp.py --command python --adapter ghidra -- `
  "C:\Tools\GhidraMCP\bridge_mcp_ghidra.py" --profile read_only
~~~

That command performs real MCP initialize/tools/list against the Python bridge,
but by itself does not prove the Java plugin is reachable or a Program is open;
use `verify_ghidra_mcp.py` for authenticated health and read-only calls.

## Primary sources

- [Official Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)
- [Official Ghidra Getting Started](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md)
- [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
