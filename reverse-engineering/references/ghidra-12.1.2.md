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
4. binds the unauthenticated plugin HTTP surface to `127.0.0.1`, never the LAN;
5. adds `/health` and the classified `ghidra_health` MCP tool.

Apply it only to the pinned commit:

~~~powershell
git clone https://github.com/LaurieWired/GhidraMCP.git C:\Tools\GhidraMCP
git -C C:\Tools\GhidraMCP checkout 27f316f80139e2d5dec882519a1bdf4aa46ac04c
git -C C:\Tools\GhidraMCP apply "<project>\assets\ghidra-mcp\GhidraMCP-12.1.2.patch"
~~~

## Build and install

The installer refuses a different upstream commit, a different Ghidra version,
a non-empty reviewed manifest, a missing loopback bind, or missing Ghidra JARs.
It never deletes an extension tree.

~~~powershell
& "<project>\scripts\install_ghidra_mcp.ps1" `
  -GhidraHome "C:\Users\beessy\Tools\ghidra_12.1.2_PUBLIC" `
  -Source "C:\Users\beessy\Tools\GhidraMCP" `
  -JavaHome "C:\Program Files\Microsoft\jdk-21.0.11.10-hotspot" `
  -MavenHome "C:\Users\beessy\Tools\apache-maven-3.9.12" `
  -Install
~~~

The command prints the effective commit and SHA-256 of the generated ZIP/JAR.
The installed extension is
`<GhidraHome>\Ghidra\Extensions\GhidraMCP`.

## One-time CodeBrowser activation

1. Start Ghidra and open or create a project.
2. Open a program in CodeBrowser.
3. Choose `File -> Configure`, locate `GhidraMCPPlugin`, enable it, and save the
   tool configuration.
4. Restart that CodeBrowser tool.
5. Verify `http://127.0.0.1:8080/health`; `program=none` means the plugin is
   alive but no Program is active.

After this one-time tool configuration, the MCP client starts the Python bridge
over stdio. Opening a configured CodeBrowser supplies the local HTTP plugin.

## Codex registration on this workstation

The global Codex configuration has three separate enabled servers:

- `reverse-engineering-companion` — 19 safe local tools with all nine env vars;
- `ida-pro-idalib` — upstream IDA stdio MCP;
- `ghidra-mcp` — patched 28-tool Python bridge to `127.0.0.1:8080`.

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
- With the trusted `python.exe` Program open, `/health` returned `status=ok`
  and `program=python.exe`. Actual stdio MCP calls to `ghidra_health`,
  `list_functions`, and `get_current_function` all succeeded.
- After a full Ghidra close/relaunch, the saved project and CodeBrowser Program
  reopened, the plugin restarted automatically on `127.0.0.1:8080`, and the
  same three read-only MCP calls passed again.
- `doctor` detects the launcher, headless analyzer, extension JAR, bridge,
  version and loopback health separately; its live host claim was true.

Repeat the live check on another workstation with:

~~~powershell
& "<project>\.venv\Scripts\python.exe" scripts\verify_ghidra_mcp.py `
  --bridge "C:\Path\To\GhidraMCP\bridge_mcp_ghidra.py" `
  --ghidra-server "http://127.0.0.1:8080/" `
  --expected-program "sample.exe"
~~~

## Primary sources

- [Official Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)
- [Official Ghidra Getting Started](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md)
- [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
