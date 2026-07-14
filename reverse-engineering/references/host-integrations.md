# MCP and host integration assets

Read this reference before enabling the companion MCP, installing the IDA
context-export plugin, or using the Ghidra selection-export script.

## Companion MCP

`scripts/re_mcp_server.py` is a stdio-only, read-only/planning companion MCP.
It exposes classification, deep PE triage, bounded selection analysis, entropy
and XOR candidates, the 50-feature catalog, host workflow plans, dump plans,
sealed edit/patch **plans**, and the safe runtime environment contract. It
exposes no apply/write/debug/`py_eval` tool.

Use `references/client-integration.md` for client-specific configuration. The
renderer supports Codex, Claude Code, Qwen Code, VS Code, Visual Studio, Zed,
Google Antigravity, and Kimi without modifying their real settings.
Use `references/environment-variables.md` for the nine validated `RE_MCP_*`
values, `.env.example`, root restrictions, and client-specific env syntax.

Check without starting a persistent server:

~~~text
python scripts/re_mcp_server.py --check
~~~

Use `assets/mcp/reverse-engineering-companion.json` as a client configuration
template after replacing `ABSOLUTE_PATH_TO`. Pin and review the optional Python
MCP SDK. Keep stdio client-owned; do not expose it over a network.

For this workstation, validation generated an ignored machine-local eight-client
pack under `.tmp/validation/client-configs-v0.5-ghidra/` containing separate
companion, `idalib-mcp`, and Ghidra bridge entries. Review the matching client
fragment before merging it; generation does not install or start a server.

## IDA

- Use upstream `idalib-mcp` for the primary MCP connection. Its current
  documented model uses persistent per-database workers, `idb_open`,
  `idb_list`, explicit `database` on every call, and `--stdio`.
- On this workstation its 65 tools/eight resources were discovered, and a
  trusted `python.exe` completed `idb_open`, `server_health`, and `list_funcs`
  with auto-analysis and Hex-Rays ready.
- The GUI MCP plugin is upstream-deprecated in favor of idalib, but GUI
  adoption remains useful for cursor/selection state.
- `assets/ida-plugin/re_skill_context.py` is an optional IDAPython plugin. On
  IDA startup it registers a manual menu action that exports at most 4096
  selected bytes, 2000 instructions, optional pseudocode, input hash, and IDB
  path to `~/.reverse-engineering-skill/exports`.
- The plugin does not start MCP, modify the database, run the sample, or use
  arbitrary Python evaluation. Copy/install only after code review and an IDB
  snapshot. On this workstation the source and installed copy have matching
  SHA-256, `py_compile` passed, and `PLUGIN_ENTRY()` loaded under the real
  IDA 9.4 `idapro` runtime; GUI menu activation still requires an IDA restart.
- Manual IDA 9.4 installation: copy `re_skill_context.py` to
  `%APPDATA%\Hex-Rays\IDA Pro\plugins\`, restart IDA, then use
  `File -> Produce file -> Export selection for Reverse Engineering Skill`.
  If `IDAUSR` is set, use its first element's `plugins` subdirectory instead.
  IDA's official SDK resolves user plugin directories before the installation
  plugin directory; do not overwrite built-in files under Program Files.

## Ghidra

- Use the upstream GhidraMCP release: its Java extension supplies the Ghidra
  HTTP endpoint and its Python bridge supplies MCP stdio/SSE. Keep both on
  loopback; stdio is preferred.
- The reviewed bridge exposes 28 tools including loopback health,
  method/class/import/export/string listing,
  decompilation, disassembly, current address/function, xrefs, renames,
  comments, prototypes, and variable types.
- `assets/ghidra-script/RESkillExportSelection.java` is a manual companion
  GhidraScript that exports a bounded selection, instructions, and decompiler
  text to the same user export directory. It performs no Program transaction
  or mutation. It was compiled and executed with Ghidra 12.1.2/OpenJDK 21
  against a trusted local PE; the JSON export completed without mutation.
- Add the Java file through Ghidra's Script Manager or a reviewed user script
  path (commonly `~/ghidra_scripts`). Install the upstream GhidraMCP release
  separately through the Extension Manager; the script is not that extension.
- Generate client entries with `client-configs --ghidra-bridge
  <bridge_mcp_ghidra.py> --ghidra-server http://127.0.0.1:8080/`. Opening
  Ghidra alone starts the plugin only if the extension is installed/enabled;
  the MCP client must still start the Python stdio bridge.
- For Ghidra 12.1.2, use `assets/ghidra-mcp/GhidraMCP-12.1.2.patch` and
  `scripts/install_ghidra_mcp.ps1`. The patch pins upstream commit
  `27f316f80139e2d5dec882519a1bdf4aa46ac04c`, fixes the 12.1.2 manifest/JAR
  contract, binds HTTP only to `127.0.0.1`, and adds `/health` plus the
  `ghidra_health` MCP tool. Full commands and this workstation's paths are in
  `ghidra-12.1.2.md`.

## Capability negotiation

Discover tools before use and normalize them through `adapters.py`. Unknown
tools fail closed. Upstream mutations remain `annotate`/`patch`; debugger and
arbitrary execution remain disabled unless separately authorized.

## Primary sources researched 2026-07-14

- [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- [Ghidra framework](https://github.com/NationalSecurityAgency/ghidra)
- [JADX](https://github.com/skylot/jadx)
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy)
- [IDA user/plugin path resolution](https://cpp.docs.hex-rays.com/diskio_8hpp.html)
- [IDA plugin packaging and format](https://hcli.docs.hex-rays.com/reference/plugin-packaging-and-format/)
- [Ghidra Getting Started and extension location](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md)
