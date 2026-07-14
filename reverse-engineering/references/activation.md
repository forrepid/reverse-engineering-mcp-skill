# Host activation contract

Read this reference when installing, auto-starting, or troubleshooting a live
IDA/Ghidra connection.

## Separation of responsibility

The skill does not inject code into IDA or Ghidra. The official/upstream host
extension owns application lifecycle events and exposes local analysis
capabilities. The MCP client owns bridge startup. The local session monitor
only reports loopback TCP transitions and does not treat an open port as a
trusted MCP server.

## IDA

1. Run `ida-profile` first and review the discovered executable, version,
   component hashes, activation script, wheel, and warnings.
2. Install or update a compatible release of `mrexodia/ida-pro-mcp` only from
   its documented source; do not execute similarly named files found nearby.
3. Generate `idalib-plan` and review the exact `shell=False`, loopback-only
   command before any start. Prefer `stdio` for a client-owned server. The
   validated 2.0.0 supervisor already uses persistent per-database workers;
   there is no separate shared-context flag.
4. Prefer `idalib-mcp` for headless and multi-database work.
5. Use the GUI plugin only when application-open, cursor, selection, or
   interactive database state is required.
6. Restart IDA and the MCP client after installation.
7. Discover resources/tools, verify database identity and auto-analysis state,
   then create the normalized capability profile.

## Ghidra

1. Install a GhidraMCP build matching the exact Ghidra version. For 12.1.2 use
   the pinned patch/build procedure in `ghidra-12.1.2.md`; the public upstream
   1.4 archive targets Ghidra 11.3.2.
2. Restart Ghidra and enable `GhidraMCPPlugin` once in CodeBrowser tool
   configuration. Later CodeBrowser openings load it with that saved tool.
3. Keep the plugin server on `127.0.0.1`; the reviewed build adds `/health` and
   refuses LAN exposure. Configure the Python MCP bridge as a separate stdio
   server in the client.
4. Call `ghidra_health`. Require `status=ok` and a non-`none` Program before
   accepting a live Program claim; then confirm analysis completion.

Opening IDA/Ghidra does not by itself start every MCP layer. For IDA, the MCP
client normally starts `idalib-mcp` over stdio; the GUI plugin activates only
when installed in IDA. For Ghidra, the enabled Java plugin supplies the local
HTTP endpoint while the MCP client starts `bridge_mcp_ghidra.py`. The generated
client config records both processes separately.

## Startup watcher

Run:

~~~text
python scripts/re_cli.py hosts --watch --interval 2
~~~

Start this command through a supervised user service or MCP-client lifecycle,
not an elevated system service. On `host-online`, initialize MCP, list
capabilities, validate the server identity, and enter read-only mode. Never
auto-enable annotate, patch, debug, sandbox, or arbitrary Python execution.

Default probes are IDA GUI `127.0.0.1:13337`, idalib `127.0.0.1:8745`, Ghidra
plugin `127.0.0.1:8080`, and Ghidra bridge `127.0.0.1:8081`. Override these in
a future signed deployment profile rather than editing policy at runtime.

## Current validation status

On 2026-07-14, IDA 9.4 and its idalib/IDAPython components were profiled at the
user-provided path, and an `idalib-mcp` entry point was discovered in the local
Python environment. Its 65 tools and eight resources were discovered; on a
trusted local `python.exe`, real stdio calls to `idb_open`, `server_health`, and
`list_funcs` passed with auto-analysis and Hex-Rays ready. Ghidra 12.1.2 and
OpenJDK 21 are installed, the patched extension builds against the real 12.1.2
JARs, a trusted PE import/headless-analysis smoke passed, and the bridge exposed
28 fully classified MCP tools. The bounded selection exporter also executed in
Ghidra headless mode. `GhidraMCPPlugin` was enabled in the CodeBrowser Developer
package and the tool configuration was saved. With the trusted `python.exe`
Program active, `/health` returned `status=ok`/`program=python.exe`; actual stdio
MCP calls to `ghidra_health`, `list_functions`, and `get_current_function`
succeeded. A full Ghidra close/relaunch then reopened the saved project,
Program, and plugin automatically; the listener remained bound only to
`127.0.0.1:8080`, and the same MCP calls passed again. Optional external
detectors remain provider-by-provider preflight items.
