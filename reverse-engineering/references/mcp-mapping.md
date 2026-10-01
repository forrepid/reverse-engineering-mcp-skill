# IDA and Ghidra MCP mapping

Read this reference before using a live IDA, idalib, or Ghidra session.

## Normalized capabilities

| Capability | IDA / idalib MCP | GhidraMCP | Mutation class |
|---|---|---|---|
| Session health | `server_health`, `idb_list` (negotiate aliases if upstream changes) | `get_current_program`, `list_open_programs` plus bridge health | Read |
| Open/adopt database | `idb_open` (negotiate aliases if upstream changes) | `set_current_program` | Read/session |
| Metadata/segments | `ida://idb/metadata`, `ida://idb/segments` | `get_current_program`, `list_segments` | Read |
| Functions | `list_funcs`, `lookup_funcs` | `list_functions`, `get_function_by_address/name` | Read |
| Decompile | `decompile` | `decompile_function_by_address/name` | Read |
| Assembly | `disasm` | `disassemble_function` | Read |
| Raw bytes | `get_bytes` | host memory/search tools when negotiated | Read |
| Strings | `get_string`, `find_regex` | `list_strings`, `search_strings` | Read |
| Imports/exports | `imports`, import/export resources | `list_imports`, `list_exports` | Read |
| References | `xrefs_to`, `callees` | `get_xrefs_to/from` | Read |
| Rename/comment/type | `rename`, `set_comments`, `set_type` | rename tools, `set_decompiler_comment`, prototype/type tools | Annotate |
| Patch | `patch`, `patch_asm`, `put_int` | patch/write endpoints if exposed | Patch |
| Debug | `dbg_*` extension | Ghidra debugger/traces if separately wired | Debug |

Tool names can change across upstream versions. Discover capabilities first
and fail closed if a mutating tool is not classified.

The local `scripts/re_mcp_server.py` companion is a third surface for file
classification, advanced PE evidence, bounded selections, feature plans and
sealed edit/patch plans. It deliberately exposes no apply/write/debug/eval or
process-execution tool. It complements IDA/Ghidra; it does not emulate their
decompiler, control-flow analysis or active selection state.

## IDA session rules

1. Prefer `idalib-mcp` for headless or multi-database work.
2. For locally validated `ida-pro-mcp 2.0.0`, call `idb_open` and retain the
   returned session identifier. Discover tools rather than assuming future
   aliases.
3. Pass the explicit `database` argument on every database operation.
4. Wait for auto-analysis and record whether Hex-Rays is available. Do not
   collect final context while analysis is still changing the database.
5. Use GUI state resources only when the user intends cursor/selection scope.
6. Keep debugger tools disabled unless `debug` mode was approved.
7. Do not call `py_eval` on data-derived code.
8. Use `ida-context-plan` to inspect the bounded read-only request set before
   wiring a new transport.

The upstream documentation states that GUI MCP is no longer the recommended
path and describes persistent, per-database idalib workers. Recheck upstream
before pinning a release.

## Ghidra session rules

1. Confirm the GhidraMCP extension is enabled and the local HTTP plugin is
   listening.
2. Keep the Ghidra plugin endpoint on loopback by default.
3. Launch the Python MCP bridge through the client's stdio configuration or a
   protected local transport.
4. Confirm that the intended Program is current before reading or mutating.
5. Wait for analysis completion; record the active language/compiler spec.
6. Wrap mutations in a Ghidra transaction and report rollback/commit state.
7. Treat the supplied `assets/ghidra-script/RESkillExportSelection.java` as a
   manual read-only exporter until it is compiled and tested against the
   installed Ghidra release; it is not a replacement for GhidraMCP.

## Capability negotiation

The adapter profile in `scripts/re_core/adapters.py` is the local, testable
contract. A live host integration should:

1. list tools/resources;
2. map only known names;
3. classify each operation as read, annotate, patch, debug, or dynamic;
4. expose unavailable capabilities honestly;
5. log request IDs and bounded response metadata without sample secrets.
### Runtime OEP

- `oep_static_candidates(sample)`: read-only PE OEP hypothesis report; explicitly
  returns `oep_result` with `Runtime OEP: NOT VERIFIED` until signed runtime
  evidence is verified.
- `oep_runtime_plan(sample, provider, ...)`: returns a bounded plan and broker
  configuration status only. It does not submit, start a VM, or execute samples.
- `oep_runtime_verify(...)`: imports evidence only and requires the confirmed
  plan digest, trusted broker ID, and operator-pinned Ed25519 key digest.
- Runtime start/status/trace/dump/export MCP tools remain unavailable until a
  broker-specific capture/signing adapter and approval protocol are implemented.
