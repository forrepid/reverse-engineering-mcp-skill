# IDA Professional 9.4 local profile

Read this reference before changing IDA discovery, idalib activation, database
snapshots, or live context collection.

## Validated local installation

- User-supplied executable: `C:\Program Files\IDA Professional 9.4\ida.exe`
- Profiled product version: `9.4.26.610`
- Required IDA GUI, idalib, IDAPython, activation script, and Python wheel were
  detected by a read-only dry run on 2026-07-14.
- A local Python `idalib-mcp` entry point from `ida-pro-mcp 2.0.0` was
  discovered. Its 65-tool/eight-resource stdio surface was initialized and
  classified without unknown capabilities.
- The optional selection plugin was copied to the user plugin directory with
  a matching SHA-256; `py_compile` and `PLUGIN_ENTRY()` under IDA 9.4's real
  `idapro` runtime passed.
- On a trusted local `python.exe`, `idb_open` created a headless session with
  auto-analysis and Hex-Rays ready. Real `server_health` and `list_funcs` MCP
  calls succeeded. The original sample was not patched or executed.
- The installation root contains at least one suspiciously named executable.
  It is excluded from all launch allowlists and must never be run by this
  project. Presence is a warning, not proof of provenance or behavior.

Do not store IDA binaries, SDK artifacts, wheels, license material, or local
installation hashes in the repository. Regenerate machine-local profiles when
needed; put them in ignored artifact directories.

## Modules and responsibilities

| Module | Responsibility | Side effects |
|---|---|---|
| `ida_installation.py` | Locate exact components, versions, optional hashes, wheel, and warnings | Read-only |
| `mcp_supervisor.py` | Build an allowlisted loopback launch plan; optional HTTP lifecycle supervisor | None during planning |
| `ida_live.py` | Select an explicit session, gate on auto-analysis, collect bounded context | Read-only by default |
| `snapshots.py` | Copy a confirmed-saved IDB and seal a manifest | New snapshot only |
| `patch_impact.py` | Apply a sealed plan in memory and preview structural/integrity effects | None |
| `inventory.py` | Record import/section/dependency evidence and limitations | None unless CLI output requested |

## Activation boundaries

1. `ida-profile` may hash components but never imports or launches IDA.
2. `idalib-plan` emits exact activation and MCP command arrays but executes
   neither. Only the basename `idalib-mcp`/`idalib-mcp.exe` is accepted. The
   local 2.0.0 command surface uses `--stdio`, `--host`, `--port`, and
   `--max-workers`; unsupported shared/isolation flags are never invented.
3. HTTP plans are loopback-only. `stdio` remains client-owned.
4. The optional supervisor is not auto-started and accepts only the reviewed
   HTTP plan with `shell=False`; start also requires the planned executable's
   SHA-256 as an explicit confirmation.
5. A live session is not trusted merely because a port is open. Negotiate MCP,
   list tools/resources, select the intended database, and wait for analysis.
6. Final context is collected through `lookup_funcs`, `get_bytes`, `disasm`,
   `decompile`, `xrefs_to`, and `callees`; required calls fail closed.

Repeat the live read-only smoke with a trusted sample:

~~~powershell
& "<project>\.venv\Scripts\python.exe" scripts\verify_idalib_mcp.py `
  --command "C:\Path\To\idalib-mcp.exe" `
  --sample "C:\Path\To\Trusted\sample.exe"
~~~

## Snapshot and patch boundaries

- IDB snapshots require the operator to confirm that IDA saved/flushed the
  database. The source hash is checked before and after copying.
- Restore is plan-only. IDA must be closed and a separate explicit operation
  must verify the manifest before replacing any database.
- Patch impact uses an in-memory copy. For PE files it reports affected
  sections, overlay/certificate intersection, projected hash, entropy,
  Authenticode re-signing need, checksum guidance, and optional Capstone linear
  disassembly. IDA/Ghidra remains authoritative for code boundaries.

## Primary references

- [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- [Hex-Rays IDA 9.4 release notes](https://docs.hex-rays.com/release-notes/9_4)
- [Hex-Rays IDAPython developer guide](https://docs.hex-rays.com/developer-guide/idapython)
- [Hex-Rays Domain API](https://docs.hex-rays.com/developer-guide/domain-api)
