# Primary tooling research

Research date: 2026-07-14. Revalidate versions and license terms before
shipping. Links point to primary project or vendor documentation.

## MCP and host integration

- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) — IDA and
  idalib MCP implementation. Current documentation recommends `idalib-mcp`
  over the older GUI MCP plugin, uses explicit database session identifiers,
  and exposes read, annotation, patch, search, graph, and optional debugger
  operations.
- [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — Ghidra
  Java extension plus Python MCP bridge; supports decompilation, listing and
  rename workflows.
- [mrexodia/mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset)
  — small, semi-structured examples of LLM reverse-engineering tasks. Use only
  as workflow inspiration, not as an industrial benchmark or trusted corpus.
- [Hex-Rays IDAPython SDK](https://docs.hex-rays.com/developer-guide/idapython)
  — official scripting and plugin API guidance.
- [NSA Ghidra](https://github.com/NationalSecurityAgency/ghidra) — official
  source tree and plugin API examples.
- [MCP specification](https://modelcontextprotocol.io/specification/) —
  protocol lifecycle, tools, resources and transports. Pin an implemented
  stable revision rather than a future release candidate.

## Detection and static analysis

- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) — cross-platform
  signature and heuristic file identification, packer/protection detection,
  PEiD rule compatibility, CLI `diec` and developer API. Its maintained format
  surface includes PE, ELF, APK, IPA, JAR, ZIP, DEX, DOS/COM, LE/LX, Mach-O and
  NPM; correlate its signature and heuristic results with structural evidence.
- [YARA-X](https://github.com/VirusTotal/yara-x) — maintained Rust rewrite for
  pattern matching. Prefer it for new provider work while retaining classic
  YARA compatibility only when required.
- [capa](https://github.com/mandiant/capa) — static and supported sandbox-report
  capability identification for PE, ELF, .NET, shellcode and more; also has
  IDA/Ghidra integration paths.
- [FLOSS](https://github.com/mandiant/flare-floss) — static, stack, tight,
  decoded, Go and Rust string recovery.
- [pefile](https://github.com/erocarrera/pefile) — mature Python PE parser,
  including header/section access and PEiD signature support.
- [LIEF](https://github.com/lief-project/LIEF) — C++/Python/Rust library for
  parsing and instrumenting PE, ELF, Mach-O and related formats.
- [Capstone](https://github.com/capstone-engine/capstone) — multi-architecture
  disassembly engine with instruction detail. The optional local `disasm`
  command performs linear sweep only; use IDA/Ghidra for code/data boundaries
  and control-flow-aware analysis.

## Category-specific providers

- [JADX](https://github.com/skylot/jadx) — APK/DEX/AAB/AAR/JAR/class/smali/zip
  decompiler and resource decoder. It includes deobfuscation support, but its
  own documentation warns that every method is not guaranteed to decompile;
  retain DEX/smali and error evidence beside Java-like output.
- [Apktool](https://github.com/iBotPeaches/Apktool) — Android resource and
  manifest decoding/rebuilding. Rebuild is an explicit mutation workflow, not
  read-only triage.
- [radareorg/radare2](https://github.com/radareorg/radare2) — portable binary
  inspection and multi-format tooling; use through a bounded provider adapter.
- [BinDiff](https://github.com/google/bindiff) — function-level binary
  comparison for supported IDA/Ghidra exports. Keep it optional and record the
  exact exporter/tool version.
- [ExifTool](https://exiftool.org/) — metadata extraction for visual/audio and
  many container formats. Strip sensitive paths and metadata before sharing.

Language translation is never treated as lossless source recovery. Prefer an
intermediate representation containing address, bytes, assembly, pseudocode,
types and confidence; keep the original host export next to any translated
Rust/C/Python explanation.

## Dynamic analysis boundary

- [Unicorn](https://github.com/unicorn-engine/unicorn) emulates CPU
  instructions but is not a complete operating-system sandbox.
- [Qiling](https://github.com/qilingframework/qiling) adds executable loaders,
  syscall and OS abstractions on top of Unicorn. Treat it as emulation, not a
  substitute for an isolated malware-analysis environment.
- capa officially consumes dynamic reports from CAPE, DRAKVUF and VMRay.
  Provider-specific submission must remain outside the core and require
  authorization, credentials handling, retention policy, and network controls.

## Selection policy

Use the stdlib analyzer for deterministic baseline evidence. Add DiE for
format/packer detection, YARA-X for organization rules, capa for behavioral
capabilities, FLOSS for recovered strings, and LIEF/pefile for deep format
parsing. Keep every provider optional, versioned, timeout-bounded and
independently testable.
