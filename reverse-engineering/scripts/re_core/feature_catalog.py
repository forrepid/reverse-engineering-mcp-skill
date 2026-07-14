from __future__ import annotations

from dataclasses import asdict, dataclass
from collections import Counter
from collections.abc import Iterable
from typing import Any


@dataclass(frozen=True)
class EngineeringFeature:
    id: str
    name: str
    category: str
    description: str
    mode: str
    status: str
    local_implementation: str
    generation: int = 1
    ida_tools: tuple[str, ...] = ()
    ida_resources: tuple[str, ...] = ()
    ghidra_tools: tuple[str, ...] = ()
    ghidra_resources: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()
    guards: tuple[str, ...] = ()


FEATURES: tuple[EngineeringFeature, ...] = (
    EngineeringFeature(
        "file-taxonomy",
        "Universal file taxonomy",
        "triage",
        "Classify Android, macOS/iOS, Java, Windows, assembly, dongle, binary, script, visual, and audio artifacts from evidence.",
        "read_only",
        "implemented",
        "re_core.file_types.classify_file",
        providers=("die",),
    ),
    EngineeringFeature(
        "pe-oep-map",
        "Declared entry point and OEP candidate map",
        "pe",
        "Map AddressOfEntryPoint to RVA, VA, file offset, section, permissions, and entry bytes without claiming runtime OEP recovery.",
        "read_only",
        "implemented",
        "re_core.advanced_pe.analyze_pe_deep",
        ida_tools=("get_bytes", "disasm"),
        ida_resources=("ida://idb/entrypoints",),
        ghidra_tools=("get_function_by_address", "disassemble_function"),
    ),
    EngineeringFeature(
        "boundary-overlay-map",
        "Header, section, certificate, overlay, and EOF map",
        "pe",
        "Identify physical boundaries, inter-section gaps, certificate table, overlay, and logical end.",
        "read_only",
        "implemented",
        "re_core.advanced_pe.analyze_pe_deep",
    ),
    EngineeringFeature(
        "marker-extractor",
        "Compiler, PDB, packer, anti-debug, and license markers",
        "detection",
        "Extract explicit markers with offsets and confidence while preserving false-positive caveats.",
        "read_only",
        "implemented",
        "re_core.advanced_pe.analyze_pe_deep",
        ida_tools=("find_bytes", "find_regex", "imports"),
        ghidra_tools=("list_imports", "list_strings"),
        providers=("die", "yara-x"),
    ),
    EngineeringFeature(
        "protection-correlation",
        "Multi-engine packer and protection correlation",
        "detection",
        "Correlate local heuristics with DiE, YARA-X, capa, and optional format parsers.",
        "read_only",
        "provider-ready",
        "re_core.external + evidence correlation",
        providers=("die", "yara-x", "capa", "lief"),
    ),
    EngineeringFeature(
        "injection-detector",
        "Process-injection technique detector",
        "behavior",
        "Group imported primitives into remote-thread, APC, hollowing, section-map, hook, and permission-transition candidates.",
        "read_only",
        "implemented",
        "re_core.advanced_pe.analyze_pe_deep",
        ida_tools=("imports", "xrefs_to", "callees", "analyze_batch"),
        ghidra_tools=("list_imports", "get_xrefs_to", "get_xrefs_from"),
        guards=("detection-only by default",),
    ),
    EngineeringFeature(
        "obfuscation-score",
        "Explainable obfuscation score",
        "detection",
        "Score entropy, RWX sections, packer names, entry permissions, import scarcity, and overlay signals with reasons.",
        "read_only",
        "implemented",
        "re_core.advanced_pe.analyze_pe_deep",
    ),
    EngineeringFeature(
        "encrypted-region-map",
        "Encrypted or compressed region candidates",
        "detection",
        "Map high-entropy sections and bounded entropy windows without asserting encryption as fact.",
        "read_only",
        "implemented",
        "re_core.transforms.entropy_windows",
    ),
    EngineeringFeature(
        "xor-transform-lab",
        "Bounded XOR decode lab",
        "transform",
        "Rank all 256 single-byte XOR keys for a selected region and export a confirmed out-of-place transform.",
        "patch_plan",
        "implemented",
        "re_core.transforms",
        guards=("1 MiB selection", "not credential or license brute force", "hash confirmation"),
    ),
    EngineeringFeature(
        "memory-dump-plan",
        "Static and runtime dump planner",
        "dump",
        "Create bounded static get-bytes or approval-gated isolated debugger memory-dump requests.",
        "debug",
        "implemented-plan",
        "re_core.selection.build_dump_plan",
        ida_tools=("get_bytes", "dbg_read"),
        guards=("runtime requires isolated debugger", "never auto-execute sample"),
    ),
    EngineeringFeature(
        "selection-context",
        "Address and range context extractor",
        "selection",
        "Collect bytes, function, disassembly, pseudocode, xrefs, and callees for a bounded selection.",
        "read_only",
        "implemented",
        "re_core.selection",
        ida_tools=("lookup_funcs", "get_bytes", "disasm", "decompile", "xrefs_to", "callees"),
        ghidra_tools=("get_current_address", "get_function_by_address", "disassemble_function", "decompile_function_by_address"),
    ),
    EngineeringFeature(
        "decompiled-source-export",
        "Decompiler source view and evidence export",
        "source",
        "Export decompiler output with address provenance and label it as reconstruction rather than original source.",
        "read_only",
        "mapped-upstream",
        "re_core.selection.build_source_operation_plan",
        ida_tools=("decompile", "export_funcs"),
        ghidra_tools=("decompile_function_by_address",),
    ),
    EngineeringFeature(
        "source-line-features",
        "Selected source-line feature extraction",
        "source",
        "Extract imports, functions, URLs, TODOs, and crypto terms from a bounded UTF-8 line range.",
        "read_only",
        "implemented",
        "re_core.selection.inspect_text_lines",
    ),
    EngineeringFeature(
        "sealed-source-edit",
        "Sealed out-of-place source edit",
        "source",
        "Plan and apply replace/insert edits with expected text, source SHA-256, digest, and new output only.",
        "patch_apply",
        "implemented",
        "re_core.source_edit",
        guards=("UTF-8", "no in-place write", "explicit hash confirmation"),
    ),
    EngineeringFeature(
        "language-provenance",
        "Programming language and runtime provenance",
        "detection",
        "Identify .NET, Go, Rust, Delphi, VB6, PyInstaller, AutoIt, Qt, Java, and Android candidates from structural markers.",
        "read_only",
        "implemented",
        "re_core.advanced_pe + re_core.file_types",
        providers=("die", "capa"),
    ),
    EngineeringFeature(
        "code-translation-contract",
        "Evidence-preserving code translation",
        "source",
        "Translate selected pseudocode or assembly into C, C++, Rust, Python, Java, C#, or explanatory pseudocode with provenance.",
        "read_only",
        "implemented-plan",
        "re_core.selection.build_source_operation_plan",
        guards=("never claim original source", "never compile or execute automatically"),
    ),
    EngineeringFeature(
        "semantic-function-diff",
        "Semantic function difference report",
        "comparison",
        "Compare normalized instructions, decompiler structure, calls, constants, strings, and types across versions.",
        "read_only",
        "planned-provider",
        "comparison extension point",
        ida_tools=("analyze_batch", "export_funcs", "basic_blocks"),
        ghidra_tools=("decompile_function_by_address", "disassemble_function"),
        providers=("bindiff",),
    ),
    EngineeringFeature(
        "callgraph-slice",
        "Bounded call-graph and data-flow slice",
        "graph",
        "Build depth- and node-limited call slices around selected security-relevant functions.",
        "read_only",
        "mapped-upstream",
        "host workflow plan",
        ida_tools=("callgraph", "callees", "xrefs_to"),
        ghidra_tools=("get_xrefs_to", "get_xrefs_from"),
    ),
    EngineeringFeature(
        "decoded-string-correlation",
        "Decoded string correlation",
        "strings",
        "Correlate ordinary strings, FLOSS results, XOR candidates, and code references.",
        "read_only",
        "provider-ready",
        "re_core.transforms + external provider",
        ida_tools=("find_regex", "xrefs_to"),
        ghidra_tools=("list_strings", "get_xrefs_to"),
        providers=("floss",),
    ),
    EngineeringFeature(
        "import-hash-analysis",
        "Import-hash and resolver analysis",
        "detection",
        "Detect resolver loops and compare constants against explicitly supplied, authorized API hash schemes.",
        "read_only",
        "planned-provider",
        "host workflow plan",
        ida_tools=("find", "analyze_batch", "callees"),
        ghidra_tools=("disassemble_function", "get_xrefs_from"),
    ),
    EngineeringFeature(
        "dongle-license-map",
        "Dongle and license interaction map",
        "dongle",
        "Detect HASP/Sentinel, Wibu/CodeMeter, FlexNet, Rockey, and related components; map call sites without bypassing licensing.",
        "read_only",
        "implemented",
        "re_core.file_types + re_core.advanced_pe",
        ida_tools=("imports", "find_regex", "xrefs_to"),
        ghidra_tools=("list_imports", "list_strings", "get_xrefs_to"),
        guards=("analysis only", "no license bypass or key generation"),
    ),
    EngineeringFeature(
        "android-pipeline",
        "Android APK/AAB/DEX pipeline",
        "android",
        "Classify containers, decode manifest/resources, decompile DEX, retain smali/CFG fallback, and correlate native libraries.",
        "read_only",
        "provider-ready",
        "file taxonomy + provider plan",
        providers=("jadx", "apktool", "ghidra"),
    ),
    EngineeringFeature(
        "java-pipeline",
        "Java JAR/class pipeline",
        "java",
        "Classify JAR/class files, record class version, decompile, extract resources, and preserve bytecode fallback.",
        "read_only",
        "provider-ready",
        "file taxonomy + provider plan",
        providers=("vineflower", "cfr", "jadx"),
    ),
    EngineeringFeature(
        "apple-pipeline",
        "Mach-O and IPA pipeline",
        "mac",
        "Classify Mach-O/fat/IPA artifacts, enumerate bundle metadata, signatures, Objective-C/Swift symbols, and native code.",
        "read_only",
        "provider-ready",
        "file taxonomy + host plan",
        providers=("lief", "ghidra", "ida"),
    ),
    EngineeringFeature(
        "resource-media-extractor",
        "Visual, audio, and embedded resource extractor",
        "resources",
        "Identify resource media by magic, map container/PE resources, and extract only to hash-recorded out-of-place artifacts.",
        "read_only",
        "implemented-partial",
        "re_core.file_types + selection extraction contract",
        providers=("binwalk", "lief"),
        guards=("never render active content automatically",),
    ),
    EngineeringFeature(
        "function-fingerprint-cluster",
        "Function fingerprint and similarity cluster",
        "comparison",
        "Cluster functions using normalized instructions, constants, calls, strings, and bounded CFG features across authorized samples.",
        "read_only",
        "planned-provider",
        "normalized host export extension",
        generation=2,
        ida_tools=("export_funcs", "basic_blocks", "callees"),
        ghidra_tools=("disassemble_function", "get_xrefs_from"),
        providers=("bindiff", "diaphora"),
    ),
    EngineeringFeature(
        "control-flow-anomaly-map",
        "Control-flow anomaly and opaque-predicate map",
        "graph",
        "Locate flattening dispatchers, opaque-predicate candidates, overlapping instructions, and unresolved indirect branches with reasons.",
        "read_only",
        "mapped-upstream",
        "host workflow plan",
        generation=2,
        ida_tools=("basic_blocks", "disasm", "xrefs_to"),
        ghidra_tools=("disassemble_function", "get_xrefs_to", "get_xrefs_from"),
    ),
    EngineeringFeature(
        "bounded-taint-slice",
        "Bounded source-to-sink data-flow slice",
        "dataflow",
        "Trace a depth- and node-limited path from selected inputs to security-relevant calls without claiming whole-program coverage.",
        "read_only",
        "planned-provider",
        "host workflow plan",
        generation=2,
        ida_tools=("analyze_batch", "xrefs_to", "callees"),
        ghidra_tools=("decompile_function_by_address", "get_xrefs_to", "get_xrefs_from"),
        providers=("angr", "ghidra-pcode"),
    ),
    EngineeringFeature(
        "stack-frame-recovery",
        "Stack-frame, arguments, and local-variable recovery",
        "types",
        "Compare calling-convention, stack-use, decompiler, and unwind evidence to recover function arguments and locals.",
        "annotate",
        "mapped-upstream",
        "host workflow plan",
        generation=2,
        ida_tools=("decompile", "disasm", "set_type"),
        ghidra_tools=("decompile_function_by_address", "set_function_prototype", "set_local_variable_type"),
        guards=("annotation requires snapshot and review",),
    ),
    EngineeringFeature(
        "type-reconstruction-assistant",
        "Structure, union, enum, and class reconstruction assistant",
        "types",
        "Infer candidate data types from offsets, access widths, calls, strings, and constructor patterns before reviewed annotation.",
        "annotate",
        "mapped-upstream",
        "host workflow plan",
        generation=2,
        ida_tools=("decompile", "type_query", "type_inspect", "set_type"),
        ghidra_tools=("decompile_function_by_address", "set_function_prototype", "set_local_variable_type"),
        guards=("candidate types only", "snapshot before annotation"),
    ),
    EngineeringFeature(
        "vtable-rtti-recovery",
        "Vtable, RTTI, Objective-C, and Swift metadata recovery",
        "types",
        "Find class metadata and virtual dispatch tables, then map methods and inheritance candidates.",
        "read_only",
        "planned-provider",
        "host workflow plan",
        generation=2,
        ida_tools=("find", "xrefs_to", "type_query", "search_structs"),
        ghidra_tools=("list_classes", "list_methods", "get_xrefs_to"),
        providers=("ghidra-classtypeinfo",),
    ),
    EngineeringFeature(
        "syscall-api-resolution",
        "Syscall, API-set, ordinal, and dynamic resolver map",
        "detection",
        "Resolve direct syscalls, forwarded exports, ordinals, Windows API sets, and authorized dynamic API-hash candidates.",
        "read_only",
        "planned-provider",
        "host workflow plan",
        generation=2,
        ida_tools=("imports", "find", "analyze_batch"),
        ghidra_tools=("list_imports", "disassemble_function", "get_xrefs_from"),
    ),
    EngineeringFeature(
        "anti-analysis-fingerprint",
        "Anti-debug, anti-VM, anti-sandbox fingerprint",
        "behavior",
        "Correlate timing, CPUID, process, device, registry, debugger, and hypervisor checks as detection evidence.",
        "read_only",
        "implemented-partial",
        "re_core.advanced_workflows.anti_analysis_fingerprint + host correlation",
        generation=2,
        ida_tools=("imports", "find_regex", "xrefs_to"),
        ghidra_tools=("list_imports", "list_strings", "get_xrefs_to"),
        providers=("capa", "yara-x"),
        guards=("do not generate evasion logic",),
    ),
    EngineeringFeature(
        "persistence-indicator-map",
        "Persistence mechanism indicator map",
        "behavior",
        "Map service, task, autorun, startup, login-item, launch-agent, WMI, and scheduled persistence candidates.",
        "read_only",
        "implemented-partial",
        "re_core.advanced_workflows.persistence_indicator_map + host correlation",
        generation=2,
        ida_tools=("imports", "find_regex", "xrefs_to"),
        ghidra_tools=("list_imports", "list_strings", "get_xrefs_to"),
        providers=("capa",),
    ),
    EngineeringFeature(
        "protocol-artifact-map",
        "Network protocol, endpoint, and serialization artifact map",
        "network",
        "Correlate URLs, domains, ports, TLS material, protocol constants, protobuf schemas, and socket call sites.",
        "read_only",
        "implemented-partial",
        "re_core.advanced_workflows.protocol_artifact_map + host correlation",
        generation=2,
        ida_tools=("find_regex", "imports", "xrefs_to"),
        ghidra_tools=("list_strings", "list_imports", "get_xrefs_to"),
        providers=("floss", "capa"),
        guards=("no automatic network connection",),
    ),
    EngineeringFeature(
        "crypto-primitive-recognition",
        "Cryptographic primitive and misuse candidate recognition",
        "crypto",
        "Identify constants, S-boxes, APIs, round structures, key sizes, modes, and suspicious nonce or RNG use.",
        "read_only",
        "planned-provider",
        "host workflow plan",
        generation=2,
        ida_tools=("find", "analyze_batch", "callees"),
        ghidra_tools=("disassemble_function", "decompile_function_by_address"),
        providers=("capa", "yara-x"),
        guards=("recognition is not successful decryption",),
    ),
    EngineeringFeature(
        "config-blob-carver",
        "Embedded configuration blob carver",
        "carving",
        "Find bounded JSON, XML, INI, protobuf, compressed, XOR, and custom TLV configuration candidates and export provenance.",
        "read_only",
        "implemented-partial",
        "re_core.advanced_workflows.config_blob_carver",
        generation=2,
        ida_tools=("find_bytes", "find_regex", "get_bytes", "xrefs_to"),
        ghidra_tools=("list_strings", "get_xrefs_to"),
    ),
    EngineeringFeature(
        "recursive-embedded-carver",
        "Recursive embedded-file and container carver",
        "carving",
        "Carve nested magic-aligned artifacts with depth, count, size, decompression-ratio, and hash limits.",
        "read_only",
        "implemented-partial",
        "re_core.advanced_workflows.recursive_embedded_map + bounded providers",
        generation=2,
        providers=("binwalk", "lief"),
        guards=("never auto-open or render carved active content", "bounded recursion"),
    ),
    EngineeringFeature(
        "resource-diff-visualizer",
        "Resource, manifest, icon, and media difference viewer",
        "comparison",
        "Compare PE resources, Android resources, Apple bundle metadata, icons, images, and audio fingerprints across versions.",
        "read_only",
        "implemented-partial",
        "re_core.comparison structural diff + format-specific providers",
        generation=2,
        providers=("lief", "apktool", "exiftool"),
    ),
    EngineeringFeature(
        "firmware-partition-map",
        "Firmware image, filesystem, and partition map",
        "firmware",
        "Identify firmware headers, partition tables, filesystems, bootloaders, kernels, device trees, and embedded executables.",
        "read_only",
        "planned-provider",
        "file taxonomy extension point",
        generation=2,
        providers=("binwalk", "unblob", "ghidra"),
        guards=("no flashing or device write operations",),
    ),
    EngineeringFeature(
        "archive-safety-audit",
        "Archive bomb, path traversal, and unsafe-member audit",
        "container",
        "Inspect member counts, paths, compression ratios, overlaps, encryption flags, and nested-depth risks before extraction.",
        "read_only",
        "implemented",
        "re_core.advanced_workflows.archive_safety_audit",
        generation=2,
        guards=("inspect central directory before extraction", "no unsafe path writes"),
    ),
    EngineeringFeature(
        "signature-trust-assessment",
        "Authenticode, code-signing, entitlement, and trust assessment",
        "trust",
        "Record signature structure, certificate chain metadata, timestamps, entitlements, notarization evidence, and verification limitations.",
        "read_only",
        "implemented-partial",
        "re_core.advanced_workflows.signature_trust_assessment + verification providers",
        generation=2,
        providers=("lief", "osslsigncode", "codesign"),
        guards=("never claim trust from certificate presence alone",),
    ),
    EngineeringFeature(
        "debug-source-map",
        "PDB, DWARF, dSYM, source path, and build artifact map",
        "debug",
        "Extract debug identifiers, source paths, compilation units, build IDs, and symbol-server lookup plans without uploading samples.",
        "read_only",
        "implemented-partial",
        "re_core.advanced_pe + provider extension",
        generation=2,
        ida_tools=("type_query", "find_regex"),
        ida_resources=("ida://idb/metadata",),
        ghidra_tools=("list_classes", "list_methods"),
        providers=("lief",),
    ),
    EngineeringFeature(
        "exception-unwind-analysis",
        "Exception, unwind, SEH, and cleanup-flow analysis",
        "controlflow",
        "Map Windows SEH, C++ exceptions, DWARF unwind data, cleanup handlers, and non-local control transfers.",
        "read_only",
        "mapped-upstream",
        "host workflow plan",
        generation=2,
        ida_tools=("func_profile", "disasm", "xrefs_to"),
        ghidra_tools=("disassemble_function", "decompile_function_by_address"),
    ),
    EngineeringFeature(
        "concurrency-sync-analysis",
        "Threading, synchronization, IPC, and race-surface map",
        "behavior",
        "Find thread creation, locks, atomics, shared memory, pipes, RPC, callbacks, and candidate unsynchronized state.",
        "read_only",
        "planned-provider",
        "host workflow plan",
        generation=2,
        ida_tools=("imports", "callees", "xrefs_to"),
        ghidra_tools=("list_imports", "get_xrefs_to", "get_xrefs_from"),
    ),
    EngineeringFeature(
        "privilege-boundary-map",
        "Privilege, sandbox, broker, and trust-boundary map",
        "security",
        "Correlate token, capability, entitlement, IPC, service, driver, and broker transitions with reachable call sites.",
        "read_only",
        "planned-provider",
        "host workflow plan",
        generation=2,
        ida_tools=("imports", "xrefs_to", "callgraph"),
        ghidra_tools=("list_imports", "get_xrefs_to", "get_xrefs_from"),
        guards=("analysis only; do not generate privilege escalation",),
    ),
    EngineeringFeature(
        "dependency-risk-map",
        "Embedded dependency and supply-chain risk map",
        "dependencies",
        "Fingerprint static libraries, runtimes, package metadata, manifests, and version strings with confidence and coverage limits.",
        "read_only",
        "implemented-partial",
        "re_core.inventory + Syft/signature providers",
        generation=2,
        providers=("capa", "syft", "retdec-signatures"),
        guards=("fingerprint is not a complete SBOM",),
    ),
    EngineeringFeature(
        "patch-regression-verifier",
        "Patch regression and invariant verifier",
        "patch",
        "Re-run hashes, format checks, entry points, imports, target function context, signatures, and selected invariants after a patch.",
        "patch_plan",
        "implemented-partial",
        "re_core.comparison static regression checks + runtime test plan",
        generation=2,
        guards=("new output only", "expected bytes and source hash required"),
    ),
    EngineeringFeature(
        "analysis-coverage-metrics",
        "Analysis coverage, confidence, and unresolved-work dashboard",
        "quality",
        "Report analyzed functions, decompiler failures, unresolved indirect branches, unknown bytes, conflicts, truncation, and provider gaps.",
        "read_only",
        "implemented-partial",
        "re_core.advanced_workflows.analysis_coverage_metrics + host metrics",
        generation=2,
        ida_tools=("survey_binary", "list_funcs"),
        ghidra_tools=("list_functions", "get_current_function"),
    ),
    EngineeringFeature(
        "evidence-bundle-export",
        "Portable evidence bundle with manifest",
        "reporting",
        "Bundle reports, selected bytes, host exports, tool versions, hashes, limitations, and chain-of-custody metadata without samples by default.",
        "read_only",
        "implemented-partial",
        "re_core.reporting + host export assets",
        generation=2,
        guards=("exclude original samples by default", "no automatic upload"),
    ),
)


def feature_catalog(
    *, category: str = "", status: str = "", generation: int = 0
) -> dict[str, Any]:
    if generation not in {0, 1, 2}:
        raise ValueError("generation must be 0, 1, or 2")
    selected = [
        item
        for item in FEATURES
        if (not category or item.category == category)
        and (not status or item.status == status)
        and (not generation or item.generation == generation)
    ]
    return {
        "schema_version": "0.5.0",
        "count": len(selected),
        "generation": generation or "all",
        "status_counts": dict(sorted(Counter(item.status for item in selected).items())),
        "features": [asdict(item) for item in selected],
    }


def validate_feature_catalog() -> dict[str, Any]:
    """Validate feature ids, provider ids, and exact host tool/resource names."""
    from .adapters import GHIDRA_CAPABILITIES, IDA_CAPABILITIES
    from .external import PROVIDERS

    issues: list[dict[str, Any]] = []
    ids = [item.id for item in FEATURES]
    duplicates = sorted({feature_id for feature_id in ids if ids.count(feature_id) > 1})
    if duplicates:
        issues.append({"kind": "duplicate-feature-id", "values": duplicates})
    for generation in (1, 2):
        count = sum(item.generation == generation for item in FEATURES)
        if count != 25:
            issues.append(
                {"kind": "generation-size", "generation": generation, "count": count}
            )

    known_ida_tools = {
        name for capability in IDA_CAPABILITIES for name in capability.upstream_names
    }
    known_ida_resources = {
        uri for capability in IDA_CAPABILITIES for uri in capability.resource_uris
    }
    known_ghidra_tools = {
        name for capability in GHIDRA_CAPABILITIES for name in capability.upstream_names
    }
    known_ghidra_resources = {
        uri for capability in GHIDRA_CAPABILITIES for uri in capability.resource_uris
    }
    valid_statuses = {
        "implemented",
        "implemented-partial",
        "implemented-plan",
        "mapped-upstream",
        "provider-ready",
        "planned-provider",
        "planned-local",
    }
    valid_modes = {"read_only", "annotate", "patch_plan", "patch_apply", "debug"}
    for feature in FEATURES:
        if feature.status not in valid_statuses:
            issues.append(
                {"kind": "invalid-status", "feature": feature.id, "value": feature.status}
            )
        if feature.mode not in valid_modes:
            issues.append(
                {"kind": "invalid-mode", "feature": feature.id, "value": feature.mode}
            )
        for provider in feature.providers:
            if provider not in PROVIDERS:
                issues.append(
                    {"kind": "unknown-provider", "feature": feature.id, "value": provider}
                )
        for host, values, known in (
            ("ida", feature.ida_tools, known_ida_tools),
            ("ghidra", feature.ghidra_tools, known_ghidra_tools),
        ):
            for value in values:
                if "://" in value:
                    issues.append(
                        {
                            "kind": "resource-in-tool-list",
                            "feature": feature.id,
                            "host": host,
                            "value": value,
                        }
                    )
                elif value not in known:
                    issues.append(
                        {
                            "kind": "unknown-host-tool",
                            "feature": feature.id,
                            "host": host,
                            "value": value,
                        }
                    )
        for host, values, known in (
            ("ida", feature.ida_resources, known_ida_resources),
            ("ghidra", feature.ghidra_resources, known_ghidra_resources),
        ):
            for value in values:
                if value not in known:
                    issues.append(
                        {
                            "kind": "unknown-host-resource",
                            "feature": feature.id,
                            "host": host,
                            "value": value,
                        }
                    )
    return {
        "schema_version": "0.5.0",
        "valid": not issues,
        "feature_count": len(FEATURES),
        "generation_counts": {
            str(generation): sum(item.generation == generation for item in FEATURES)
            for generation in (1, 2)
        },
        "issues": issues,
    }


def build_feature_workflow(
    feature_id: str,
    *,
    host: str,
    sample: str = "",
    database: str = "",
    address: str = "",
    discovered_tools: Iterable[str] | None = None,
    discovered_resources: Iterable[str] | None = None,
    available_providers: Iterable[str] | None = None,
) -> dict[str, Any]:
    if host not in {"local", "ida", "ghidra"}:
        raise ValueError("host must be local, ida, or ghidra")
    feature = next((item for item in FEATURES if item.id == feature_id), None)
    if feature is None:
        raise ValueError(f"unknown feature: {feature_id}")
    host_tools = (
        feature.ida_tools
        if host == "ida"
        else feature.ghidra_tools
        if host == "ghidra"
        else ()
    )
    host_resources = (
        feature.ida_resources
        if host == "ida"
        else feature.ghidra_resources
        if host == "ghidra"
        else ()
    )
    discovered_tool_set = set(discovered_tools or ())
    discovered_resource_set = set(discovered_resources or ())
    discovery_performed = discovered_tools is not None or discovered_resources is not None

    if available_providers is None:
        from .external import provider_status

        available_provider_set = {
            item["id"] for item in provider_status() if item["available"]
        }
    else:
        available_provider_set = set(available_providers)
    if host == "ida":
        available_provider_set.add("ida")
    elif host == "ghidra":
        available_provider_set.add("ghidra")
    provider_candidates = set(feature.providers)
    available_candidates = sorted(provider_candidates & available_provider_set)
    missing_providers = sorted(provider_candidates - available_provider_set)
    missing_tools = sorted(set(host_tools) - discovered_tool_set)
    missing_resources = sorted(set(host_resources) - discovered_resource_set)

    if host == "local":
        status_map = {
            "implemented": "ready-local",
            "implemented-partial": "partial-local",
            "implemented-plan": "plan-only",
            "mapped-upstream": "host-required",
            "provider-ready": (
                "ready-with-provider" if available_candidates else "provider-required"
            ),
            "planned-provider": "planned-not-implemented",
            "planned-local": "planned-not-implemented",
        }
        workflow_status = status_map[feature.status]
    elif not host_tools and not host_resources:
        workflow_status = "capability-unavailable"
    elif not discovery_performed:
        workflow_status = "discovery-required"
    elif missing_tools or missing_resources:
        workflow_status = "capability-unavailable"
    elif feature.status in {"planned-provider", "planned-local"}:
        workflow_status = "planned-not-implemented"
    elif feature.status == "provider-ready" and provider_candidates and not available_candidates:
        workflow_status = "provider-required"
    elif feature.status == "implemented-partial":
        workflow_status = "partial-ready"
    elif feature.status == "implemented-plan":
        workflow_status = "plan-only"
    else:
        workflow_status = "ready-to-dispatch"
    return {
        "schema_version": "0.5.0",
        "feature": asdict(feature),
        "target": {
            "host": host,
            "sample": sample or None,
            "database": database or None,
            "address": address or None,
        },
        "tool_sequence": list(host_tools),
        "resource_sequence": list(host_resources),
        "discovery_performed": discovery_performed,
        "missing_tools": missing_tools if discovery_performed else [],
        "missing_resources": missing_resources if discovery_performed else [],
        "provider_candidates": list(feature.providers),
        "available_providers": available_candidates,
        "missing_providers": missing_providers,
        "guards": list(feature.guards),
        "status": workflow_status,
        "executed": False,
        "requirements": [
            "Discover live tools before sending requests.",
            "Fail closed on unknown mutating capabilities.",
            "Record hashes, tool versions, arguments, and limitations.",
        ],
    }
