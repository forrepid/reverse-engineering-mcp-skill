from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable
from urllib.parse import urlparse


class OperationClass(str, Enum):
    READ = "read"
    ANNOTATE = "annotate"
    PATCH = "patch"
    DEBUG = "debug"
    DYNAMIC = "dynamic"


@dataclass(frozen=True)
class Capability:
    normalized_name: str
    upstream_names: tuple[str, ...]
    operation_class: OperationClass
    resource_uris: tuple[str, ...] = ()


@dataclass
class CapabilityProfile:
    host: str
    capabilities: list[Capability]
    endpoint: str = ""
    discovered_tools: set[str] = field(default_factory=set)
    discovered_resources: set[str] = field(default_factory=set)

    def available(self) -> dict[str, bool]:
        return {
            capability.normalized_name: any(
                name in self.discovered_tools for name in capability.upstream_names
            )
            or any(uri in self.discovered_resources for uri in capability.resource_uris)
            for capability in self.capabilities
        }

    def classify(self, tool_name: str) -> OperationClass | None:
        """Classify a discovered MCP tool; unknown tools remain fail-closed."""
        for capability in self.capabilities:
            if tool_name in capability.upstream_names:
                return capability.operation_class
        return None

    def classify_resource(self, uri: str) -> OperationClass | None:
        """Classify a discovered MCP resource URI."""
        for capability in self.capabilities:
            if uri in capability.resource_uris:
                return capability.operation_class
        return None

    def unknown_tools(self) -> list[str]:
        known = {
            name
            for capability in self.capabilities
            for name in capability.upstream_names
        }
        return sorted(self.discovered_tools - known)

    def unknown_resources(self) -> list[str]:
        known = {
            uri for capability in self.capabilities for uri in capability.resource_uris
        }
        return sorted(self.discovered_resources - known)

    def available_resources(self) -> dict[str, str]:
        """Return discovered known resources and their fail-closed operation class."""
        return {
            uri: operation.value
            for uri in sorted(self.discovered_resources)
            if (operation := self.classify_resource(uri)) is not None
        }

    def require_loopback(self) -> None:
        if not self.endpoint:
            return
        parsed = urlparse(self.endpoint)
        host = parsed.hostname
        if not host:
            raise ValueError("adapter endpoint has no hostname")
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host.lower() == "localhost"
        if not is_loopback:
            raise ValueError("remote MCP endpoint requires an explicit secure profile")


# The aliases below cover the locally validated ida-pro-mcp 2.0.0 surfaces and
# retain a few older names so capability discovery can fail closed without
# breaking a reviewed older deployment.
IDA_CAPABILITIES = [
    Capability(
        "health",
        ("server_health", "idb_list", "idalib_list"),
        OperationClass.READ,
        ("ida://databases",),
    ),
    Capability("open_database", ("idb_open", "idalib_open"), OperationClass.READ),
    Capability(
        "switch_database", ("idalib_switch", "idb_switch"), OperationClass.READ
    ),
    Capability(
        "metadata",
        ("idb_metadata", "metadata"),
        OperationClass.READ,
        ("ida://idb/metadata",),
    ),
    Capability("segments", (), OperationClass.READ, ("ida://idb/segments",)),
    Capability("entrypoints", (), OperationClass.READ, ("ida://idb/entrypoints",)),
    Capability(
        "current_selection",
        (),
        OperationClass.READ,
        ("ida://cursor", "ida://selection"),
    ),
    Capability(
        "functions", ("list_funcs", "lookup_funcs", "func_query"), OperationClass.READ
    ),
    Capability("decompile", ("decompile", "force_recompile"), OperationClass.READ),
    Capability("disassemble", ("disasm",), OperationClass.READ),
    Capability("bytes", ("get_bytes", "get_int"), OperationClass.READ),
    Capability(
        "strings", ("get_string", "find_regex", "search_text"), OperationClass.READ
    ),
    Capability(
        "search",
        ("find_bytes", "find_insns", "find", "insn_query"),
        OperationClass.READ,
    ),
    Capability(
        "references",
        ("xrefs_to", "xref_query", "xrefs_to_field", "callees"),
        OperationClass.READ,
    ),
    Capability(
        "signatures",
        (
            "find_xref_signatures",
            "make_signature",
            "make_signature_for_function",
            "make_signature_for_range",
        ),
        OperationClass.READ,
    ),
    Capability(
        "analysis_bundle",
        (
            "analyze_funcs",
            "analyze_batch",
            "analyze_function",
            "analyze_component",
            "trace_data_flow",
            "func_profile",
            "survey_binary",
        ),
        OperationClass.READ,
    ),
    Capability("basic_blocks", ("basic_blocks",), OperationClass.READ),
    Capability("callgraph", ("callgraph",), OperationClass.READ),
    Capability("exports", ("export_funcs",), OperationClass.READ),
    Capability("imports", ("imports", "imports_query"), OperationClass.READ),
    Capability(
        "globals", ("list_globals", "entity_query", "get_global_value"), OperationClass.READ
    ),
    Capability("number_conversion", ("int_convert",), OperationClass.READ),
    Capability(
        "types_read",
        ("type_query", "type_inspect", "read_struct", "search_structs"),
        OperationClass.READ,
        ("ida://types", "ida://structs"),
    ),
    Capability("save_database", ("idb_save",), OperationClass.ANNOTATE),
    Capability("bookmarks", ("add_bookmark",), OperationClass.ANNOTATE),
    Capability("rename", ("rename",), OperationClass.ANNOTATE),
    Capability(
        "comments", ("set_comments", "append_comments"), OperationClass.ANNOTATE
    ),
    Capability(
        "types_write",
        (
            "set_type",
            "declare_type",
            "enum_upsert",
            "type_apply_batch",
            "infer_types",
            "set_op_type",
        ),
        OperationClass.ANNOTATE,
    ),
    Capability(
        "definitions",
        ("define_func", "define_code", "undefine", "make_data"),
        OperationClass.ANNOTATE,
    ),
    Capability(
        "stack",
        ("stack_frame", "declare_stack", "delete_stack"),
        OperationClass.ANNOTATE,
    ),
    Capability("patch", ("patch", "patch_asm", "put_int"), OperationClass.PATCH),
    Capability(
        "debug",
        (
            "dbg_start",
            "dbg_status",
            "dbg_exit",
            "dbg_continue",
            "dbg_run_to",
            "dbg_step_into",
            "dbg_step_over",
            "dbg_bps",
            "dbg_add_bp",
            "dbg_delete_bp",
            "dbg_toggle_bp",
            "dbg_set_bp_condition",
            "dbg_regs_all",
            "dbg_regs_remote",
            "dbg_regs",
            "dbg_gpregs_remote",
            "dbg_gpregs",
            "dbg_regs_named_remote",
            "dbg_regs_named",
            "dbg_stacktrace",
            "dbg_read",
            "dbg_write",
        ),
        OperationClass.DEBUG,
    ),
    Capability("arbitrary_python", ("py_eval", "py_exec_file"), OperationClass.DYNAMIC),
]


# LaurieWired/GhidraMCP main exposes both name- and address-based decompilers,
# plus class/method listing. It does not currently expose raw memory, patch,
# debugger, get_current_program, or set_global_data_type tools.
GHIDRA_CAPABILITIES = [
    Capability("health", ("ghidra_health",), OperationClass.READ),
    Capability(
        "current_selection",
        ("get_current_address", "get_current_function"),
        OperationClass.READ,
    ),
    Capability("segments", ("list_segments",), OperationClass.READ),
    Capability("classes", ("list_classes", "list_namespaces"), OperationClass.READ),
    Capability("methods", ("list_methods",), OperationClass.READ),
    Capability(
        "functions", ("list_functions", "get_function_by_address"), OperationClass.READ
    ),
    Capability(
        "decompile",
        ("decompile_function", "decompile_function_by_address"),
        OperationClass.READ,
    ),
    Capability("disassemble", ("disassemble_function",), OperationClass.READ),
    Capability("imports", ("list_imports",), OperationClass.READ),
    Capability("exports", ("list_exports",), OperationClass.READ),
    Capability("strings", ("list_strings",), OperationClass.READ),
    Capability(
        "references",
        ("get_xrefs_to", "get_xrefs_from", "get_function_xrefs"),
        OperationClass.READ,
    ),
    Capability("data_items", ("list_data_items",), OperationClass.READ),
    Capability("search_functions", ("search_functions_by_name",), OperationClass.READ),
    Capability(
        "rename",
        (
            "rename_function",
            "rename_function_by_address",
            "rename_data",
            "rename_variable",
        ),
        OperationClass.ANNOTATE,
    ),
    Capability(
        "comments",
        ("set_comment", "set_decompiler_comment", "set_disassembly_comment"),
        OperationClass.ANNOTATE,
    ),
    Capability(
        "types_write",
        ("set_function_prototype", "set_local_variable_type"),
        OperationClass.ANNOTATE,
    ),
]


def ida_profile(
    discovered_tools: Iterable[str] = (),
    endpoint: str = "http://127.0.0.1:8745/mcp",
    discovered_resources: Iterable[str] = (),
) -> CapabilityProfile:
    profile = CapabilityProfile(
        host="ida",
        capabilities=IDA_CAPABILITIES,
        endpoint=endpoint,
        discovered_tools=set(discovered_tools),
        discovered_resources=set(discovered_resources),
    )
    profile.require_loopback()
    return profile


def ghidra_profile(
    discovered_tools: Iterable[str] = (),
    endpoint: str = "http://127.0.0.1:8080/",
    discovered_resources: Iterable[str] = (),
) -> CapabilityProfile:
    profile = CapabilityProfile(
        host="ghidra",
        capabilities=GHIDRA_CAPABILITIES,
        endpoint=endpoint,
        discovered_tools=set(discovered_tools),
        discovered_resources=set(discovered_resources),
    )
    profile.require_loopback()
    return profile
