from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import sys
from typing import Any

from re_core.advanced_pe import analyze_pe_deep
from re_core.advanced_workflows import execute_local_feature, local_feature_ids
from re_core.client_configs import client_profiles
from re_core.environment import (
    EnvironmentConfigError,
    environment_contract as build_environment_contract,
    load_runtime_environment,
)
from re_core.external import provider_status, run_provider
from re_core.feature_catalog import (
    build_feature_workflow,
    feature_catalog,
    validate_feature_catalog,
)
from re_core.file_types import classify_file
from re_core.patching import create_patch_plan
from re_core.readiness import build_readiness_report
from re_core.selection import (
    build_dump_plan,
    build_source_operation_plan,
    inspect_file_region,
    inspect_text_lines,
)
from re_core.source_edit import create_source_edit_plan
from re_core.transforms import entropy_windows, scan_single_byte_xor


def server_status() -> dict[str, Any]:
    runtime = load_runtime_environment()
    environment = build_environment_contract()
    return {
        "schema_version": "0.5.0",
        "name": "reverse-engineering-companion",
        "transport": "stdio",
        "mcp_importable": importlib.util.find_spec("mcp") is not None,
        "tool_count": 19,
        "default_mode": "read_only",
        "writes_exposed": False,
        "unsafe_tools_exposed": False,
        "environment": environment,
        "feature_catalog": validate_feature_catalog(),
        "local_feature_ids": list(local_feature_ids()),
        "providers": provider_status(runtime.provider_config),
    }


def build_server() -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as error:
        raise RuntimeError(
            "The optional MCP Python SDK is unavailable. Use the CLI or install a reviewed, pinned mcp package."
        ) from error

    runtime = load_runtime_environment()
    log_level = getattr(logging, runtime.log_level)
    for logger_name in ("", "mcp", "fastmcp"):
        logging.getLogger(logger_name).setLevel(log_level)
    mcp = FastMCP("reverse-engineering-companion")

    @mcp.tool()
    def classify_artifact(sample: str) -> dict[str, Any]:
        """Classify a local artifact from magic, structure, container, and bounded indicators."""
        return classify_file(runtime.validate_file(sample)).to_dict()

    @mcp.tool()
    def deep_pe_triage(sample: str) -> dict[str, Any]:
        """Map PE entry point, boundaries, indicators, injection primitives, and obfuscation candidates."""
        return analyze_pe_deep(runtime.validate_file(sample))

    @mcp.tool()
    def inspect_binary_selection(
        sample: str,
        offset: int,
        length: int,
        architecture: str = "",
        base_address: int | None = None,
    ) -> dict[str, Any]:
        """Inspect a bounded file-offset region without modifying the source."""
        runtime.validate_region(length)
        return inspect_file_region(
            runtime.validate_file(sample),
            offset=offset,
            length=length,
            architecture=architecture or None,
            base_address=base_address,
        )

    @mcp.tool()
    def inspect_source_lines(
        source: str, start_line: int, end_line: int
    ) -> dict[str, Any]:
        """Extract lexical features from a bounded UTF-8 source line selection."""
        return inspect_text_lines(
            runtime.validate_file(source),
            start_line=start_line,
            end_line=end_line,
        )

    @mcp.tool()
    def xor_decode_candidates(
        sample: str, offset: int, length: int, limit: int = 10
    ) -> dict[str, Any]:
        """Rank the bounded single-byte XOR keyspace for a selected local region."""
        runtime.validate_region(length)
        return scan_single_byte_xor(
            runtime.validate_file(sample), offset=offset, length=length, limit=limit
        )

    @mcp.tool()
    def entropy_region_candidates(
        sample: str,
        offset: int = 0,
        length: int | None = None,
        window: int = 4096,
        threshold: float = 7.2,
    ) -> dict[str, Any]:
        """Locate high-entropy windows as compression/encryption/packing candidates."""
        source = runtime.validate_file(sample)
        selected_length = source.stat().st_size - offset if length is None else length
        runtime.validate_scan(selected_length)
        return entropy_windows(
            source,
            offset=offset,
            length=length,
            window=window,
            threshold=threshold,
        )

    @mcp.tool()
    def engineering_features(
        category: str = "", status: str = "", generation: int = 0
    ) -> dict[str, Any]:
        """List the 50 versioned reverse-engineering feature contracts."""
        return feature_catalog(
            category=category,
            status=status,
            generation=generation,
        )

    @mcp.tool()
    def supported_mcp_clients() -> dict[str, Any]:
        """List supported client config formats and documented merge targets."""
        return client_profiles()

    @mcp.tool()
    def runtime_environment() -> dict[str, Any]:
        """Show the allowlisted RE_MCP environment contract and effective safe values."""
        return build_environment_contract()

    @mcp.tool()
    def feature_workflow_plan(
        feature_id: str,
        host: str,
        sample: str = "",
        database: str = "",
        address: str = "",
        discovered_tools: list[str] | None = None,
        discovered_resources: list[str] | None = None,
    ) -> dict[str, Any]:
        """Build a local, IDA, or Ghidra workflow plan without sending it."""
        validated_sample = str(runtime.validate_file(sample)) if sample else ""
        return build_feature_workflow(
            feature_id,
            host=host,
            sample=validated_sample,
            database=database,
            address=address,
            discovered_tools=discovered_tools,
            discovered_resources=discovered_resources,
        )

    @mcp.tool()
    def feature_catalog_check() -> dict[str, Any]:
        """Validate all 50 feature contracts against provider and host capability registries."""
        return validate_feature_catalog()

    @mcp.tool()
    def provider_preflight() -> dict[str, Any]:
        """Detect configured static providers without launching or scanning a sample."""
        records = provider_status(runtime.provider_config)
        return {
            "schema_version": "0.5.0",
            "providers": records,
            "available": [item["id"] for item in records if item["available"]],
            "runnable": [item["id"] for item in records if item["runnable"]],
            "host_note": "IDA/Ghidra host providers require live MCP tool discovery.",
        }

    @mcp.tool()
    def run_static_provider(
        provider: str,
        sample: str,
        rule_path: str = "",
    ) -> dict[str, Any]:
        """Run one allowlisted non-executing static provider with timeout and output limits."""
        return run_provider(
            provider,
            runtime.validate_file(sample),
            rule_path=rule_path or None,
            config_path=runtime.provider_config,
            timeout_seconds=runtime.provider_timeout_seconds,
            max_output_bytes=runtime.max_provider_output_bytes,
        )

    @mcp.tool()
    def local_feature_analysis(
        feature_id: str,
        sample: str,
        second_sample: str = "",
    ) -> dict[str, Any]:
        """Execute an allowlisted, bounded, non-mutating local engineering feature."""
        source = runtime.validate_file(sample)
        other = runtime.validate_file(second_sample) if second_sample else None
        return execute_local_feature(
            feature_id,
            source,
            second_sample=other,
            max_scan_bytes=runtime.max_scan_bytes,
        )

    @mcp.tool()
    def system_readiness(
        ida_path: str = "",
        idalib_mcp: str = "",
        ghidra_home: str = "",
        ghidra_bridge: str = "",
    ) -> dict[str, Any]:
        """Audit local dependencies and explicit IDA/Ghidra paths without launching hosts."""
        return build_readiness_report(
            runtime,
            ida_path=ida_path or None,
            idalib_mcp=idalib_mcp or None,
            ghidra_home=ghidra_home or None,
            ghidra_bridge=ghidra_bridge or None,
        )

    @mcp.tool()
    def source_operation_plan(
        host: str,
        operation: str,
        address: str = "",
        end: str = "",
        database: str = "",
        target_language: str = "",
    ) -> dict[str, Any]:
        """Plan view, extract, translate, save, or approval-gated source/binary changes."""
        return build_source_operation_plan(
            host=host,
            operation=operation,
            address=address or None,
            end=end or None,
            database=database,
            target_language=target_language,
        )

    @mcp.tool()
    def dump_request_plan(
        host: str,
        kind: str,
        address: str,
        length: int,
        database: str = "",
    ) -> dict[str, Any]:
        """Create a bounded static or approval-gated runtime dump request plan."""
        runtime.validate_scan(length)
        return build_dump_plan(
            host=host,
            kind=kind,
            address=address,
            length=length,
            database=database,
        )

    @mcp.tool()
    def byte_patch_plan(
        sample: str,
        offset: int,
        expected: str,
        replacement: str,
        rationale: str = "",
    ) -> dict[str, Any]:
        """Create a sealed length-preserving byte patch plan; do not apply it."""
        return create_patch_plan(
            runtime.validate_file(sample),
            offset=offset,
            expected=expected,
            replacement=replacement,
            rationale=rationale,
        ).to_dict()

    @mcp.tool()
    def source_change_plan(
        source: str,
        mode: str,
        start_line: int,
        end_line: int,
        replacement_text: str,
        rationale: str = "",
        target_language: str = "",
    ) -> dict[str, Any]:
        """Create a sealed UTF-8 source replace/insert plan; do not write it."""
        return create_source_edit_plan(
            runtime.validate_file(source),
            mode=mode,
            start_line=start_line,
            end_line=end_line,
            replacement_text=replacement_text,
            rationale=rationale,
            target_language=target_language,
        ).to_dict()

    return mcp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only/planning companion MCP for the reverse-engineering skill."
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check:
            status = server_status()
            print(json.dumps(status, indent=2))
            return 0 if status["mcp_importable"] else 2
        build_server().run()
        return 0
    except EnvironmentConfigError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
