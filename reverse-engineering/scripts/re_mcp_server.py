from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import sys
from typing import Any

from re_core.advanced_pe import analyze_pe_deep
from re_core.advanced_workflows import execute_local_feature, local_feature_ids
from re_core.adapters import GHIDRA_CAPABILITIES, IDA_CAPABILITIES, CapabilityProfile
from re_core.broker_config import load_broker_config
from re_core.client_configs import client_profiles
from re_core.environment import (
    EnvironmentConfigError,
    environment_contract as build_environment_contract,
    load_runtime_environment,
    read_saved_settings,
    save_setting,
    settings_path,
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
from re_core.sandbox import create_sandbox_plan
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
        "tool_count": 24,
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
        return classify_file(runtime.validate_file(sample), max_file_size=runtime.max_file_bytes).to_dict()

    @mcp.tool()
    def deep_pe_triage(sample: str) -> dict[str, Any]:
        """Map PE entry point, static OEP hypotheses, boundaries, and triage indicators without execution."""
        return analyze_pe_deep(runtime.validate_file(sample), max_file_size=runtime.max_file_bytes, max_scan_bytes=runtime.max_scan_bytes)

    @mcp.tool()
    def oep_static_candidates(sample: str) -> dict[str, Any]:
        """Rank static PE entry-point hypotheses; never executes or runtime-verifies a sample."""
        result = analyze_pe_deep(
            runtime.validate_file(sample),
            max_file_size=runtime.max_file_bytes,
            max_scan_bytes=runtime.max_scan_bytes,
        )
        return {
            "source": result["source"],
            "architecture": result["pe"].get("architecture"),
            "image_base": result["pe"].get("image_base"),
            "declared_entry_point": result["declared_entry_point"],
            "oep_result": result["oep_result"],
            "oep_analysis": result["oep_analysis"],
            "mutation_performed": False,
        }

    @mcp.tool()
    def oep_runtime_plan(
        sample: str,
        provider: str,
        timeout_seconds: int = 300,
        network: str = "blocked",
        image_digest: str = "",
        snapshot_id: str = "",
        cpu_cores: int = 2,
        memory_mb: int = 2048,
        disk_mb: int = 4096,
    ) -> dict[str, Any]:
        """Create a bounded isolated-runtime OEP plan only; never submits or executes the sample."""
        source = runtime.validate_file(sample)
        plan = create_sandbox_plan(
            source,
            provider=provider,
            timeout_seconds=timeout_seconds,
            network=network,
            image_digest=image_digest or None,
            snapshot_id=snapshot_id or None,
            cpu_cores=cpu_cores,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
        )
        broker = load_broker_config().public_status()
        plan["broker_capture_contract"] = {
            **plan["broker_capture_contract"],
            "status": broker["status"],
            "provider": broker["provider"],
            "broker_id": broker["broker_id"],
            "capture_adapter": "not_implemented",
            "continuous_capture": False,
            "submission_enabled": False,
            "live_capture_ready": False,
            "note": "Plan preview only. No sample submission or execution is available through this MCP tool.",
        }
        plan["status"] = "plan_only"
        return plan

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
    def settings_read() -> dict[str, Any]:
        """Read saved overrides and currently effective runtime limits."""
        return {
            "path": str(settings_path()),
            "precedence": "process environment > saved settings > defaults",
            "saved_values": read_saved_settings(),
            "effective_values": load_runtime_environment().to_dict(),
        }

    @mcp.tool()
    def settings_update(key: str, value: int | None = None, delta: int | None = None) -> dict[str, Any]:
        """Persist one allowlisted runtime limit; provide exactly one of value or delta."""
        if (value is None) == (delta is None):
            raise ValueError("provide exactly one of value or delta")
        if value is not None:
            saved_path = save_setting(key, value)
        else:
            current = read_saved_settings().get(
                key, load_runtime_environment().to_dict().get(key)
            )
            if not isinstance(current, (int, str)) or not str(current).isdigit():
                raise ValueError(f"setting is not adjustable: {key}")
            if delta is None:
                raise ValueError("delta is required")
            saved_path = save_setting(key, int(current) + int(delta))
        return {
            "path": str(saved_path),
            "saved_values": read_saved_settings(),
            "effective_values": load_runtime_environment().to_dict(),
            "restart_required": True,
        }

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
            max_archive_members=runtime.max_archive_members,
            max_archive_expanded_bytes=runtime.max_archive_expanded_bytes,
            max_archive_member_ratio=runtime.max_archive_member_ratio,
            archive_timeout_seconds=runtime.archive_timeout_seconds,
            max_file_bytes=runtime.max_file_bytes,
            host_coverage=None,
        )

    @mcp.tool()
    def host_capability_coverage(
        host: str,
        tools: list[str],
        resources: list[str] | None = None,
        endpoint: str = "",
    ) -> dict[str, Any]:
        """Compute host coverage only from caller-supplied live discovery results."""
        if host not in {"ida", "ghidra"}:
            raise ValueError("host must be ida or ghidra")
        profile = CapabilityProfile(
            host,
            IDA_CAPABILITIES if host == "ida" else GHIDRA_CAPABILITIES,
            endpoint=endpoint,
            discovered_tools=set(tools),
            discovered_resources=set(resources or []),
        )
        profile.require_loopback()
        payload = profile.coverage_report()
        payload["available_tool_policy"] = {
            name: operation.value if (operation := profile.classify(name)) is not None else "unknown"
            for name in sorted(profile.discovered_tools)
        }
        return payload

    @mcp.tool()
    def system_readiness(
        ida_path: str = "",
        idalib_mcp: str = "",
        ghidra_home: str = "",
        ghidra_bridge: str = "",
        probe_ida: bool = False,
    ) -> dict[str, Any]:
        """Audit local dependencies and explicit IDA/Ghidra paths without launching hosts."""
        return build_readiness_report(
            runtime,
            ida_path=ida_path or None,
            idalib_mcp=idalib_mcp or None,
            ghidra_home=ghidra_home or None,
            ghidra_bridge=ghidra_bridge or None,
            probe_ida=probe_ida,
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
