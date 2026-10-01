from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from .advanced_pe import AdvancedPeError, analyze_pe_deep
from .advanced_workflows import AdvancedWorkflowError, execute_local_feature
from .adapters import CapabilityProfile, GHIDRA_CAPABILITIES, IDA_CAPABILITIES, ghidra_profile, ida_profile
from .analyzers import (
    AnalysisError,
    StaticAnalyzer,
    bitdump,
    hexdump,
    parse_int,
    search_hex,
    search_text,
)
from .comparison import compare_files
from .client_configs import (
    CLIENTS,
    ClientConfigError,
    client_profiles,
    render_all_client_configs,
)
from .disassembly import DisassemblyError, disassemble_file
from .external import ProviderError, provider_status, run_provider
from .environment import (
    EnvironmentConfigError,
    ENVIRONMENT_VARIABLES,
    environment_contract,
    load_runtime_environment,
    SETTINGS_KEYS,
    resolve_config_environment,
    read_saved_settings,
    save_setting,
    settings_path,
)
from .feature_catalog import (
    build_feature_workflow,
    feature_catalog,
    validate_feature_catalog,
)
from .file_types import FileTypeError, classify_file
from .ida_installation import (
    IdaInstallationError,
    build_idalib_profile,
    detect_ida_installation,
)
from .ida_live import (
    IdaLiveError,
    build_context_requests,
    create_project_deeplink,
    requests_to_dict,
)
from .inventory import build_binary_inventory
from .mcp_supervisor import McpSupervisorError, build_mcp_launch_plan
from .patching import (
    PatchError,
    apply_patch_plan,
    create_patch_plan,
    load_patch_plan,
    save_patch_plan,
)
from .patch_impact import PatchImpactError, preview_patch_impact
from .reporting import write_reports
from .readiness import build_readiness_report
from .sandbox import create_sandbox_plan
from .runtime_oep import verify_runtime_oep_evidence
from .selection import (
    SelectionError,
    build_dump_plan,
    build_host_selection_plan,
    build_source_operation_plan,
    inspect_file_region,
    inspect_text_lines,
)
from .session import host_snapshot, watch_host_transitions
from .snapshots import SnapshotError, build_restore_plan, create_idb_snapshot
from .source_edit import (
    SourceEditError,
    apply_source_edit_plan,
    create_source_edit_plan,
    load_source_edit_plan,
    save_source_edit_plan,
)
from .transforms import (
    TransformError,
    entropy_windows,
    scan_single_byte_xor,
    transform_region_to_file,
)


def _write_json(payload: Any, output: str | Path) -> str:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(path.resolve())


def _emit_json(
    payload: Any,
    output: str | Path | None = None,
    *,
    label: str = "output",
) -> None:
    if output:
        saved = _write_json(payload, output)
        print(json.dumps({label: saved}, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))


def _read_window(path: str | Path, offset: int, length: int) -> bytes:
    if offset < 0:
        raise ValueError("offset cannot be negative")
    if length < 1 or length > 1024 * 1024:
        raise ValueError("length must be between 1 and 1048576")
    with Path(path).open("rb") as stream:
        stream.seek(offset)
        return stream.read(length)


def _cmd_analyze(args: argparse.Namespace) -> int:
    result = StaticAnalyzer(
        min_string_length=args.min_string_length,
        max_strings=args.max_strings,
        max_file_size=load_runtime_environment().max_file_bytes,
        max_scan_bytes=load_runtime_environment().max_scan_bytes,
    ).analyze(args.sample)
    provider_records: list[dict[str, Any]] = []
    for provider in args.external:
        try:
            provider_result = run_provider(
                provider,
                args.sample,
                timeout_seconds=args.provider_timeout,
            )
            provider_records.append(
                {
                    "name": provider,
                    "status": "completed",
                    "result": provider_result,
                }
            )
        except ProviderError as error:
            result.limitations.append(f"provider {provider}: {error}")
            provider_records.append(
                {"name": provider, "status": "unavailable", "error": str(error)}
            )
    if provider_records:
        result.summary["providers"] = provider_records
    paths = write_reports(result, args.output_dir)
    print(json.dumps({"run_id": result.run_id, "reports": paths}, indent=2))
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    data = _read_window(args.sample, args.offset, args.length)
    print(hexdump(data, base_offset=args.offset, width=args.width))
    if args.bits:
        print()
        print("BITS")
        print(bitdump(data, base_offset=args.offset))
    return 0


def _cmd_search(args: argparse.Namespace) -> int:
    if not args.hex_pattern and not args.text:
        raise ValueError("provide --hex and/or --text")
    sample_path = Path(args.sample)
    if sample_path.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("search input exceeds the 512 MiB safety limit")
    data = sample_path.read_bytes()
    payload: dict[str, Any] = {"sample": str(Path(args.sample).resolve())}
    if args.hex_pattern:
        offsets = search_hex(data, args.hex_pattern, limit=args.limit)
        payload["hex"] = {
            "pattern": args.hex_pattern,
            "matches": [
                {"offset": offset, "hex": f"0x{offset:X}"} for offset in offsets
            ],
        }
    if args.text:
        payload["text"] = {
            "pattern": args.text,
            "matches": search_text(
                data,
                args.text,
                ignore_case=args.ignore_case,
                limit=args.limit,
            ),
        }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    output_path = Path(args.output).resolve()
    if output_path in {Path(args.left).resolve(), Path(args.right).resolve()}:
        raise ValueError("comparison output cannot overwrite an input")
    payload = compare_files(
        args.left,
        args.right,
        analyzer=StaticAnalyzer(max_file_size=load_runtime_environment().max_file_bytes, max_scan_bytes=load_runtime_environment().max_scan_bytes),
        diff_range_limit=args.limit,
    )
    output = _write_json(payload, args.output)
    print(json.dumps({"comparison": output, "identical": payload["identical"]}, indent=2))
    return 0


def _cmd_disasm(args: argparse.Namespace) -> int:
    payload = disassemble_file(
        args.sample,
        architecture=args.architecture,
        offset=args.offset,
        length=args.length,
        base_address=args.base_address,
        max_instructions=args.limit,
    )
    if args.output:
        output = _write_json(payload, args.output)
        print(json.dumps({"disassembly": output}, indent=2))
    else:
        print(json.dumps(payload, indent=2))
    return 0


def _cmd_patch_plan(args: argparse.Namespace) -> int:
    plan = create_patch_plan(
        args.sample,
        offset=args.offset,
        expected=args.expected,
        replacement=args.replacement,
        rationale=args.rationale,
    )
    output = save_patch_plan(plan, args.output)
    print(
        json.dumps(
            {
                "plan": str(output),
                "source_sha256": plan.source_sha256,
                "plan_digest": plan.plan_digest,
                "status": "planned-not-applied",
            },
            indent=2,
        )
    )
    return 0


def _cmd_patch_apply(args: argparse.Namespace) -> int:
    result = apply_patch_plan(
        args.sample,
        load_patch_plan(args.plan),
        confirm_sha256=args.confirm_sha256,
        output=args.output,
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_sandbox_plan(args: argparse.Namespace) -> int:
    plan = create_sandbox_plan(
        args.sample,
        provider=args.provider,
        timeout_seconds=args.timeout,
        network=args.network,
        image_digest=args.image_digest,
        snapshot_id=args.snapshot_id,
        cpu_cores=args.cpu_cores,
        memory_mb=args.memory_mb,
        disk_mb=args.disk_mb,
        max_trace_bytes=args.max_trace_bytes,
        max_dump_bytes=args.max_dump_bytes,
    )
    if Path(args.output).resolve() == Path(args.sample).resolve():
        raise ValueError("sandbox-plan output cannot overwrite the sample")
    output = _write_json(plan, args.output)
    print(json.dumps({"plan": output, "status": plan["status"]}, indent=2))
    return 0


def _cmd_oep_runtime_verify(args: argparse.Namespace) -> int:
    result = verify_runtime_oep_evidence(
        args.sample,
        args.plan,
        args.trace,
        args.dump,
        args.attestation,
        args.broker_public_key,
        trusted_broker_id=args.trusted_broker_id,
        confirm_plan_sha256=args.confirm_plan_sha256,
    )
    _emit_json(result, args.output, label="oep_runtime_verification")
    return 0 if result["status"] == "verified" else 2


def _cmd_tools(args: argparse.Namespace) -> int:
    print(json.dumps(provider_status(args.provider_config), indent=2))
    return 0


def _cmd_provider_run(args: argparse.Namespace) -> int:
    payload = run_provider(
        args.provider,
        args.sample,
        rule_path=args.rule,
        config_path=args.provider_config,
        timeout_seconds=args.timeout,
        max_output_bytes=args.max_output_bytes,
    )
    _emit_json(payload, args.output, label="provider_result")
    return 0


def _cmd_hosts(args: argparse.Namespace) -> int:
    if not args.watch:
        print(json.dumps(host_snapshot(timeout=args.timeout), indent=2))
        return 0
    for event in watch_host_transitions(
        interval=args.interval,
        duration=args.duration,
        timeout=args.timeout,
    ):
        print(json.dumps(event, ensure_ascii=False), flush=True)
    return 0


def _cmd_capabilities(args: argparse.Namespace) -> int:
    profile = (
        ida_profile(args.tools, endpoint=args.endpoint, discovered_resources=args.resources)
        if args.host == "ida"
        else ghidra_profile(
            args.tools, endpoint=args.endpoint, discovered_resources=args.resources
        )
    )
    print(
        json.dumps(
            {
                "host": profile.host,
                "endpoint": profile.endpoint,
                "available": profile.available(),
                "unknown_tools_fail_closed": profile.unknown_tools(),
                "available_resources": profile.available_resources(),
                "unknown_resources_fail_closed": profile.unknown_resources(),
            },
            indent=2,
        )
    )
    return 0


def _cmd_ida_profile(args: argparse.Namespace) -> int:
    if args.python:
        payload = build_idalib_profile(
            args.ida,
            python_executable=args.python,
            include_hashes=not args.no_hashes,
        )
    else:
        payload = detect_ida_installation(
            args.ida,
            include_hashes=not args.no_hashes,
        ).to_dict()
    _emit_json(payload, args.output, label="ida_profile")
    return 0


def _cmd_idalib_plan(args: argparse.Namespace) -> int:
    profile = build_idalib_profile(
        args.ida,
        python_executable=args.python,
        include_hashes=not args.no_hashes,
    )
    launch = build_mcp_launch_plan(
        transport=args.transport,
        executable=args.mcp_executable,
        host=args.host,
        port=args.port,
        max_workers=args.max_workers,
        isolated_contexts=True,
    )
    payload = {
        "schema_version": "0.5.0",
        "installation_profile": profile,
        "mcp_launch_plan": launch.to_dict(),
        "status": "preview-only-not-started",
        "automatic_execution": False,
    }
    _emit_json(payload, args.output, label="idalib_plan")
    return 0


def _cmd_ida_context_plan(args: argparse.Namespace) -> int:
    payload = {
        "schema_version": "0.5.0",
        "database": args.database,
        "address": f"0x{args.address:X}",
        "requests": requests_to_dict(
            build_context_requests(
                database=args.database,
                address=args.address,
                byte_count=args.byte_count,
            )
        ),
        "status": "planned-not-sent",
        "mutation_performed": False,
    }
    _emit_json(payload, args.output, label="context_plan")
    return 0


def _cmd_ida_deeplink(args: argparse.Namespace) -> int:
    payload = {
        "database": args.database,
        "address": f"0x{args.address:X}",
        "view": args.view,
        "deeplink": create_project_deeplink(
            database=args.database,
            address=args.address,
            view=args.view,
        ),
        "scheme_scope": "project-local",
    }
    _emit_json(payload, args.output, label="deeplink")
    return 0


def _cmd_snapshot_idb(args: argparse.Namespace) -> int:
    payload = create_idb_snapshot(
        args.idb,
        args.output_dir,
        confirm_saved=args.confirm_saved,
        label=args.label,
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_snapshot_restore_plan(args: argparse.Namespace) -> int:
    payload = build_restore_plan(args.manifest, args.target)
    _emit_json(payload, args.output, label="restore_plan")
    return 0


def _cmd_patch_impact(args: argparse.Namespace) -> int:
    payload = preview_patch_impact(
        args.sample,
        load_patch_plan(args.plan),
        architecture=args.architecture,
        disassembly_window=args.disassembly_window,
    )
    if args.output and Path(args.output).resolve() == Path(args.sample).resolve():
        raise ValueError("patch-impact output cannot overwrite the sample")
    _emit_json(payload, args.output, label="patch_impact")
    return 0


def _cmd_inventory(args: argparse.Namespace) -> int:
    runtime = load_runtime_environment()
    payload = build_binary_inventory(
        args.sample,
        max_file_bytes=runtime.max_file_bytes,
        max_scan_bytes=runtime.max_scan_bytes,
    )
    if args.output and Path(args.output).resolve() == Path(args.sample).resolve():
        raise ValueError("inventory output cannot overwrite the sample")
    _emit_json(payload, args.output, label="inventory")
    return 0


def _cmd_classify(args: argparse.Namespace) -> int:
    payload = classify_file(args.sample, max_file_size=load_runtime_environment().max_file_bytes).to_dict()
    if args.output and Path(args.output).resolve() == Path(args.sample).resolve():
        raise ValueError("classification output cannot overwrite the sample")
    _emit_json(payload, args.output, label="classification")
    return 0


def _cmd_pe_deep(args: argparse.Namespace) -> int:
    runtime = load_runtime_environment()
    payload = analyze_pe_deep(
        args.sample,
        max_file_size=runtime.max_file_bytes,
        max_scan_bytes=runtime.max_scan_bytes,
    )
    if args.output and Path(args.output).resolve() == Path(args.sample).resolve():
        raise ValueError("PE triage output cannot overwrite the sample")
    _emit_json(payload, args.output, label="pe_deep")
    return 0


def _cmd_region(args: argparse.Namespace) -> int:
    payload = inspect_file_region(
        args.sample,
        offset=args.offset,
        length=args.length,
        architecture=args.architecture,
        base_address=args.base_address,
    )
    _emit_json(payload, args.output, label="region")
    return 0


def _cmd_text_selection(args: argparse.Namespace) -> int:
    payload = inspect_text_lines(
        args.source,
        start_line=args.start_line,
        end_line=args.end_line,
    )
    _emit_json(payload, args.output, label="text_selection")
    return 0


def _cmd_entropy_map(args: argparse.Namespace) -> int:
    payload = entropy_windows(
        args.sample,
        offset=args.offset,
        length=args.length,
        window=args.window,
        threshold=args.threshold,
        limit=args.limit,
    )
    _emit_json(payload, args.output, label="entropy_map")
    return 0


def _cmd_xor_scan(args: argparse.Namespace) -> int:
    payload = scan_single_byte_xor(
        args.sample,
        offset=args.offset,
        length=args.length,
        limit=args.limit,
    )
    _emit_json(payload, args.output, label="xor_scan")
    return 0


def _cmd_transform_region(args: argparse.Namespace) -> int:
    payload = transform_region_to_file(
        args.sample,
        offset=args.offset,
        length=args.length,
        operation=args.operation,
        key=args.key,
        output=args.output,
        confirm_sha256=args.confirm_sha256,
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_host_selection(args: argparse.Namespace) -> int:
    payload = build_host_selection_plan(
        host=args.host,
        address=args.address,
        end=args.end,
        database=args.database,
    )
    _emit_json(payload, args.output, label="host_selection")
    return 0


def _cmd_source_operation(args: argparse.Namespace) -> int:
    payload = build_source_operation_plan(
        host=args.host,
        operation=args.operation,
        address=args.address,
        end=args.end,
        database=args.database,
        target_language=args.target_language,
    )
    _emit_json(payload, args.output, label="source_operation")
    return 0


def _cmd_dump_plan(args: argparse.Namespace) -> int:
    payload = build_dump_plan(
        host=args.host,
        kind=args.kind,
        address=args.address,
        length=args.length,
        database=args.database,
    )
    _emit_json(payload, args.output, label="dump_plan")
    return 0


def _cmd_source_edit_plan(args: argparse.Namespace) -> int:
    replacement_path = Path(args.replacement_file).resolve()
    if not replacement_path.is_file() or replacement_path.stat().st_size > 4 * 1024 * 1024:
        raise SourceEditError("replacement file must exist and be no larger than 4 MiB")
    replacement = replacement_path.read_text(encoding="utf-8")
    plan = create_source_edit_plan(
        args.source,
        mode=args.mode,
        start_line=args.start_line,
        end_line=args.end_line,
        replacement_text=replacement,
        rationale=args.rationale,
        target_language=args.target_language,
    )
    output = save_source_edit_plan(plan, args.output)
    print(
        json.dumps(
            {
                "plan": str(output),
                "source_sha256": plan.source_sha256,
                "plan_digest": plan.plan_digest,
                "status": "planned-not-applied",
            },
            indent=2,
        )
    )
    return 0


def _cmd_source_edit_apply(args: argparse.Namespace) -> int:
    payload = apply_source_edit_plan(
        args.source,
        load_source_edit_plan(args.plan),
        confirm_sha256=args.confirm_sha256,
        output=args.output,
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_features(args: argparse.Namespace) -> int:
    payload = feature_catalog(
        category=args.category,
        status=args.status,
        generation=args.generation,
    )
    _emit_json(payload, args.output, label="feature_catalog")
    return 0


def _cmd_feature_plan(args: argparse.Namespace) -> int:
    payload = build_feature_workflow(
        args.feature,
        host=args.host,
        sample=args.sample,
        database=args.database,
        address=args.address,
        discovered_tools=args.discovered_tools,
        discovered_resources=args.discovered_resources,
    )
    _emit_json(payload, args.output, label="feature_plan")
    return 0


def _cmd_feature_check(args: argparse.Namespace) -> int:
    payload = validate_feature_catalog()
    _emit_json(payload, args.output, label="feature_check")
    return 0 if payload["valid"] else 2


def _cmd_feature_run(args: argparse.Namespace) -> int:
    payload = execute_local_feature(
        args.feature,
        args.sample,
        second_sample=args.second_sample,
        max_scan_bytes=load_runtime_environment().max_scan_bytes,
        max_archive_members=load_runtime_environment().max_archive_members,
        max_archive_expanded_bytes=load_runtime_environment().max_archive_expanded_bytes,
        max_archive_member_ratio=load_runtime_environment().max_archive_member_ratio,
        archive_timeout_seconds=load_runtime_environment().archive_timeout_seconds,
        max_file_bytes=load_runtime_environment().max_file_bytes,
        host_coverage=args.host_coverage,
    )
    _emit_json(payload, args.output, label="feature_result")
    return 0


def _cmd_client_profiles(args: argparse.Namespace) -> int:
    _emit_json(client_profiles(), args.output, label="client_profiles")
    return 0


def _cmd_env_show(args: argparse.Namespace) -> int:
    _emit_json(environment_contract(), args.output, label="environment_contract")
    return 0


def _cmd_env_check(args: argparse.Namespace) -> int:
    environment = resolve_config_environment(
        assignments=args.env,
        env_file=args.env_file,
    )
    payload = environment_contract(environment)
    payload["status"] = "valid"
    _emit_json(payload, args.output, label="environment_check")
    return 0


def _cmd_settings(args: argparse.Namespace) -> int:
    if args.settings_action == "set":
        saved_path = save_setting(args.key, args.value)
    elif args.settings_action == "adjust":
        current = read_saved_settings().get(
            args.key, str(load_runtime_environment().to_dict()[args.key])
        )
        saved_path = save_setting(args.key, int(current) + args.delta)
    elif args.settings_action == "reset":
        saved = read_saved_settings()
        if args.key:
            if args.key not in SETTINGS_KEYS:
                raise EnvironmentConfigError(f"unknown setting: {args.key}")
            saved.pop(args.key, None)
        else:
            saved.clear()
        target = settings_path()
        if saved:
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=target.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump({"schema_version": "1", "values": saved}, stream, indent=2)
                    stream.write("\n")
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        elif target.exists():
            target.unlink()
        saved_path = target
    else:
        saved_path = settings_path()
    runtime = load_runtime_environment()
    payload = {
        "path": str(saved_path),
        "precedence": "process environment > saved settings > defaults",
        "saved_values": read_saved_settings(),
        "effective_values": runtime.to_dict(),
        "adjustable_settings": [
            {
                "key": key,
                "environment_variable": env_name,
                "minimum": next(item.minimum for item in ENVIRONMENT_VARIABLES if item.name == env_name),
                "maximum": next(item.maximum for item in ENVIRONMENT_VARIABLES if item.name == env_name),
                "default": next(item.default for item in ENVIRONMENT_VARIABLES if item.name == env_name),
            }
            for key, env_name in SETTINGS_KEYS.items()
        ],
    }
    _emit_json(payload)
    return 0


def _cmd_client_configs(args: argparse.Namespace) -> int:
    payload = render_all_client_configs(
        args.output_dir,
        python_executable=args.python,
        companion_script=args.companion_script,
        idalib_mcp=args.idalib_mcp,
        ghidra_bridge=args.ghidra_bridge,
        ghidra_server=args.ghidra_server,
        clients=args.clients,
        max_workers=args.max_workers,
        env_assignments=args.env,
        env_file=args.env_file,
        force=args.force,
        host_profile=args.host_profile,
        confirm_read_write=args.confirm_read_write,
        ghidra_token=args.ghidra_token or os.environ.get(args.ghidra_token_env),
        ida_profile_path=args.ida_profile_file,
        ghidra_token_env=args.ghidra_token_env,
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    runtime = load_runtime_environment()
    payload = build_readiness_report(
        runtime,
        ida_path=args.ida,
        idalib_mcp=args.idalib_mcp,
        ghidra_home=args.ghidra_home,
        ghidra_bridge=args.ghidra_bridge,
        ghidra_server=args.ghidra_server,
        ghidra_token=os.environ.get("RE_GHIDRA_TOKEN"),
        probe_ida=args.probe_ida,
    )
    _emit_json(payload, args.output, label="readiness")
    return 0 if payload["summary"]["local_companion_ready"] else 2


def _cmd_host_coverage(args: argparse.Namespace) -> int:
    capabilities = IDA_CAPABILITIES if args.host == "ida" else GHIDRA_CAPABILITIES
    profile = CapabilityProfile(args.host, capabilities, endpoint=args.endpoint, discovered_tools=set(args.tool), discovered_resources=set(args.resource))
    if args.endpoint:
        profile.require_loopback()
    payload = profile.coverage_report()
    payload["tool_policy"] = profile.policy_report(args.profile)
    _emit_json(payload, args.output, label="host_coverage")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-cli",
        description="Safe standalone primitives for the reverse-engineering skill.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Run static triage and reports")
    analyze.add_argument("sample")
    analyze.add_argument("--output-dir", required=True)
    analyze.add_argument("--min-string-length", type=int, default=4)
    analyze.add_argument("--max-strings", type=int, default=5000)
    analyze.add_argument(
        "--external",
        nargs="*",
        choices=("die", "capa", "floss"),
        default=[],
        help="Optional local, allowlisted detectors; never uploads automatically",
    )
    analyze.add_argument("--provider-timeout", type=int, default=120)
    analyze.set_defaults(handler=_cmd_analyze)

    inspect = subparsers.add_parser("inspect", help="Show bounded hex/byte/bit view")
    inspect.add_argument("sample")
    inspect.add_argument("--offset", type=parse_int, default=0)
    inspect.add_argument("--length", type=parse_int, default=256)
    inspect.add_argument("--width", type=int, default=16)
    inspect.add_argument("--bits", action="store_true")
    inspect.set_defaults(handler=_cmd_inspect)

    search = subparsers.add_parser("search", help="Search hex wildcard or byte regex")
    search.add_argument("sample")
    search.add_argument("--hex", dest="hex_pattern")
    search.add_argument("--text", help="Byte-oriented regular expression")
    search.add_argument("--ignore-case", action="store_true")
    search.add_argument("--limit", type=int, default=1000)
    search.set_defaults(handler=_cmd_search)

    compare = subparsers.add_parser("compare", help="Compare two files and structures")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--output", required=True)
    compare.add_argument("--limit", type=int, default=1000)
    compare.set_defaults(handler=_cmd_compare)

    disasm = subparsers.add_parser(
        "disasm", help="Linear opcode/assembly view using optional Capstone"
    )
    disasm.add_argument("sample")
    disasm.add_argument(
        "--architecture",
        required=True,
        choices=("x86", "x64", "arm", "thumb", "arm64", "mips32le", "mips64le"),
    )
    disasm.add_argument("--offset", type=parse_int, default=0)
    disasm.add_argument("--length", type=parse_int, default=256)
    disasm.add_argument("--base-address", type=parse_int)
    disasm.add_argument("--limit", type=int, default=1000)
    disasm.add_argument("--output")
    disasm.set_defaults(handler=_cmd_disasm)

    patch_plan = subparsers.add_parser(
        "patch-plan", help="Validate expected bytes and create a sealed plan"
    )
    patch_plan.add_argument("sample")
    patch_plan.add_argument("--offset", type=parse_int, required=True)
    patch_plan.add_argument("--expected", required=True)
    patch_plan.add_argument("--replace", dest="replacement", required=True)
    patch_plan.add_argument("--rationale", default="")
    patch_plan.add_argument("--output", required=True)
    patch_plan.set_defaults(handler=_cmd_patch_plan)

    patch_apply = subparsers.add_parser(
        "patch-apply", help="Apply a sealed plan to a new output file"
    )
    patch_apply.add_argument("sample")
    patch_apply.add_argument("plan")
    patch_apply.add_argument("--confirm-sha256", required=True)
    patch_apply.add_argument("--output", required=True)
    patch_apply.set_defaults(handler=_cmd_patch_apply)

    sandbox = subparsers.add_parser(
        "sandbox-plan", help="Create an approval-gated plan; never executes the sample"
    )
    sandbox.add_argument("sample")
    sandbox.add_argument("--provider", required=True)
    sandbox.add_argument("--timeout", type=int, default=300)
    sandbox.add_argument(
        "--network",
        choices=("blocked", "simulated", "restricted"),
        default="blocked",
    )
    sandbox.add_argument("--image-digest", help="Pinned disposable guest image SHA-256 digest")
    sandbox.add_argument("--snapshot-id", help="Operator-selected clean snapshot/clone identity")
    sandbox.add_argument("--cpu-cores", type=int, default=2)
    sandbox.add_argument("--memory-mb", type=int, default=2048)
    sandbox.add_argument("--disk-mb", type=int, default=4096)
    sandbox.add_argument("--max-trace-bytes", type=int, default=32 * 1024 * 1024)
    sandbox.add_argument("--max-dump-bytes", type=int, default=64 * 1024 * 1024)
    sandbox.add_argument("--output", required=True)
    sandbox.set_defaults(handler=_cmd_sandbox_plan)

    runtime_oep = subparsers.add_parser(
        "oep-runtime-verify",
        help="Verify a user-approved, broker-signed isolated trace and reconstructed PE dump; never executes the sample",
    )
    runtime_oep.add_argument("sample")
    runtime_oep.add_argument("--plan", required=True, help="Exact sandbox plan file approved for this run")
    runtime_oep.add_argument("--trace", required=True, help="Broker-normalized trace JSON")
    runtime_oep.add_argument("--dump", required=True, help="Broker reconstructed PE dump")
    runtime_oep.add_argument("--attestation", required=True, help="Ed25519-signed broker evidence manifest")
    runtime_oep.add_argument("--broker-public-key", required=True, help="Operator-pinned Ed25519 public key file")
    runtime_oep.add_argument("--trusted-broker-id", required=True)
    runtime_oep.add_argument("--confirm-plan-sha256", required=True, help="Explicit confirmation of the exact approved plan digest")
    runtime_oep.add_argument("--output")
    runtime_oep.set_defaults(handler=_cmd_oep_runtime_verify)

    tools = subparsers.add_parser("tools", help="Show optional provider availability")
    tools.add_argument("--provider-config")
    tools.set_defaults(handler=_cmd_tools)

    provider_run = subparsers.add_parser(
        "provider-run", help="Run one allowlisted non-executing static provider"
    )
    provider_run.add_argument("--provider", required=True)
    provider_run.add_argument("--sample", required=True)
    provider_run.add_argument("--rule")
    provider_run.add_argument("--provider-config")
    provider_run.add_argument("--timeout", type=int, default=120)
    provider_run.add_argument("--max-output-bytes", type=int, default=4 * 1024 * 1024)
    provider_run.add_argument("--output")
    provider_run.set_defaults(handler=_cmd_provider_run)

    hosts = subparsers.add_parser(
        "hosts", help="Probe or watch loopback IDA/Ghidra endpoint transitions"
    )
    hosts.add_argument("--watch", action="store_true")
    hosts.add_argument("--interval", type=float, default=2.0)
    hosts.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Watch seconds; zero means until interrupted",
    )
    hosts.add_argument("--timeout", type=float, default=0.25)
    hosts.set_defaults(handler=_cmd_hosts)

    capabilities = subparsers.add_parser(
        "capabilities", help="Normalize a discovered IDA/Ghidra tool list"
    )
    capabilities.add_argument("--host", choices=("ida", "ghidra"), required=True)
    capabilities.add_argument("--endpoint", required=True)
    capabilities.add_argument("--tools", nargs="*", default=[])
    capabilities.add_argument("--resources", nargs="*", default=[])
    capabilities.set_defaults(handler=_cmd_capabilities)

    ida_install = subparsers.add_parser(
        "ida-profile",
        help="Profile a local IDA 9.x installation without launching it",
    )
    ida_install.add_argument("--ida", required=True, help="ida.exe or install root")
    ida_install.add_argument(
        "--python",
        help="Also prepare an idalib activation profile for this Python executable",
    )
    ida_install.add_argument("--no-hashes", action="store_true")
    ida_install.add_argument("--output")
    ida_install.set_defaults(handler=_cmd_ida_profile)

    idalib_plan = subparsers.add_parser(
        "idalib-plan",
        help="Create a reviewed IDA/idalib/MCP activation plan; never starts it",
    )
    idalib_plan.add_argument("--ida", required=True)
    idalib_plan.add_argument("--python", default=sys.executable)
    idalib_plan.add_argument("--mcp-executable")
    idalib_plan.add_argument(
        "--transport",
        choices=("http", "stdio"),
        default="stdio",
    )
    idalib_plan.add_argument("--host", default="127.0.0.1")
    idalib_plan.add_argument("--port", type=int, default=8745)
    idalib_plan.add_argument("--max-workers", type=int, default=4)
    idalib_plan.add_argument("--no-hashes", action="store_true")
    idalib_plan.add_argument("--output")
    idalib_plan.set_defaults(handler=_cmd_idalib_plan)

    context_plan = subparsers.add_parser(
        "ida-context-plan",
        help="Plan bounded read-only context calls for a live IDA database",
    )
    context_plan.add_argument("--database", required=True)
    context_plan.add_argument("--address", type=parse_int, required=True)
    context_plan.add_argument("--byte-count", type=int, default=64)
    context_plan.add_argument("--output")
    context_plan.set_defaults(handler=_cmd_ida_context_plan)

    deeplink = subparsers.add_parser(
        "ida-deeplink", help="Create a project-local IDB navigation link"
    )
    deeplink.add_argument("--database", required=True)
    deeplink.add_argument("--address", type=parse_int, required=True)
    deeplink.add_argument(
        "--view",
        choices=("disassembly", "pseudocode", "hex", "graph"),
        default="disassembly",
    )
    deeplink.add_argument("--output")
    deeplink.set_defaults(handler=_cmd_ida_deeplink)

    snapshot = subparsers.add_parser(
        "snapshot-idb", help="Hash and copy a saved IDB into an immutable snapshot"
    )
    snapshot.add_argument("idb")
    snapshot.add_argument("--output-dir", required=True)
    snapshot.add_argument("--label", default="before-change")
    snapshot.add_argument(
        "--confirm-saved",
        action="store_true",
        help="Assert that IDA has saved and closed/flushed the database",
    )
    snapshot.set_defaults(handler=_cmd_snapshot_idb)

    restore = subparsers.add_parser(
        "snapshot-restore-plan",
        help="Verify a snapshot and create a manual restore plan",
    )
    restore.add_argument("manifest")
    restore.add_argument("--target", required=True)
    restore.add_argument("--output")
    restore.set_defaults(handler=_cmd_snapshot_restore_plan)

    impact = subparsers.add_parser(
        "patch-impact",
        help="Preview structural, integrity, entropy, and assembly effects in memory",
    )
    impact.add_argument("sample")
    impact.add_argument("plan")
    impact.add_argument(
        "--architecture",
        choices=("x86", "x64", "arm", "thumb", "arm64", "mips32le", "mips64le"),
    )
    impact.add_argument("--disassembly-window", type=int, default=64)
    impact.add_argument("--output")
    impact.set_defaults(handler=_cmd_patch_impact)

    inventory = subparsers.add_parser(
        "inventory", help="Create evidence-based binary dependency inventory"
    )
    inventory.add_argument("sample")
    inventory.add_argument("--output")
    inventory.set_defaults(handler=_cmd_inventory)

    classify = subparsers.add_parser(
        "classify", help="Classify Android, Mac, Java, Win, assembly, dongle, binary, script, visual, and audio artifacts"
    )
    classify.add_argument("sample")
    classify.add_argument("--output")
    classify.set_defaults(handler=_cmd_classify)

    pe_deep = subparsers.add_parser(
        "pe-deep", help="Analyze PE metadata, static OEP candidates, boundaries, and indicators without executing the sample"
    )
    pe_deep.add_argument("sample")
    pe_deep.add_argument("--output")
    pe_deep.set_defaults(handler=_cmd_pe_deep)

    region = subparsers.add_parser(
        "region", help="Extract features from a bounded file-offset selection"
    )
    region.add_argument("sample")
    region.add_argument("--offset", type=parse_int, required=True)
    region.add_argument("--length", type=parse_int, required=True)
    region.add_argument(
        "--architecture",
        choices=("x86", "x64", "arm", "thumb", "arm64", "mips32le", "mips64le"),
    )
    region.add_argument("--base-address", type=parse_int)
    region.add_argument("--output")
    region.set_defaults(handler=_cmd_region)

    text_selection = subparsers.add_parser(
        "text-selection", help="Extract lexical features from selected source lines"
    )
    text_selection.add_argument("source")
    text_selection.add_argument("--start-line", type=int, required=True)
    text_selection.add_argument("--end-line", type=int, required=True)
    text_selection.add_argument("--output")
    text_selection.set_defaults(handler=_cmd_text_selection)

    entropy = subparsers.add_parser(
        "entropy-map", help="Locate high-entropy compression/encryption/packing candidates"
    )
    entropy.add_argument("sample")
    entropy.add_argument("--offset", type=parse_int, default=0)
    entropy.add_argument("--length", type=parse_int)
    entropy.add_argument("--window", type=parse_int, default=4096)
    entropy.add_argument("--threshold", type=float, default=7.2)
    entropy.add_argument("--limit", type=int, default=1000)
    entropy.add_argument("--output")
    entropy.set_defaults(handler=_cmd_entropy_map)

    xor_scan = subparsers.add_parser(
        "xor-scan", help="Rank the bounded single-byte XOR keyspace"
    )
    xor_scan.add_argument("sample")
    xor_scan.add_argument("--offset", type=parse_int, required=True)
    xor_scan.add_argument("--length", type=parse_int, required=True)
    xor_scan.add_argument("--limit", type=int, default=10)
    xor_scan.add_argument("--output")
    xor_scan.set_defaults(handler=_cmd_xor_scan)

    transform = subparsers.add_parser(
        "transform-region", help="Export a confirmed XOR/NOT/identity transformed selection"
    )
    transform.add_argument("sample")
    transform.add_argument("--offset", type=parse_int, required=True)
    transform.add_argument("--length", type=parse_int, required=True)
    transform.add_argument("--operation", choices=("xor", "not", "identity"), required=True)
    transform.add_argument("--key", type=parse_int)
    transform.add_argument("--confirm-sha256", required=True)
    transform.add_argument("--output", required=True)
    transform.set_defaults(handler=_cmd_transform_region)

    host_selection = subparsers.add_parser(
        "host-selection-plan", help="Plan bounded IDA/Ghidra selection-context calls"
    )
    host_selection.add_argument("--host", choices=("ida", "ghidra"), required=True)
    host_selection.add_argument("--database", default="")
    host_selection.add_argument("--address", type=parse_int)
    host_selection.add_argument("--end", type=parse_int)
    host_selection.add_argument("--output")
    host_selection.set_defaults(handler=_cmd_host_selection)

    source_operation = subparsers.add_parser(
        "source-operation-plan", help="Plan source view/extract/translate/save or gated mutation"
    )
    source_operation.add_argument("--host", choices=("ida", "ghidra"), required=True)
    source_operation.add_argument(
        "--operation",
        choices=("view", "read", "extract", "translate", "save", "modify", "write", "binary-inject", "process-inject"),
        required=True,
    )
    source_operation.add_argument("--database", default="")
    source_operation.add_argument("--address", type=parse_int)
    source_operation.add_argument("--end", type=parse_int)
    source_operation.add_argument("--target-language", default="")
    source_operation.add_argument("--output")
    source_operation.set_defaults(handler=_cmd_source_operation)

    dump = subparsers.add_parser(
        "dump-plan", help="Plan a bounded static or approval-gated runtime dump"
    )
    dump.add_argument("--host", choices=("ida", "ghidra"), required=True)
    dump.add_argument("--kind", choices=("static", "runtime"), required=True)
    dump.add_argument("--database", default="")
    dump.add_argument("--address", type=parse_int, required=True)
    dump.add_argument("--length", type=parse_int, required=True)
    dump.add_argument("--output")
    dump.set_defaults(handler=_cmd_dump_plan)

    source_plan = subparsers.add_parser(
        "source-edit-plan", help="Create a sealed UTF-8 source replace/insert plan"
    )
    source_plan.add_argument("source")
    source_plan.add_argument("--mode", choices=("replace", "insert_before", "insert_after"), required=True)
    source_plan.add_argument("--start-line", type=int, required=True)
    source_plan.add_argument("--end-line", type=int, required=True)
    source_plan.add_argument("--replacement-file", required=True)
    source_plan.add_argument("--rationale", default="")
    source_plan.add_argument("--target-language", default="")
    source_plan.add_argument("--output", required=True)
    source_plan.set_defaults(handler=_cmd_source_edit_plan)

    source_apply = subparsers.add_parser(
        "source-edit-apply", help="Apply a sealed source edit to a new output file"
    )
    source_apply.add_argument("source")
    source_apply.add_argument("plan")
    source_apply.add_argument("--confirm-sha256", required=True)
    source_apply.add_argument("--output", required=True)
    source_apply.set_defaults(handler=_cmd_source_edit_apply)

    features = subparsers.add_parser(
        "features", help="List the 50 advanced engineering feature contracts"
    )
    features.add_argument("--category", default="")
    features.add_argument("--status", default="")
    features.add_argument("--generation", type=int, choices=(1, 2), default=0)
    features.add_argument("--output")
    features.set_defaults(handler=_cmd_features)

    feature_plan = subparsers.add_parser(
        "feature-plan", help="Create a local, IDA, or Ghidra workflow for one feature"
    )
    feature_plan.add_argument("--feature", required=True)
    feature_plan.add_argument("--host", choices=("local", "ida", "ghidra"), required=True)
    feature_plan.add_argument("--sample", default="")
    feature_plan.add_argument("--database", default="")
    feature_plan.add_argument("--address", default="")
    feature_plan.add_argument("--discovered-tools", nargs="*")
    feature_plan.add_argument("--discovered-resources", nargs="*")
    feature_plan.add_argument("--output")
    feature_plan.set_defaults(handler=_cmd_feature_plan)

    feature_check = subparsers.add_parser(
        "feature-check", help="Validate feature, provider, and host capability mappings"
    )
    feature_check.add_argument("--output")
    feature_check.set_defaults(handler=_cmd_feature_check)

    feature_run = subparsers.add_parser(
        "feature-run", help="Execute one bounded non-mutating local feature"
    )
    feature_run.add_argument("--feature", required=True)
    feature_run.add_argument("--sample", required=True)
    feature_run.add_argument("--second-sample")
    feature_run.add_argument("--host-coverage", type=json.loads, help="JSON live discovery record from IDA/Ghidra; never inferred from static catalogs")
    feature_run.add_argument("--output")
    feature_run.set_defaults(handler=_cmd_feature_run)

    coverage = subparsers.add_parser("host-coverage", help="Calculate feature capability coverage from actual host discovery inputs")
    coverage.add_argument("--host", choices=("ida", "ghidra"), required=True)
    coverage.add_argument("--endpoint", default="")
    coverage.add_argument("--tool", action="append", default=[])
    coverage.add_argument("--resource", action="append", default=[])
    coverage.add_argument("--profile", choices=("current", "read_only", "read_write", "annotate", "patch_plan", "debug"), default="read_only")
    coverage.add_argument("--output")
    coverage.set_defaults(handler=_cmd_host_coverage)

    env_show = subparsers.add_parser(
        "env-show", help="Show the companion MCP environment contract and effective values"
    )
    env_show.add_argument("--output")
    env_show.set_defaults(handler=_cmd_env_show)

    env_check = subparsers.add_parser(
        "env-check", help="Validate an allowlisted companion MCP environment"
    )
    env_check.add_argument("--env-file")
    env_check.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Override one allowlisted RE_MCP_* value; repeat as needed",
    )
    env_check.add_argument("--output")
    env_check.set_defaults(handler=_cmd_env_check)

    settings = subparsers.add_parser(
        "settings", help="Read, tune, save, and reset persistent bounded-analysis settings"
    )
    settings_actions = settings.add_subparsers(dest="settings_action", required=True)
    settings_actions.add_parser("show", help="Show saved and effective values")
    setting_set = settings_actions.add_parser("set", help="Set and persist one bounded setting")
    setting_set.add_argument("key", choices=tuple(SETTINGS_KEYS))
    setting_set.add_argument("value", type=int)
    setting_adjust = settings_actions.add_parser("adjust", help="Increase/decrease and persist one setting")
    setting_adjust.add_argument("key", choices=tuple(SETTINGS_KEYS))
    setting_adjust.add_argument("delta", type=int, help="Positive to increase, negative to decrease")
    setting_reset = settings_actions.add_parser("reset", help="Remove one or all saved overrides")
    setting_reset.add_argument("key", nargs="?", choices=tuple(SETTINGS_KEYS))
    settings.set_defaults(handler=_cmd_settings)

    doctor = subparsers.add_parser(
        "doctor", help="Audit local companion, IDA, Ghidra, dependencies, and providers"
    )
    doctor.add_argument("--ida")
    doctor.add_argument("--idalib-mcp")
    doctor.add_argument("--ghidra-home")
    doctor.add_argument("--ghidra-bridge")
    doctor.add_argument("--ghidra-server", default="http://127.0.0.1:8080/")
    doctor.add_argument("--probe-ida", action="store_true", help="Spawn selected idalib-mcp briefly for read-only MCP initialize/tools/list health probe")
    doctor.add_argument("--output")
    doctor.set_defaults(handler=_cmd_doctor)

    profiles = subparsers.add_parser(
        "client-profiles", help="List supported Codex, Claude, Qwen, IDE, Zed, Antigravity, and Kimi config formats"
    )
    profiles.add_argument("--output")
    profiles.set_defaults(handler=_cmd_client_profiles)

    configs = subparsers.add_parser(
        "client-configs", help="Generate reviewed MCP config fragments without installing them"
    )
    configs.add_argument("--output-dir", required=True)
    configs.add_argument("--python", default=sys.executable)
    configs.add_argument(
        "--companion-script",
        default=str(Path(__file__).resolve().parents[1] / "re_mcp_server.py"),
    )
    configs.add_argument("--idalib-mcp")
    configs.add_argument("--ida-profile-file", help="Reviewed idalib-mcp --profile whitelist; required with restricted host profiles")
    configs.add_argument("--ghidra-bridge")
    configs.add_argument("--ghidra-token-env", default="RE_GHIDRA_TOKEN", help="Environment variable name carrying Ghidra token; value is never written to generated config")
    configs.add_argument("--ghidra-token", help="Supply secret to renderer process; it is validated and never written to outputs")
    configs.add_argument(
        "--ghidra-server",
        default="http://127.0.0.1:8080/",
        help="Loopback URL exposed by the Ghidra plugin",
    )
    configs.add_argument(
        "--clients",
        nargs="+",
        choices=tuple(item.id for item in CLIENTS),
    )
    configs.add_argument("--max-workers", type=int, default=4)
    configs.add_argument(
        "--env-file",
        help="Read only allowlisted RE_MCP_* values from a reviewed UTF-8 env file",
    )
    configs.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Override one allowlisted RE_MCP_* value; repeat as needed",
    )
    configs.add_argument("--force", action="store_true")
    configs.add_argument("--host-profile", choices=("current", "read_only", "read_write"), default="current", help="current preserves upstream exposure; read_only filters writes; read_write exposes only reviewed annotations")
    configs.add_argument("--confirm-read-write", action="store_true", help="Explicitly opt in to reviewed annotation tools; patch/debug/arbitrary code stay disabled")
    configs.set_defaults(handler=_cmd_client_configs)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (
        AnalysisError,
        AdvancedPeError,
        AdvancedWorkflowError,
        ClientConfigError,
        DisassemblyError,
        EnvironmentConfigError,
        FileTypeError,
        IdaInstallationError,
        IdaLiveError,
        McpSupervisorError,
        PatchError,
        PatchImpactError,
        ProviderError,
        SelectionError,
        SnapshotError,
        SourceEditError,
        TransformError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
