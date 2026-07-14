# Evidence and report schema

Read this reference when changing analyzers, adapters, provider integration,
comparison output, or report serialization.

Current serialization contract: `0.5.0`. Consumers must reject unsupported
major versions and tolerate additive fields within the same major version.

## Core records

### AnalysisRun

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Serialization contract version |
| `run_id` | string | Unique run identifier |
| `started_at` | UTC ISO-8601 | Start time |
| `source` | object | Path, size, hashes, file identity |
| `environment` | object | Python/platform/tool versions |
| `summary` | object | Format, architecture, entropy, entry point |
| `sections` | array | File/RVA bounds, permissions, entropy |
| `imports` | array | DLL and imported symbols |
| `strings` | array | Encoding, file offset, value |
| `findings` | array | Evidence-backed observations |
| `limitations` | array | Missing tools, truncation, parse failures |

### Finding

Every finding has:

- `id`: stable category identifier.
- `title`: concise observation.
- `source`: analyzer or adapter.
- `location`: typed file offset, RVA, VA, function, or session.
- `observation`: what the tool directly showed.
- `interpretation`: analyst conclusion; optional.
- `confidence`: `low`, `medium`, or `high`.
- `severity`: `info`, `low`, `medium`, `high`, or `critical`.
- `tags`: normalized labels.
- `provenance`: tool name/version, arguments without secrets, and raw output
  hash when an external provider is used.

Never raise confidence merely because multiple reports reuse the same engine.

### ClassificationRecord

- `categories`: one or more of `android`, `mac`, `java`, `win`, `assembly`,
  `dongle`, `binary`, `script`, `visual`, or `audio`.
- `format` and `subtype`: magic/container-derived identity; extension is only
  supporting evidence.
- `evidence`: exact magic, container member, marker or structural observation.
- `hashes`, `size`, and `limitations`: provenance and bounded-read coverage.

### AdvancedPeRecord

- `declared_entry_point`: PE header RVA mapped to VA/file offset/section when possible.
- `boundaries`: headers, sections, gaps, certificate table and overlay.
- `markers`: PDB/Rich, packer/protection, runtime/language and dongle evidence.
- `injection_candidates`: API groups and matched primitives; detection only.
- `obfuscation`: explainable indicators and score, never a verdict.
- `high_entropy_candidates`: compression/encryption/packing candidates.

### Selection and transformation records

Selection records include address space, offset/line range, requested and
returned length, truncation, hashes, entropy and extracted local features.
Transformation plans include algorithm, bounded region, source hash, expected
input and destination; applying always writes a new file. Single-byte XOR key
ranking is capped at 256 keys over at most 1 MiB and is not credential cracking.

### SourceEditPlan

Source edits are limited to UTF-8 text and contain source SHA-256, operation,
line range, expected source lines, replacement text and a deterministic digest.
Application requires the hash confirmation and a non-existing output path.
Decompiler exports additionally record that they are pseudocode, not original
or guaranteed-recompilable source.

### ClientConfigManifest

- `status` is always `generated-not-installed` for renderer output.
- `outputs` records client id, generated path, documented merge target, and
  primary documentation URL.
- `servers` distinguishes the portable companion from optional idalib.
- `companion_environment` records the nine validated, non-secret effective
  `RE_MCP_*` values rendered into every companion server entry.
- `automatic_installation` is `false`; no existing client config is parsed,
  merged, or overwritten by generation.

### EnvironmentContract

- `variables` contains only the nine allowlisted names, type, default, bounds,
  effective value and whether it came from the process environment or default.
- `runtime` contains parsed numeric limits and resolved allowed roots.
- `required_count` and `secret_count` are both zero in v0.4.
- `automatic_dotenv_loading` is false. Unknown names and invalid values are
  errors; unrelated process environment is never serialized.

### EngineeringFeature

Every catalog item includes a `generation` integer, implementation `status`,
mode, local implementation/provider/host mapping, and guards. Generation 1 and
2 each contain exactly 25 unique ids. A planned/provider status must not be
presented as a locally implemented capability.

## Address representation

Serialize numeric addresses as both integer and canonical hex when an API
needs arithmetic and human review:

~~~json
{"space":"file_offset","value":512,"hex":"0x200"}
~~~

Valid spaces are `file_offset`, `rva`, `va`, `runtime`, and `unknown`. Never
silently convert between them. Record image base and mapping source.

## Byte representation

Use uppercase, space-separated byte text in reports, such as `4D 5A 90 00`.
Patch records carry:

- original sample SHA-256;
- offset space and integer offset;
- expected bytes;
- replacement bytes;
- rationale;
- creator and UTC timestamp;
- a deterministic plan digest.

Expected and replacement lengths must match in v0. A future structural patcher
may explicitly version a different invariant.

Before applying, `patch-impact` validates the sealed plan and reports the
projected hash, affected PE regions, integrity consequences, entropy delta, and
optional linear disassembly without writing a file.

## IDA integration records

- `IdaInstallationReport` records exact discovered paths, optional component
  hashes, version, readiness, and warnings; it never launches a component.
- `McpLaunchPlan` records transport, loopback endpoint, exact command array,
  context isolation, worker bound, and `shell=false`.
- `ContextRequest` records explicit database, canonical address, tool,
  arguments, and whether a failure is fatal.
- IDB snapshot manifests record source/snapshot hashes and make restore a
  separate explicit plan.
- Binary dependency inventory is evidence-only and includes explicit
  CycloneDX/SPDX non-compliance and coverage limitations.

## Report invariants

- JSON is UTF-8, sorted and indented.
- TXT is UTF-8 and readable in current Windows Notepad.
- Output paths never overwrite the source.
- Truncated collections declare the limit and total when known.
- Parser failures become limitations; they do not erase successful evidence.
