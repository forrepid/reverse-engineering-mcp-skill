# Advanced engineering workflows

Read this reference for OEP, obfuscation, encryption, dump, injection,
selection, translation, or source-edit work.

## PE entry point, markers, differences, and end

- Report `AddressOfEntryPoint` as the **declared entry point** with RVA, VA,
  file offset, section, permissions, and bytes.
- Do not call it the original entry point when packing/self-modification may
  transfer control later. True runtime OEP recovery requires an approved
  isolated trace or dump.
- Map header end, every raw section boundary, inter-section gaps, certificate
  table, last section end, overlay, and physical EOF.
- Record Rich/PDB, packer/protector, anti-debug, language/runtime, dongle, and
  compiler candidates with offsets and confidence.
- Use `compare` for byte/structure differences. Semantic function diff remains
  a host/provider workflow until normalized instruction and CFG records exist.

## Injection and obfuscation

- Group imports into remote-thread, APC, hollowing, section mapping, DLL load,
  hook, and memory-protection-transition candidates.
- Confirm reachable call sites, arguments, and data flow through IDA/Ghidra;
  imports alone never prove injection.
- Score obfuscation from explainable evidence: entropy, RWX, packer sections,
  markers, sparse imports, writable entry point, and overlay. Preserve every
  contributing reason.
- Process injection is blocked by default. `binary-inject` means a sealed,
  out-of-place byte/source edit, never an automatic live-process action.

## Encryption, decryption, and brute force

- Use entropy as a compression/encryption candidate only.
- `xor-scan` enumerates exactly 256 single-byte XOR keys for a selected region
  no larger than 1 MiB and ranks readable-text candidates.
- `transform-region` exports only the selected XOR/NOT/identity result after
  explicit source SHA-256 confirmation. It never overwrites the source.
- Do not label generic transforms as successful cryptographic decryption
  without format/plaintext validation.
- Password, credential, license-key, dongle, online-service, and open-ended
  brute force are outside this project.

## Dump

- Static IDB bytes use `get_bytes` and remain `read_only`.
- Runtime memory uses `dbg_read`, requires `debug` mode, an isolated target,
  explicit approval, bounds, and provenance.
- GhidraMCP currently lacks an equivalent bounded raw-byte/dump tool in its
  published bridge. Report the capability gap instead of improvising writes.

## Selection and source workbench

- For file selections, report file offset, end-exclusive boundary, hash,
  entropy, bounded hex/bytes, strings, and optional linear disassembly.
- For IDA, combine `lookup_funcs`, `get_bytes`, `disasm`, `decompile`,
  `xrefs_to`, and `callees`, always with explicit `database`.
- For Ghidra, combine current address/function, function lookup, disassembly,
  decompilation, and xrefs. Preserve its raw-byte limitation.
- For UTF-8 source lines, extract lexical imports/includes, function
  candidates, URLs, TODO/FIXME, and crypto terms without executing text.
- Treat decompiled C/pseudocode as reconstruction, not original source.

## Read, write, translate, inject, and save

- `view`, `read`, `extract`, `translate`, and `save` are read-only artifact
  workflows. Translation must preserve address/provenance comments and must
  not compile or execute automatically.
- `modify`, `write`, and `binary-inject` require a snapshot, a sealed edit or
  patch plan, explicit SHA-256 confirmation, a new output, and reanalysis.
- `source-edit-plan` supports UTF-8 replace/insert-before/insert-after with
  expected text and a deterministic digest. `source-edit-apply` writes only a
  new file.
- Editing exported pseudocode does not patch the binary or IDB. Convert a
  reviewed semantic change into a byte/assembly patch separately.

The versioned 50-feature inventory is emitted by `features`. Use
`--generation 1` for the original 25 and `--generation 2` for the second 25;
the machine contract lives in `scripts/re_core/feature_catalog.py`.
