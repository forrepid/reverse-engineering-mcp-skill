# File taxonomy contract

Read this reference before extending magic detection, archive inspection, or
category-specific analysis pipelines.

## Categories

| Category | Structural evidence | Representative subtypes |
|---|---|---|
| `android` | DEX magic or APK/AAB/AAR container structure | DEX, APK, AAB, AAR |
| `mac` | Mach-O/fat magic or IPA application bundle | Mach-O, universal binary, IPA |
| `java` | Java class magic or JAR contents | `.class`, JAR; also Android bytecode context |
| `win` | Valid or candidate DOS/PE structure | EXE, DLL, driver, UEFI, .NET assembly |
| `assembly` | CLR runtime header or assembly-source structure | .NET assembly, ASM source |
| `dongle` | HASP/Sentinel, Wibu/CodeMeter, FlexNet, Rockey indicators | secondary evidence only |
| `binary` | ELF, PE, Mach-O, archives, DEX, or unknown non-text data | executable, object, firmware, archive |
| `script` | shebang, known extension, or script container structure | Python, PowerShell, JS/TS, shell, batch, Lua |
| `visual` | image magic or verified SVG structure | PNG, JPEG, GIF, BMP, ICO, WebP, SVG |
| `audio` | audio/container magic | WAV, MP3, FLAC, Ogg, MIDI |

Categories are multi-valued. `primary_category` is routing metadata, not an
exclusive truth. An APK may be `android + java + binary`; a .NET PE may be
`win + assembly + binary`; a Mach-O containing license API markers may add
`dongle` as secondary evidence.

## Detection order

1. Hash the complete file.
2. Prefer validated magic and structural headers.
3. Inspect ZIP central-directory names without extracting or decompressing
   entries. Bound the entry count and output list.
4. Parse PE headers and directories for EXE/DLL/driver/UEFI/.NET distinctions.
5. Use text structure and extension together for script/assembly/SVG.
6. Add bounded content markers as secondary evidence with offsets.
7. Fall back to `binary`; never invent a precise subtype from an extension.

Java `.class` and Mach-O universal binaries share `CAFEBABE`. Disambiguate
with the Java major version, extension, and plausible fat-architecture count;
retain uncertainty for malformed or adversarial inputs.

## Provider routing

- Use `classify` for the deterministic baseline.
- Correlate broad executable/archive coverage with Detect It Easy. DiE's
  primary documentation lists PE, ELF, APK, IPA, JAR, ZIP, DEX, DOS/COM,
  LE/LX, Mach-O, and NPM support.
- Route APK/AAB/DEX to JADX plus native-library analysis in IDA/Ghidra.
- Route Java class/JAR to a reviewed Java decompiler while retaining bytecode.
- Route Mach-O/IPA to IDA/Ghidra and optional LIEF parsing.
- Treat images/audio as resources. Do not render active or malformed content
  automatically; extract to a hash-recorded artifact first.

## Limits

- A file can be polyglot or deliberately malformed.
- Dongle strings/imports indicate integration, not a license bypass target.
- Extension-only script identification is medium confidence.
- Container entry names are untrusted and are never used as extraction paths.
- Classification does not execute, import, render, or upload the artifact.

## Primary sources

- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy)
- [JADX](https://github.com/skylot/jadx)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [LIEF](https://github.com/lief-project/LIEF)
