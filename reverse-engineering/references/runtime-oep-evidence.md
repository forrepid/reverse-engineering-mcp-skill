# Runtime OEP evidence verifier

The `oep-runtime-verify` command imports evidence from a separately operated,
approved isolated-analysis broker. It never starts a VM, submits a sample,
attaches a debugger, or reads host process memory. The first delivered slice
is an evidence verifier/import contract—not a runtime capture backend.

## Broker capture status

No live broker endpoint, operator-pinned broker ID/key, or guest capture/signing
agent is configured by this repository at present. `sandbox-plan` explicitly
reports `broker_capture_contract.status=not_configured`,
`continuous_capture=false`, and `submission_enabled=false`; it never starts a
background poller or uploads a sample. A plan marked ready only means its
static isolation fields are populated, not that a compatible broker exists.

CAPE's current REST API documents task submission, task status/report retrieval,
and downloadable `all`/`dropped` result archives. That API alone does not
establish this project's lossless normalized trace, reconstructed-PE OEP
evidence, or plan-bound Ed25519 attestation contract. A CAPE worker/sensor
adapter must produce and sign those artifacts within the isolated broker; the
private signing key must remain in the broker/HSM. Do not treat an ordinary
CAPE report or an unsigned dump as runtime OEP proof. See the [CAPE REST API
documentation](https://github.com/kevoreilly/CAPEv2/blob/master/docs/book/src/usage/api.rst).

## Trust and approval gates

1. Generate a sandbox plan with a pinned disposable image SHA-256, clean
   snapshot ID, blocked networking, and finite CPU/time/RAM/disk/trace/dump
   quotas. Without image and snapshot identity the plan is not ready for broker
   submission; non-blocked networking also keeps runtime OEP submission closed.
2. Inspect the exact plan and separately approve it in the broker/operator
   workflow. Record its SHA-256. The verifier also requires the caller to pass
   that exact digest via `--confirm-plan-sha256`.
3. Pin the broker Ed25519 public key and broker ID out-of-band. Never trust a
   public key shipped inside the evidence bundle or selected by an untrusted
   sample. Private signing keys stay inside the broker/HSM.
4. The broker returns a normalized trace JSON, reconstructed PE dump, and an
   Ed25519-signed attestation binding the approved plan, sample, session, trace,
   dump, event-loss count, runtime image range, and candidate address.
5. `verified` means all locally checkable evidence gates passed under that
   broker trust. It is not a claim that the broker or its sensor is infallible.
6. Results expose `oep_display`: verified VA/RVA/offset or a clear NOT VERIFIED
   status. Static `pe-deep` uses `oep_result.status=not_verified`; declared EP
   remains only a reference, never a runtime OEP claim.

Example plan creation (planning only):

```powershell
python scripts/re_cli.py sandbox-plan .\sample.exe `
  --provider internal `
  --network blocked `
  --image-digest <64-hex-guest-image-sha256> `
  --snapshot-id clean-win-analysis-2026-01 `
  --timeout 300 --cpu-cores 2 --memory-mb 2048 --disk-mb 4096 `
  --output .\artifacts\oep-plan.json
Get-FileHash .\artifacts\oep-plan.json -Algorithm SHA256
```

After an external broker has run that specifically approved plan and exported
the bundle:

```powershell
python scripts/re_cli.py oep-runtime-verify .\sample.exe `
  --plan .\artifacts\oep-plan.json `
  --trace .\artifacts\trace-index.json `
  --dump .\artifacts\reconstructed.exe `
  --attestation .\artifacts\broker-attestation.json `
  --broker-public-key .\trust\lab-broker-ed25519.pub `
  --trusted-broker-id lab-broker-01 `
  --expected-broker-public-key-sha256 <sha256-of-raw-public-key-bytes> `
  --confirm-plan-sha256 <exact-approved-plan-sha256> `
  --output .\artifacts\runtime-oep.json
```

The public key file may contain 32 raw bytes, 64 hexadecimal characters, or
base64-encoded raw Ed25519 key bytes. The private key must not be on the
analysis workstation. Supply the out-of-band raw-key SHA-256 pin when available;
the MCP verifier requires it. The CLI exits `0` only for `verified`; rejected/tampered
evidence or incomplete telemetry returns a nonzero exit and a JSON report.
Signature verification uses the Ed25519 verify API from the pinned
`cryptography` package; see the [Ed25519 signing and verification reference](https://cryptography.io/en/41.0.6/hazmat/primitives/asymmetric/ed25519/).

## Normalized trace contract

Trace JSON has `schema_version: "1"`, the attested `broker_id`, `session_id`,
`sample_sha256`, exact `plan_sha256`, `complete: true`, `event_loss_count: 0`,
and a bounded `events` array. Events have monotonically increasing integer
`seq` values and include:

- `process_start` with the exact sample SHA-256;
- `module_map` for the original sample image and runtime base;
- `unpack_complete` with the mapped image base and size;
- `control_transfer` with `phase: "post_unpack"`, source and candidate target
  VAs, and executable target protection;
- `memory_map` covering the candidate with executable protection;
- `instruction` at the candidate VA after the transfer.

The attestation's signed canonical JSON fields include `algorithm: "Ed25519"`,
`broker_id`, `session_id`, signed approval `{approved: true, plan_sha256: ...}`,
sample/plan/trace/dump SHA-256 values, `dump_kind: "reconstructed_pe"`, trace
completeness/loss/event count, runtime image base/size, candidate VA, and
base64 `signature`. Signature verification excludes only the `signature`
field. Unknown added fields remain covered by the signature.

The verifier parses only a bounded reconstructed PE file (not a raw process
memory blob), requires its `AddressOfEntryPoint` to equal the candidate RVA,
requires candidate membership in a file-backed executable section, and
cross-checks the trace sequence. Full relocation/import reconstruction quality
scoring remains open. Missing broker capture support,
untrusted keys, telemetry loss, malformed dumps, image/address mismatch, or
unsupported dump format cannot produce `verified`. In those cases use the
returned `inconclusive`/`rejected` status; do not promote static OEP candidates.
