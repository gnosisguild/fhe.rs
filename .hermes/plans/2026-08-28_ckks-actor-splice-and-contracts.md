# CKKS Actor-Shell Splice + Chain Result Path — Implementation Plan

> **For Hermes:** Execute task-by-task; every task ends with its verification
> command green before moving on. No commits — user reviews and commits.

**Goal:** Wire the already-tested CKKS keyshare machinery
(`crates/keyshare/src/threshold_keyshare_ckks/`) into the live
`ThresholdKeyshare` actix actor + E3 lifecycle, and land the CKKS
fixed-point result on-chain through the existing `publishPlaintextOutput`
path — ending with a `tests/integration/ckks.sh` that runs real ciphernode
processes like `base.sh` does.

**Architecture:** The CKKS state machine (`machine.rs`) already consumes the
same events the BFV actor handles and emits commands mapping 1:1 onto
existing event types. The splice is therefore a *dispatch* problem, not a
crypto problem: choose machine-vs-BFV at `CiphernodeSelected` time via
`SchemeParams::from_encoded(meta.params)`, translate commands to bus events
in one place, and version the recovery schema. On the chain side,
`Interfold.publishPlaintextOutput` takes opaque `bytes` verified by hash
through a pluggable `decryptionVerifier` — the core contract is untouched;
only a CKKS decryption-verifier binding and program-side decoding change.

**Tech stack:** actix actors (`e3-keyshare`), event bus (`e3-events`),
`e3-fhe::SchemeParams`/`CkksFhe`, `trckks::program` fixed-point codec,
solidity (`packages/interfold-contracts`), integration harness
(`tests/integration`).

**Current state (all local, uncommitted, branch
`feat/ckks-user-data-encryption`):** machine + encrypted transport + C2
proof gate + slot-batched auction all green (45 e3-keyshare tests). The
BFV actor path is untouched. Pre-existing clippy error in
`crates/zk-prover/src/witness.rs:56` is NOT ours — leave it alone.

---

## Phase A — Actor-shell splice (Rust, `crates/keyshare` + `crates/events`)

### A1. Scheme flag on the persisted state
**Files:** `crates/keyshare/src/threshold_keyshare/state.rs`
- Add `scheme: E3Scheme` (`enum E3Scheme { Bfv, Ckks }`, serde, default
  `Bfv` via `#[serde(default)]` so existing persisted states deserialize).
- Set from `SchemeParams::from_encoded(&meta.params)` in
  `ThresholdKeyshareState::new` callers (see A3).
- **Verify:** `cargo test -p e3-keyshare state -- --nocapture` green;
  existing `state_tests.rs` untouched and passing (backward-compat check:
  add one test deserializing a pre-change JSON fixture without the field).

### A2. CKKS branch events — reuse, don't invent
**Files:** `crates/events/src/interfold_event/threshold_share_created.rs`
(read-only check), `crates/keyshare/src/threshold_keyshare_ckks/machine.rs`
- No new event structs: `PublishThresholdShare` → existing
  `ThresholdSharePending`/`ThresholdShareCreated` (the encrypted-transport
  module already emits the exact `ThresholdShare` payload shape;
  `esi_sss.len() == 1` for CKKS). `PublishKeyshareCreated` →
  `KeyshareCreated` (joint pk in `pubkey`). `PublishDecryptionShare` →
  `DecryptionKeyShared`-equivalent decryption-share event used by the
  aggregator (confirm exact type in
  `crates/aggregator/src/plaintext_aggregation/` before writing).
- ONLY schema touch: `ThresholdShareCreated.signed_c2a_proof/…` stay
  optional — CKKS fills c2a/c2b from the proof gate, leaves c3 vecs empty
  initially. Document that in the event's doc comment.
- **Verify:** `cargo check -p e3-events -p e3-keyshare` clean.

### A3. Dispatch in the extension + actor construction
**Files:** `crates/keyshare/src/ext.rs`,
`crates/keyshare/src/threshold_keyshare/actor.rs`
- In `ThresholdKeyshareExtension::on_event` (CiphernodeSelected): decode
  `meta.params` with `SchemeParams::from_encoded`; on `Ckks(params)` store
  scheme + build `CkksFhe::from_encoded` (CRP seed from the E3's `Seed`,
  committee shape from `meta.threshold_m/n`) into new actor field
  `ckks: Option<CkksRuntime>` (struct holding `CkksFhe` +
  `CkksKeyshareMachine` + smudging bits from the flooding calculator).
- `hydrate()`: same dispatch on the recovered meta.
- **Verify:** `cargo test -p e3-keyshare ext` + existing actor tests green.

### A4. Handler routing
**Files:** `crates/keyshare/src/threshold_keyshare/handlers.rs`,
`effects/route_events.rs`, new
`crates/keyshare/src/threshold_keyshare_ckks/shell.rs`
- Each existing handler body gains a two-line head:
  `if let Some(ckks) = &mut self.ckks { return ckks_shell::handle_x(...) }`.
  The shell translates machine commands → bus events (one function per
  event, ~15 lines each), persists machine state after every transition
  (bincode into the existing `Persistable` slot), and calls the C2 proof
  gate (`proofs::verify_ckks_share_witnesses`) before emitting
  `ThresholdSharePending`.
- Events to route: `CiphernodeSelected`, `EncryptionKeyCreated` (→
  `machine.on_encryption_key`), `ThresholdShareCreated`
  (→ `on_threshold_share`), `CiphertextOutputPublished`
  (→ `on_ciphertext_output`), plaintext-aggregated completion.
- **Verify:** new `shell_tests.rs`: drive the ACTOR (not the machine) with
  5 in-process actix instances over a test bus through the full lifecycle
  (mirror `threshold_keyshare/tests.rs` harness); assert joint pk
  convergence + decryption-share emission.

### A5. Recovery schema bump
**Files:** `crates/keyshare/src/threshold_keyshare/recovery_state.rs`
- `THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION += 1`; add optional
  `ckks_machine: Option<Vec<u8>>` (bincode machine snapshot).
- Restart test: kill mid-`CollectingThresholdShares`, rehydrate, finish.
- **Verify:** `cargo test -p e3-keyshare recovery` green; BFV recovery
  fixture still loads (the version gate in `ext.rs::hydrate` is `ensure!`
  — confirm upgrade path or document that in-flight E3s don't survive the
  bump, matching existing repo practice).

### A6. Aggregator side
**Files:** `crates/aggregator/src/plaintext_aggregation/` (exact file
  after recon), reuse `threshold_keyshare_ckks::workflow::aggregate_plaintext`
- On CKKS E3s: collect t+1 decryption shares, call `aggregate_plaintext`,
  encode with `e3_trckks::program::encode_fixed_point_output(values,
  DECIMALS)` (fix `DECIMALS = 6` as the protocol constant, one place),
  emit `PlaintextAggregated { decrypted_output: vec![bytes], .. }`.
- **Verify:** aggregator unit test: shares in → canonical `int128` bytes
  out; byte-for-byte determinism across two different t+1 subsets
  (the reason truncation exists — this test is the contract).

## Phase B — Chain result path (solidity + verifier binding)

### B0. Recon finding that shapes this phase
`Interfold.publishPlaintextOutput` (`Interfold.sol:427-464`) stores opaque
`bytes` and verifies `keccak256(plaintextOutput)` via the E3's pluggable
`decryptionVerifier` — **no core-contract change needed**. The CKKS gap is
(1) the verifier binding: C7-CKKS's public output is `u_global` (ring
element), not the BFV decoded message, so the decryption verifier for CKKS
E3s must bind `keccak(fixed_point_bytes)` to the C7-CKKS journal — the
plumbing that TODAY links plaintext hash → C7 public inputs for BFV; and
(2) app-level decoding of `int128[]`.

### B1. CKKS decryption-verifier stub + wiring
**Files:** `packages/interfold-contracts/contracts/verifiers/` (new
`CkksDecryptionVerifier.sol`, modeled on the existing decryption verifier),
registry wiring wherever verifiers are registered per E3 program.
- Mock-verifier level first (matching the repo's existing mock-verifier CI
  practice): accept proof, check hash linkage shape. Real verifier keyed to
  the DecryptionAggregator circuit ABI comes with the recursive-aggregation
  work, NOT this plan (deferred like BFV's was).
- **Verify:** `pnpm --filter interfold-contracts test` — new test:
  publish a CKKS `int128[]` payload through `publishPlaintextOutput`,
  assert `PlaintextOutputPublished` emits the exact bytes and stage →
  `Complete`.

### B2. Fixed-point decode reference + example program
**Files:** `packages/interfold-contracts/contracts/test/` (or the E3
program template dir): `CkksFixedPointLib.sol` — decode `bytes` as
big-endian `int128` words (16-byte chunks, revert on ragged length; mirror
of `e3_trckks::program::decode_fixed_point_output`).
- Cross-language fixture test: bytes produced by the Rust encoder in
  `program_tests.rs` decoded by the solidity lib to the same values
  (hard-code one vector both sides).
- **Verify:** contracts test suite green.

## Phase C — Real-process integration scenario

### C1. `tests/integration/ckks.sh` upgrade
**Files:** `tests/integration/ckks.sh` (replace current workflow-level
script), reusing `base.sh`'s process harness (anvil + N ciphernode
processes + aggregator).
- Scenario: deploy with CKKS params in the E3 request → real DKG over the
  bus → submit slot-replicated encrypted bids → `auction_round_policy` as
  the compute step → threshold decryption → `publishPlaintextOutput` with
  fixed-point bytes → assert on-chain `plaintextOutput` decodes to the
  expected signs.
- Env knobs: reuse `CIPHERNODE_SKIP_PROOF_AGGREGATION=1`.
- **Verify:** `./tests/integration/ckks.sh` exit 0 on a clean checkout;
  wire into `scripts/ckks-e2e.sh` as opt-in Stage 6 (`--with-processes`)
  so the default e2e stays fast.

---

## Order & effort
A1→A2→A3→A4 are strictly sequential (each compiles on the last); A5/A6
parallel after A4; B independent of A until C1 needs both. Rough effort:
A = the bulk (actor tests dominate), B = small given B0, C = glue but
flaky-prone (process orchestration).

## Risks / open questions (answer before A4)
1. **Exact decryption-share event type** the aggregator consumes
   (`DecryptionKeyShared` vs a share-specific event) — recon
   `crates/aggregator` first; wrong choice = rework in A4+A6.
2. **Recovery upgrade policy:** does the repo accept "in-flight E3s die on
   schema bump" (precedent suggests yes via the `ensure!` gate)? If not,
   A5 needs a migration.
3. **Proof slots:** C3a/C3b (share-encryption proofs) are left empty for
   CKKS in this plan — the encrypted-transport witnesses exist
   (`encrypt_all_extended` returns them) but the C3 circuit's
   plaintext-modulus config for CKKS moduli needs its own codegen pass.
   Flag in `ThresholdShareCreated` docs; follow-up plan.
4. **DECIMALS=6** protocol constant: confirm 6 decimal places suffice for
   the statistics use case's variance outputs at the insecure preset's
   ~0.3 absolute error (it does — noise floor >> 1e-6 — but a secure-preset
   deployment should re-derive from the flooding calculator's
   `precision_loss`).

## Verification ladder (every phase end)
```
cargo +nightly fmt --all
cargo clippy -p e3-keyshare -p e3-events -p e3-fhe -p e3-trckks -p e3-aggregator --all-targets -- -D warnings
cargo test -p e3-keyshare -p e3-events -p e3-fhe -p e3-trckks -p e3-aggregator --release
pnpm --filter interfold-contracts test        # Phase B
./scripts/ckks-e2e.sh                          # regression gate
./tests/integration/ckks.sh                    # Phase C exit criterion
```
