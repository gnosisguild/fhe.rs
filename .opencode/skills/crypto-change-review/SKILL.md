---
name: crypto-change-review
description: Use when modifying BFV, TRBFV, TRLBFV, LBFV, MBFV, key material, noise sampling, parameters, serialization, decryption, or threshold logic. Points to the crypto correctness checklist and identifies which scheme it applies to. Not a formal security audit.
---

# Cryptographic change review

Use this skill when reviewing or self-checking changes to cryptographic code in fhe.rs, whether during implementation or before commit. It is not a formal security audit.

## Identify the scope

Determine which scheme is affected:
- **BFV** (`crates/fhe/src/bfv/`) — Brakerski-Fan-Vercauteren
- **TRBFV** (`crates/fhe/src/trbfv/`) — threshold sharing, smudging, and decryption components derived from the trBFV paper; not the complete robust protocol
- **TRLBFV** (`crates/fhe/src/trlbfv/`) — Threshold l-BFV key generation, participant binding, and public-key/relinearization-key aggregation
- **LBFV** (`crates/fhe/src/lbfv/`) — BFV with linear relinearization-key generation
- **MBFV** (`crates/fhe/src/mbfv/`) — semi-honest N-out-of-N multiparty BFV

Read the matching reference before reviewing a construction-level change: <https://eprint.iacr.org/2018/117> and <https://eprint.iacr.org/2021/204> for BFV/RNS, <https://eprint.iacr.org/2024/1285> for l-BFV/trBFV, and <https://eprint.iacr.org/2020/304> for MBFV. Note that ePrint DoS protection blocks automated downloads; use these as human-readable provenance links.

## Checklist and reporting policy

The full checklist (key handling, noise, parameters, decryption, threshold, relinearization/multiparty rounds, serialization) and the reporting policy (correctness vs. security claims, threat model requirements, the Shamir constant-time caveat) live in [`.rules/crypto.md`](../../../.rules/crypto.md) — the source of truth. Read it in full and apply it to the change at hand; do not restate it here or let this file drift from it.
