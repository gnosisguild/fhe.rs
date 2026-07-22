---
name: crypto-change-review
description: Use when modifying BFV, TRBFV, TRLBFV, LBFV, MBFV, key material, noise sampling, parameters, serialization, decryption, or threshold logic. Provides a review checklist for cryptographic correctness without claiming a formal security audit.
---

# Cryptographic change review

Use this skill when reviewing changes to cryptographic code in fhe.rs. It provides a checklist for correctness review. It is not a formal security audit.

## Identify the scope

Determine which scheme is affected:
- **BFV** (`crates/fhe/src/bfv/`) — Brakerski-Fan-Vercauteren
- **TRBFV** (`crates/fhe/src/trbfv/`) — threshold sharing, smudging, and decryption components derived from the trBFV paper; not the complete robust protocol
- **TRLBFV** (`crates/fhe/src/trlbfv/`) — Threshold l-BFV key generation, participant binding, and public-key/relinearization-key aggregation
- **LBFV** (`crates/fhe/src/lbfv/`) — BFV with linear relinearization-key generation
- **MBFV** (`crates/fhe/src/mbfv/`) — semi-honest N-out-of-N multiparty BFV

Read the matching reference before reviewing a construction-level change: <https://eprint.iacr.org/2018/117> and <https://eprint.iacr.org/2021/204> for BFV/RNS, <https://eprint.iacr.org/2024/1285> for l-BFV/trBFV, and <https://eprint.iacr.org/2020/304> for MBFV. Note that ePrint DoS protection blocks automated downloads; use these as human-readable provenance links.

## Checklist

### Key handling
- [ ] Secret keys are zeroized after use (`zeroize` crate)
- [ ] No secret material in logs, error messages, or debug output
- [ ] Key generation uses the correct randomness source

### Noise
- [ ] The code distinguishes coefficient bounds, standard deviations, and variances
- [ ] trBFV satisfies both `B_C / B_sm = negl(lambda)` and `B_C + n*B_sm < Delta/2`, with `Delta = floor(Q/t_plain)` computed before halving
- [ ] trBFV samples uniform coefficients in `[-B_sm, B_sm]` and does not reuse joint pre-shared noise
- [ ] MBFV key switching/decryption derives smudging from current ciphertext noise; otherwise the limitation is reported
- [ ] Error distributions use the correct parameters

### Parameters
- [ ] Modulus chain is consistent with scheme requirements
- [ ] Polynomial degree matches parameter selection
- [ ] Plaintext modulus is compatible
- [ ] RNS source/auxiliary/destination contexts and scaling factors match the selected multiplication algorithm
- [ ] Each conversion is classified as exact, exactly rounded, or deliberately approximate; staged rounding errors are included in the noise/correctness bound

### Decryption
- [ ] Decryption produces the correct plaintext
- [ ] Error handling covers malformed ciphertexts

### Threshold (TRBFV only)
- [ ] For paper-level claims, odd `n = 2t + 1` and threshold equals `t = (n-1)/2`; even `n` is rejected or documented as outside the theorem
- [ ] Fewer than `threshold + 1` shares cannot decrypt
- [ ] Exactly `threshold + 1` shares decrypt correctly
- [ ] Share aggregation and combination are correct
- [ ] Shamir reconstruction uses the correct interpolation
- [ ] Encryption key, relinearization key, secret shares, and noise use the same participant set
- [ ] The threat model is described as static semi-malicious honest-majority, not fully malicious

### Relinearization and multiparty rounds
- [ ] l-BFV preserves common `a` and `d1`, key-switch direction/signs, and linearity in secret-key shares
- [ ] Documentation retains the circular-security assumption for l-BFV relinearization
- [ ] MBFV round-2 shares are bound to the exact round-1 aggregate
- [ ] MBFV aggregation includes each intended N-out-of-N contribution exactly once
- [ ] Missing round binding, participant identity, smudging, or one-time-noise enforcement is reported as an implementation gap rather than assumed from the paper

### Serialization
- [ ] Encode/decode round-trip correctly
- [ ] Malformed input cannot cause a panic
- [ ] Protobuf schema changes are reflected in generated files

## Reporting

Report findings as correctness observations, not security guarantees. Distinguish:
- **Correctness** — the math or logic is wrong (verifiable from code)
- **Security** — the construction may leak information (requires formal analysis)

Include the threat model (semi-honest vs. semi-malicious, corruption threshold, setup/CRS assumptions) with every protocol-level claim.

Known caveat: Shamir secret sharing uses arbitrary-precision arithmetic that is not constant-time. This is documented and accepted for local computations.
