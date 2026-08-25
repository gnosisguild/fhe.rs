# Mathematical correctness

## Scope

`fhe-math` core arithmetic for HE: RNS basis representation/conversion/CRT, NTT transforms, modular reduction/Shoup/Barrett arithmetic, polynomial multiplication/division/centering/degree management, and scalar/coefficient conversions. The independent `shamir-rns` crate additionally owns runtime prime-field reduction, interpolation, and canonical residue invariants. The BFV implementation follows <https://eprint.iacr.org/2018/117> and <https://eprint.iacr.org/2021/204>.

## Invariants

1. NTT forward followed by inverse recovers the original within modular arithmetic.
2. RNS conversions are lossless within modulus bounds.
3. Polynomial degree does not silently exceed expectations after multiplication.
4. Modular reductions produce documented canonical or centered representatives.
5. Scalar-polynomial conversions preserve value.
6. Source and destination RNS moduli are pairwise coprime, ordered for every precomputed table, and represent the product used by the scaling factor.
7. RNS integer interpretation uses the documented centered representative.
8. Each basis operation is identified as exact conversion, exact rounded scaling, or deliberately approximate extension; `RnsScaler` agrees exactly with centered big-integer scaling and only an explicitly documented approximate-extension path (the FastBaseExtension of the cited 2021/204 paper; none currently exists in `fhe-math`) may expose a bounded source-modulus correction term.
9. Rounding preserves nearest, floor, and ceiling semantics, including `-1/2 -> 0` for the current scaler.
10. Fixed-point CRT quotient estimates preserve specified nearest/directed rounding, `theta_garner_shift`, accumulator width, and truncation-error bounds without floating point.
11. Each switch and rounding stage agrees with a BigInt oracle, including HPS `t/Q` and modified `Q -> P` then `t/P` scaling.
12. Original HPS temporary `QP` contexts satisfy unreduced tensor-product bounds; modified multiplication preserves staged modulus-switch bounds and cancellation of the unwanted `QP` multiple.
13. RNS or radix digits recompose the original polynomial modulo the source context and pair with the corresponding evaluation-key component.
14. `shamir-rns` field values remain canonical in `[0, q)`, constructor points are distinct nonzero units, inversion rejects zero, and Lagrange interpolation is checked against field and property-test evidence.
15. Packed deserialization (`Modulus::deserialize_vec`) accepts only byte streams encoding a whole number of `nbits`-bit coefficients whose values are canonical representatives in `[0, p)`; noncanonical values (`>= p`) and partial streams are rejected with typed errors, never reduced. Protobuf message validation owns context-derived sizing (exact degree match with the target context and total byte length) so truncated, oversized, or wrong-degree streams never decode; full-RNS polynomial imports (`Poly::try_convert_from(Vec<u64>)` at RNS length) enforce the same per-row canonical contract, while the shorter ordinary-integer path keeps its documented reduction semantics.
16. `RnsContext::lift` requires exactly one residue per basis modulus and each residue in `[0, modulus)`; wrong-length or out-of-range inputs are rejected fallibly without truncation or reinterpretation.
17. Every public RNS-matrix ingress (`TryConvertFrom<Array2<u64>>`, `Poly::set_coefficients`, `from_coeffs_matrix`) validates exact context shape and per-row canonicality before storing; no unchecked public setter exists.
18. Serialized raw importers (`RnsContextRaw`, `ScalingFactorRaw`, `RnsScalerRaw`, `ScalerRaw`) are untrusted transport DTOs carrying only authoritative inputs (modulus lists, scaling numerators/denominators); every derived value (products, CRT tables, Shoup/Garner data, scaler caches, common-moduli counts, zero-denominator checks) is recomputed through the canonical constructors, invalid authoritative inputs (empty/non-coprime bases, zero denominators) are rejected, and default scaling factors are the identity so no public constructor path yields a zero denominator.
19. Live NTT operators are exclusively constructor-derived from a valid modulus and size: the raw NTT serialization DTO and its importer were removed, so no path accepts independently supplied sizes, tables, Shoup values, or inverse metadata, and every table-derived value is produced together by `NttOperator::new`.
20. Optimized reduction and multiplication entry points require a modulus with `supports_opt`; the public u64/u128 and lazy scalar wrappers return the typed `UnsupportedOptimizedReduction` error for unsupported moduli (and `InvalidOptimizedReductionInput` for u128 inputs `>= p^2`), while vector operations keep a single `supports_opt` branch that calls an internal kernel, with the generic reduction as the fallback for unsupported moduli.

## Evidence / tests

Use proptest for zero, one, `-1`, modulus-minus-one, full residue ranges, centering boundaries, varying/empty/full-degree polynomials, limb counts, reordered valid bases, half-points on both sides, and BigInt/BigUint oracle comparisons; approximate corrections are tested only on explicitly approximate paths and `RnsScaler` has exact oracle equality. NTT operators keep constructor, forward/backward bijection, variable-time equivalence, and lazy-forward tests under both default and `tfhe-ntt` features, and the removed raw NTT DTO/importer has no remaining code, test, or benchmark callers in Rust source. `generate_prime` has invalid-input (`None`), NFLlib-vector, strict-upper-bound, modulo-one vacuous-congruence, and property coverage asserting primality, bit length, bound, and congruence. Optimized reduction is covered by typed unsupported-modulus and `p^2` input-bound error tests plus agreement between optimized and generic reduction on `supports_opt` moduli. Packed serialization has canonical round-trip proptests plus rejection tests for representatives in `[p, 2^nbits)` (including exactly `p` and the packed maximum; power-of-two moduli with empty noncanonical intervals are skipped) and partial coefficient streams; protobuf decoding additionally rejects wrong-degree messages and truncated/oversized streams through `Poly::from_bytes` in every representation. Full-RNS vector and matrix imports reject noncanonical rows; `set_coefficients` rejects malformed dimensions and noncanonical values; `lift` rejects wrong-length and out-of-range residues with a lift/project property test; raw importers are covered by rebuild-equivalence tests and rejection of empty/non-coprime bases, zero scaling denominators, and incompatible degrees. `shamir-rns` additionally tests the Barrett reduction backend, canonical rejection, fixed inversion, distinct points, and single/batch interpolation round trips.

## Sync

- Touch → update: `mathematics.md` — `crates/fhe-math/src/**`, `crates/shamir-rns/**`.
