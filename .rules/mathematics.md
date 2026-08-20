# Mathematical correctness

## Scope

`fhe-math` core arithmetic for HE: RNS basis representation/conversion/CRT, NTT transforms, modular reduction/Shoup/Barrett arithmetic, polynomial multiplication/division/centering/degree management, and scalar/coefficient conversions. The BFV implementation follows <https://eprint.iacr.org/2018/117> and <https://eprint.iacr.org/2021/204>.

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

## Evidence / tests

Use proptest for zero, one, `-1`, modulus-minus-one, full residue ranges, centering boundaries, varying/empty/full-degree polynomials, limb counts, reordered valid bases, half-points on both sides, and BigInt/BigUint oracle comparisons; approximate corrections are tested only on explicitly approximate paths and `RnsScaler` has exact oracle equality.

## Sync

- Touch → update: `mathematics.md` — `crates/fhe-math/src/**`.
