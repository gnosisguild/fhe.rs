# Mathematical correctness

## Domain

`fhe-math` provides the core arithmetic for all HE schemes. The key surfaces:

- **RNS** (Residue Number System) — basis representation, conversion, Chinese Remainder Theorem
- **NTT** (Number Theoretic Transform) — forward and inverse transforms, in-place operations
- **Modular arithmetic** — reduction, Shoup multiplication, Barrett reduction
- **Polynomial arithmetic** — multiplication, division, centering, degree management
- **Conversions** — between RNS and coefficient form, between scalar and polynomial representations

## Invariants to check

When reviewing or testing math changes, verify:

- NTT round-trips: forward then inverse recovers the original (within modular arithmetic).
- RNS conversions are lossless when the value is within the modulus bounds.
- Polynomial degree does not silently exceed expectations after multiplication.
- Modular reductions produce canonical or centered representatives as documented.
- Scalar-polynomial conversions preserve value across forms.

### RNS scaling and basis conversion

The BFV implementation follows the HPS family of RNS techniques in <https://eprint.iacr.org/2018/117> and uses multiplication strategies from <https://eprint.iacr.org/2021/204>. For changes to `rns`, `rq::scaler`, switching, or BFV multiplication support, also verify:

- **Basis identity** — source and destination moduli are pairwise coprime, ordered as expected by every precomputed table, and the product represented by a context is the product used by the scaling factor.
- **Centered input** — operations that interpret an RNS value as an integer use the documented centered representative. A residue-wise identity does not determine the intended lift without this convention.
- **Conversion class** — identify an operation as exact conversion, exact rounded scaling, or deliberately approximate extension. `RnsScaler` is intended to agree exactly with centered big-integer scaling; only an explicit `FastBaseExtension`-style path may expose a bounded source-modulus correction term.
- **Rounding semantics** — nearest, floor, and ceiling are not interchangeable. The current scaler rounds exact half-points toward positive infinity, including `-1/2 -> 0`; test positive and negative half-way cases against a big-integer oracle.
- **Fixed-point correction** — the current scaler uses fixed-point CRT quotient estimates, with nearest or directed rounding as specified for each term, not floating point. Preserve `theta_garner_shift`, accumulator-width, and truncation-error bounds when changing limb count or limb width. Apply the HPS floating-point error-region argument only if a floating-point implementation is introduced.
- **Staged scaling** — compare each switch and rounding stage with a big-integer oracle. Original HPS multiplication scales by `t/Q`; modified multiplication first rounds a `Q -> P` switch and later scales by `t/P`, so it need not equal a single direct rounding coefficient-for-coefficient.
- **No-wrap bounds** — the original HPS strategy requires temporary `QP` contexts large enough for the assumed unreduced tensor product. The modified strategy tensors modulo `QP` and instead requires correct staged modulus-switch bounds and cancellation of the unwanted `QP` multiple.
- **Decomposition/recomposition** — RNS or radix digits reconstruct the original polynomial modulo the source context, and each digit is paired with the corresponding evaluation-key component.

## Property tests

Prefer proptest for arithmetic behavior. Strategies should cover:

- Edge values: zero, one, `-1` (mod p), the modulus minus one
- Random values across the full residue range
- Values near modulus boundaries where centering or reduction changes representation
- Polynomials of varying degrees, including empty and full-degree
- Multiple RNS limb counts, valid reordered-basis conversion, and rejection only where identical contexts are required
- Positive and negative values immediately around rounding half-points
- Comparison with a `BigInt`/`BigUint` oracle for basis extension and rational scaling
- Approximate-extension correction terms only for paths explicitly documented as approximate; exact oracle equality for `RnsScaler`
