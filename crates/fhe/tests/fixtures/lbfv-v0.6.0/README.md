# l-BFV operational keys from v0.6.0

These public-key and relinearization-key bytes were written by unmodified
`30cce84140a0fa7ce7a39e40f4882dc0fef81820` (`v0.6.0`). The inputs are
deterministic test data. Use the parameter builder and RNG sequence in
[`released_0_6_keys_still_read_and_write_identically`](../../trlbfv_e2e.rs).

`pk-seeded.bin` and `rlk.bin` are the results of the original `to_bytes()`
calls. For `pk-explicit.bin`, the generator cleared `pk.seed` and rebuilt
each row with `Ciphertext::new(row.to_vec(), &params)` before serializing.
This clears each row's derived seed too, so the fixture contains both
polynomials of every row.

`rlk-level1.bin` uses the same secret and public key, a separate URS seed
`[8; 32]`, ciphertext level 1, key level 0, and `ChaCha8Rng::from_seed([54; 32])`
for `LBFVRelinearizationKey::new_leveled`. It was written by the same unmodified
v0.6.0 library.
