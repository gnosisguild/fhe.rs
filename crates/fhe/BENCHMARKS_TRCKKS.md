# Threshold-CKKS benchmarks: DKG, relinearization ceremony, threshold decryption

Measured with `crates/fhe/examples/trckks_dkg_bench.rs` on branch
`feat/ckks-encryption`. Raw results: `/tmp/trckks-bench/*.json` (+ `.log`).

## 1. Methodology

**What one run does (per committee size `n`, threshold `t = (n-1)/2`):**

1. **DKG** — every party: sample `sk_i` (CBD), build its pk share `-a·s_i + e_i`
   over a seed-derived CRP, Shamir-share `sk_i` and a fresh smudging polynomial
   `e_sm,i` (20-bit here) coefficient-wise over ALL RNS limbs, then aggregate
   the `[L, N]` rows it received from all `n` dealers. Aggregate the pk shares.
2. **Relin ceremony** — for every requested level `ℓ` (a key per level with
   ≥ 2 limbs; `all` = every level, `ladder` = the 24 sign-extraction
   multiplication levels `1+3i, 3+3i`): sample `u_i`, round 1, aggregate R1,
   round 2, aggregate R2 into the joint key. Every party aggregates
   (verify-by-determinism), so aggregation time is charged per party.
3. **Threshold decrypt** of a fresh level-0 ciphertext: `t+1` decryption
   shares + Lagrange combine; decode and check error.
4. **One multiply + relinearize + rescale at the deepest level** at which
   `Q_ℓ` still holds `Δ²` (level `L-2` for the 40/45-bit chains; level 0
   for the 36-bit stats shape), then threshold-decrypt the product.

**Timing.** `std::time::Instant` wall time of ONE party's work, release
build, single process. For per-party steps the median across the `n` parties
within a run is taken, then **min and median across runs** are reported
(3 runs for every preset except N=65536, 1 run — see §3.5). Parties run
sequentially; the inner Shamir dealing and Lagrange combine are
rayon-parallel across limbs/coefficients (11 cores), everything else is
single-threaded. Numbers are therefore per-party CPU wall time; committee
wall time ≈ max over parties + network.

**Bandwidth.** Exact `to_bytes()` lengths of what a party sends. Two
encodings matter for the formulas in §4:

- Polynomials (pk shares, relin shares/keys, decryption shares, ciphertexts)
  are bit-packed by `fhe-math`: **`N · log₂(Q_ℓ) / 8` bytes per poly.**
- Dealt Shamir shares are raw `u64` per coefficient per limb:
  **`8 · N · L` bytes per recipient per shared polynomial** (this is the
  BFV-plaintext transport payload interfold encrypts per recipient).

**Machine.** Apple M3 Pro (`sysctl -n machdep.cpu.brand_string`), 11 cores,
`hw.memsize` = 38654705664 (36 GiB), macOS 26.6.1, rustc stable release
profile.

**Presets.**

| preset | N | limbs | log₂Q | Δ | security |
|---|---|---|---|---|---|
| `demo512-2limb` | 512 | 45,45 | 90 | 2^40 | insecure demo |
| `stats512-3limb` | 512 | 36,36,36 | 108 | 2^40 | insecure demo (salary survey) |
| `demo512-ladder` | 512 | 45 + 37×40 | 1525 | 2^40 | insecure demo (12-iteration sign ladder) |
| `secure32768-L20` | 32768 | 45 + 19×40 | 805 | 2^40 | **128-bit** |
| `secure65536-ladder` | 65536 | 45 + 37×40 | 1525 | 2^40 | **128-bit** |

Security source: *Homomorphic Encryption Security Standard* (Albrecht,
Chase, Chen, Ding, Goldwasser, Gorbunov, Halevi, Hoffstein, Laine, Lauter,
Lepoint, Lokam, Micciancio, Moody, Morrison, Sahai, Vaikuntanathan; Nov 2018,
<https://homomorphicencryption.org/standard/>), Table 1, ternary secret,
classical 128-bit: **log₂Q ≤ 881 at N = 2¹⁵**. The table stops at 2¹⁵; the
N = 2¹⁶ bound **log₂Q ≤ 1772** is the same lattice-estimator extrapolation
used by Lattigo (`ring/params` default tables) and OpenFHE
(`StdLatticeParm` HEStd_128_classic, 2¹⁶ → 1772-ish). 805 < 881 and
1525 < 1772, both with margin. (Note the fork samples uniform-ternary
secrets via CBD(0.5); the HE-standard rows used are the ternary ones.)

Commands run (all from the repo root, `BENCH_MACHINE` exported for the JSON):

```
cargo build --release --example trckks_dkg_bench
./target/release/examples/trckks_dkg_bench --preset demo512-2limb   --parties 3,5,10 --runs 3 --json /tmp/trckks-bench/demo512-2limb.json
./target/release/examples/trckks_dkg_bench --preset stats512-3limb  --parties 3,5,10 --runs 3 --json /tmp/trckks-bench/stats512-3limb.json
./target/release/examples/trckks_dkg_bench --preset demo512-ladder  --parties 3,5,10 --runs 3 --json /tmp/trckks-bench/demo512-ladder.json
./target/release/examples/trckks_dkg_bench --preset secure32768-L20 --parties 3,5,10 --relin-levels all --runs 3 --json /tmp/trckks-bench/secure32768-L20.json
./target/release/examples/trckks_dkg_bench --preset secure65536-ladder --parties 3 --relin-levels ladder --runs 1 --json /tmp/trckks-bench/secure65536-ladder-n3.json
./target/release/examples/trckks_dkg_bench --preset secure65536-ladder --parties 5 --relin-levels ladder --runs 1 --json /tmp/trckks-bench/secure65536-ladder-n5.json
```

## 2. Measured results (summary tables)

All times are per party unless marked. `min/med` = min / median over runs.

### 2.1 DKG

| preset | n | sk sample | pk share | deal sk (Shamir) | deal e_sm | aggregate rx | **DKG total /party** | pk share | dealt /recipient (sk+e_sm) | dealt out /party | dealt committee |
|---|---|---|---|---|---|---|---|---|---|---|---|
| demo512-2limb | 3 | 0.00 ms | 0.02 ms | 4.2/4.4 ms | 4.7 ms | 0.0 ms | **8.1/9.2 ms** | 5.6 KiB | 16 KiB | 32 KiB | 96 KiB |
| demo512-2limb | 5 | 0.00 | 0.02 | 8.7/8.7 | 8.9 | 0.0 | **17.5/17.7** | 5.6 KiB | 16 KiB | 64 KiB | 320 KiB |
| demo512-2limb | 10 | 0.00 | 0.02 | 12.9/13.7 | 14.1 | 0.0 | **25.3/27.8** | 5.6 KiB | 16 KiB | 144 KiB | 1.41 MiB |
| stats512-3limb | 3 | 0.00 | 0.05 | 4.8/5.1 | 5.4 | 0.0 | **10.2/10.3** | 6.8 KiB | 24 KiB | 48 KiB | 144 KiB |
| stats512-3limb | 5 | 0.01 | 0.07 | 15.1/15.3 | 15.0 | 0.0 | **28.3/31.5** | 6.8 KiB | 24 KiB | 96 KiB | 480 KiB |
| stats512-3limb | 10 | 0.01 | 0.07 | 22.2/27.1 | 26.8 | 0.0 | **42.7/54.0** | 6.8 KiB | 24 KiB | 216 KiB | 2.11 MiB |
| demo512-ladder | 3 | 0.00 | 0.34 | 11.7/12.4 | 15.9 | 0.0 | **25.7/28.0** | 95.3 KiB | 304 KiB | 608 KiB | 1.78 MiB |
| demo512-ladder | 5 | 0.00 | 0.32 | 23.2/28.0 | 26.6 | 0.1 | **47.3/55.4** | 95.3 KiB | 304 KiB | 1.19 MiB | 5.94 MiB |
| demo512-ladder | 10 | 0.00 | 0.35 | 61.3/67.5 | 71.1 | 0.1 | **129/139** | 95.3 KiB | 304 KiB | 2.67 MiB | 26.7 MiB |
| secure32768-L20 | 3 | 0.24 | 15.7 | 384/470 | 508 | 2.0 | **901/1017** | 3.14 MiB | 10 MiB | 20 MiB | 60 MiB |
| secure32768-L20 | 5 | 0.23 | 15.1 | 1247/1343 | 1495 | 2.3 | **2627/2856** | 3.14 MiB | 10 MiB | 40 MiB | 200 MiB |
| secure32768-L20 | 10 | 0.23 | 14.5 | 2601/2960 | 2796 | 3.8 | **5414/5601** | 3.14 MiB | 10 MiB | 90 MiB | 900 MiB |
| secure65536-ladder | 3 | 0.45 | 57.5 | 2092 | 1864 | 8.4 | **4022** (1 run) | 11.9 MiB | 38 MiB | 76 MiB | 228 MiB |
| secure65536-ladder | 5 | 0.45 | 57 | 3797 | 5615 | 9 | **9527** (1 run) | 11.9 MiB | 38 MiB | 152 MiB | 760 MiB |

The DKG is dominated by Shamir dealing (BigInt polynomial evaluation per
coefficient per limb, `n` evaluations each); pk-share generation (one NTT
multiply) is negligible. Dealing cost grows ≈ linearly in `n·L·N`.

### 2.2 Relinearization ceremony (all levels run, totals per party)

| preset | n | levels | ceremony CPU /party (min/med) | upload /party (R1+R2, all levels) | download /party | committee bytes |
|---|---|---|---|---|---|---|
| demo512-2limb | 3 / 5 / 10 | 1 | 0.20 / 0.20 / 0.21 ms | 45.1 KiB | 90 KiB / 180 KiB / 406 KiB | 135 KiB / 226 KiB / 451 KiB |
| stats512-3limb | 3 / 5 / 10 | 2 | 0.9 / 0.9 / 0.8 ms | 117 KiB | 235 KiB / 469 KiB / 1.03 MiB | 352 KiB / 586 KiB / 1.15 MiB |
| demo512-ladder | 3 | 24 | 405 / 411 ms | 115.1 MiB | 230 MiB | 345 MiB |
| demo512-ladder | 5 | 24 | 392 / 393 ms | 115.1 MiB | 460 MiB | 575 MiB |
| demo512-ladder | 10 | 24 | 431 / 493 ms | 115.1 MiB | 1.01 GiB | 1.12 GiB |
| secure32768-L20 | 3 | 19 (all) | 10.4 / 13.9 s | **1.77 GiB** | 3.53 GiB | 5.30 GiB |
| secure32768-L20 | 5 | 19 (all) | 7.6 / 8.7 s | 1.77 GiB | 7.07 GiB | 8.84 GiB |
| secure32768-L20 | 10 | 19 (all) | 9.8 / 10.1 s | 1.77 GiB | 15.9 GiB | 17.7 GiB |
| secure65536-ladder | 3 | 24 (ladder) | 79.6 s (1 run) | **14.38 GiB** | 28.8 GiB | 43.2 GiB |
| secure65536-ladder | 5 | 25 (ladder + L35 mult check) | 82.3 s (1 run) | 14.39 GiB | 57.6 GiB | 72.0 GiB |

Per-level detail, `secure32768-L20`, n=5 (median of 3 runs; R1 share = R2
share = key size at that level):

| level | limbs | u gen | R1 gen | R1 agg | R2 gen | R2 agg | per party | share / key bytes |
|---|---|---|---|---|---|---|---|---|
| 0 | 20 | 5.9 ms | 323 ms | 71 ms | 292 ms | 405 ms | 1083 ms | 125.8 MiB |
| 1 | 19 | 5.3 | 283 | 60 | 274 | 384 | 1067 | 113.6 MiB |
| 2 | 18 | 5.1 | 266 | 82 | 244 | 366 | 1016 | 102.0 MiB |
| 3 | 17 | 4.8 | 235 | 49 | 215 | 312 | 824 | 91.0 MiB |
| 4 | 16 | 4.5 | 200 | 41 | 193 | 279 | 710 | 80.6 MiB |
| 5 | 15 | 4.1 | 179 | 49 | 167 | 237 | 638 | 70.9 MiB |
| 6 | 14 | 3.8 | 158 | 53 | 146 | 197 | 557 | 61.8 MiB |
| 7 | 13 | 3.6 | 134 | 38 | 143 | 196 | 543 | 53.3 MiB |
| 8 | 12 | 3.6 | 133 | 32 | 112 | 137 | 428 | 45.5 MiB |
| 9 | 11 | 3.2 | 97 | 23 | 92 | 134 | 348 | 38.2 MiB |
| 10 | 10 | 2.9 | 81 | 17 | 74 | 109 | 285 | 31.6 MiB |
| 11 | 9 | 2.6 | 65 | 15 | 63 | 94 | 240 | 25.7 MiB |
| 12 | 8 | 2.4 | 53 | 5 | 52 | 59 | 173 | 20.3 MiB |
| 13 | 7 | 2.3 | 42 | 4 | 41 | 46 | 134 | 15.6 MiB |
| 14 | 6 | 1.9 | 33 | 3 | 30 | 35 | 105 | 11.5 MiB |
| 15 | 5 | 1.6 | 23 | 2 | 21 | 30 | 91 | 8.0 MiB |
| 16 | 4 | 1.5 | 25 | 1 | 22 | 18 | 75 | 5.2 MiB |
| 17 | 3 | 1.3 | 10 | 1 | 9 | 9 | 31 | 2.9 MiB |
| 18 | 2 | 0.9 | 5 | 0 | 6 | 4 | 16 | 1.3 MiB |

Per-level detail, `secure65536-ladder`, n=3 (1 run), ladder levels only:

| level | limbs | R1 gen | R1 serialize | R1 agg | R2 gen | R2 agg | per party | share / key bytes |
|---|---|---|---|---|---|---|---|---|
| 1 | 37 | 2757 ms | 4634 ms | 1012 ms | 2253 ms | 3718 ms | 9764 ms | 858.5 MiB |
| 3 | 35 | 2122 | 4050 | 712 | 1948 | 3600 | 8403 | 768.4 MiB |
| 4 | 34 | 1885 | 6542 | 1022 | 3463 | 6448 | 12839 | 725.2 MiB |
| 6 | 32 | 2238 | 3370 | 496 | 1642 | 2547 | 6954 | 642.5 MiB |
| 7 | 31 | 1817 | 3046 | 706 | 1530 | 2222 | 6301 | 603.1 MiB |
| 9 | 29 | 1393 | 3451 | 712 | 1310 | 1906 | 5341 | 527.9 MiB |
| 10 | 28 | 1529 | 2091 | 202 | 1189 | 1971 | 4908 | 492.2 MiB |
| 12 | 26 | 1117 | 1931 | 131 | 1055 | 1530 | 3847 | 424.5 MiB |
| 13 | 25 | 1011 | 1641 | 77 | 944 | 1301 | 3347 | 392.6 MiB |
| 15 | 23 | 861 | 1433 | 75 | 850 | 1039 | 2839 | 332.4 MiB |
| 16 | 22 | 805 | 1438 | 85 | 759 | 953 | 2615 | 304.2 MiB |
| 18 | 20 | 637 | 1080 | 55 | 590 | 742 | 2036 | 251.6 MiB |
| 19 | 19 | 593 | 968 | 60 | 550 | 709 | 1923 | 227.1 MiB |
| 21 | 17 | 486 | 784 | 41 | 448 | 577 | 1563 | 182.0 MiB |
| 22 | 16 | 432 | 697 | 36 | 397 | 500 | 1374 | 161.3 MiB |
| 24 | 14 | 329 | 537 | 26 | 316 | 349 | 1028 | 123.6 MiB |
| 25 | 13 | 319 | 465 | 32 | 266 | 321 | 946 | 106.6 MiB |
| 27 | 11 | 216 | 1860 | 259 | 1512 | 226 | 2220 | 76.5 MiB |
| 28 | 10 | 173 | 264 | 13 | 163 | 178 | 534 | 63.3 MiB |
| 30 | 8 | 111 | 160 | 7 | 103 | 114 | 340 | 40.6 MiB |
| 31 | 7 | 83 | 123 | 5 | 80 | 83 | 255 | 31.2 MiB |
| 33 | 5 | 44 | 64 | 4 | 41 | 42 | 135 | 16.0 MiB |
| 34 | 4 | 31 | 42 | 2 | 28 | 28 | 92 | 10.3 MiB |
| 36 | 2 | 9 | 11 | 0 | 9 | 7 | 26 | 2.7 MiB |

(`R1 serialize` is the protobuf encoding of ONE share — it is NOT included
in `per party` but a real node pays it; at N=65536 it exceeds R1 generation
itself. Levels 4 and 27 show memory-pressure outliers of a single run.)

### 2.3 Threshold decryption

| preset | n | fresh ct | dec share (t+1 parties each) | share bytes | combine (Lagrange, t+1 shares) | max abs err | deepest-level ct | dec share @deep | combine @deep |
|---|---|---|---|---|---|---|---|---|---|
| demo512-2limb | 3/5/10 | 11.3 KiB | 0.01 ms | 5.6 KiB | 0.8 / 1.4 / 3.2 ms | 3e-5 | 5.7 KiB | 0.01 ms | 0.5 / 0.7 / 1.7 ms |
| stats512-3limb | 3/5/10 | 13.5 KiB | 0.01–0.04 ms | 6.8 KiB | 1.8 / 3.5 / 6.6 ms | 3e-5 | 13.5 KiB (L0) | 0.01 ms | 1.8 / 3.5 / 6.6 ms |
| demo512-ladder | 3/5/10 | 190.7 KiB | 0.16 ms | 95.3 KiB | 12.5 / 20.2 / 55.0 ms | 5e-5 | 5.7 KiB | 0.01 ms | 0.5 / 0.7 / 1.8 ms |
| secure32768-L20 | 3/5/10 | 6.29 MiB | 8.5–24 / 9.9 / 8.6 ms | 3.14 MiB | 726 / 910 / 1387 ms | 2e-4 | 360 KiB | 0.55 ms | 23 / 40 / 78 ms |
| secure65536-ladder | 3 | 23.8 MiB | 34 ms | 11.9 MiB | 1329 ms | 7e-5 | 720 KiB | 1.15 ms | 50 ms |
| secure65536-ladder | 5 | 23.8 MiB | 39 ms | 11.9 MiB | 3243 ms | 2e-4 | 1.1 MiB (L35) | 2.2 ms | 145 ms |

Combine is the BigInt Lagrange interpolation over `N · L_ℓ` coefficients;
it scales with `(t+1)² · N · L_ℓ` and dominates decryption at level 0.
Opening at the END of a circuit (few limbs left) is 20–60× cheaper.

### 2.4 Multiply + relinearize + rescale at the deepest keyed level

| preset | level (limbs) | mul | relin | rescale | product max abs err (n=3 / 5 / 10) |
|---|---|---|---|---|---|
| demo512-2limb | 0 (2) | 0.01 ms | 0.02 ms | 0.01 ms | 9e-4 / 6e-4 / 7e-4 |
| stats512-3limb | 0 (3) | 0.01 | 0.04 | 0.01 | 7e-7 / 4e-7 / 2e-6 |
| demo512-ladder | 36 (2) | 0.01 | 0.02 | 0.01 | 1e-4 / 9e-5 / 2e-4 |
| secure32768-L20 | 18 (2) | 0.71 | 2.5 | 1.3 | **0.065 / 0.135 / 0.203** |
| secure65536-ladder | 36 (2) | 0.90 | 15.4 | 5.4 | **0.108** |
| secure65536-ladder (n=5) | 35 (3) | — | 6.2 | — | **0.103** |

Operands were `[1.5, -2.0] × [2.0, 4.0]` (products 3, -8). At N=512 the
multiparty relin error is ~1e-4; at N=32768/65536 it is **1–3 % of the value
and grows ~linearly in `n`** — see §5 lever 5.

## 3. Scaling analysis

### 3.1 Notation

- `N` degree, `L` limbs at level 0, `L_ℓ = L − ℓ` limbs at level `ℓ`,
  `b` ≈ bits per limb (40–45), `log₂Q_ℓ ≈ b·L_ℓ`, `n` parties, `t = (n−1)/2`.
- `P_ℓ = N · log₂Q_ℓ / 8 ≈ N·L_ℓ·b/8` bytes — one bit-packed polynomial at
  level `ℓ` (pk share, ct component, decryption share, relin share element).

### 3.2 Bandwidth formulas (validated against the measurements)

| object | formula | check |
|---|---|---|
| dealt shares, per recipient, per shared poly | `8·N·L` (raw u64) | N=32768, L=20: 5.00 MiB ✓ |
| dealt shares, per party out (sk + e_sm) | `2 · 8·N·L · (n−1)` | n=10: 90.0 MiB ✓ |
| dealt shares, committee | `2 · 8·N·L · n(n−1)` | n=10: 900 MiB ✓ |
| pk share / fresh ct component / dec share | `P_0` | N=32768: 3.14 MiB ✓ |
| relin R1 share = R2 share = key, level ℓ | `2·L_ℓ · P_ℓ ≈ N·L_ℓ²·b/4` | N=32768, ℓ=0: 125.8 MiB ✓; N=65536, ℓ=1: 858.5 MiB ✓ |
| ceremony upload per party (levels set S) | `Σ_{ℓ∈S} 4·L_ℓ·P_ℓ ≈ (N·b/2)·Σ L_ℓ²` | all 19 levels N=32768: 1.77 GiB ✓; ladder N=65536: 14.38 GiB ✓ |
| ceremony download per party | `(n−1) ×` upload | |
| ceremony committee volume | `n ×` upload | |

The ceremony is the only term quadratic in the limb count; with all
levels keyed, `Σ_{ℓ} L_ℓ² ≈ L³/3`, so **ceremony volume ∝ N·L³**, dealt
shares ∝ `N·L·n²` (committee) and everything else ∝ `N·L`.

### 3.3 Compute formulas (fitted to the measurements)

- **Shamir dealing** (sk or e_sm), per party: ≈ `c_deal · n · N · L` with
  `c_deal ≈ 0.4 µs` per (coefficient·limb·party) at N=32768 and 11 cores
  (n=5, L=20: 1.34 s measured; formula 1.31 s). Sub-linear in `n` at tiny N
  because of per-limb rayon overhead.
- **Relin per level, per party**: R1 gen and R2 gen are each `2·L_ℓ`
  NTT-domain multiply-adds over `P_ℓ`; measured ≈ `12–16 ns · N · L_ℓ²`
  for gen and a similar amount for the two aggregations (the aggregations
  cost ≈ `n` poly additions each and dominate at n=10). Rule of thumb from
  the tables: **≈ 0.55 ms per (N/1024)·L_ℓ² at n=3–5**, 1.5× that at n=10.
- **Combine**: BigInt Lagrange, ≈ `2.2 µs · (t+1)² · N · L_ℓ / 11 cores`;
  the measured N=32768 level-0 combine (0.7 → 0.9 → 1.4 s for n=3,5,10) is
  sub-quadratic because the `t+1` inner loop is short.

### 3.4 MEASURED vs EXTRAPOLATED

**Measured** (this report, tables in §2):

- `demo512-2limb`, `stats512-3limb`, `demo512-ladder`: n ∈ {3, 5, 10}, 3 runs.
- `secure32768-L20`: n ∈ {3, 5, 10}, ALL 19 levels, 3 runs.
- `secure65536-ladder`: n = 3, the 24 ladder levels, 1 run (9.5 min, ~5 GiB
  RSS peak).
- `secure65536-ladder`: n = 5, the 24 ladder levels + level 35, 1 run
  (8.2 min, ~3 GiB RSS after the memory-lean change).

**Extrapolated** (formulas in §3.2/3.3, marked ⚠ in §4). N=65536 at n=10 and
n=20, N=32768 at n=20, and ceremony byte counts for level subsets not run.

### 3.5 Why N=65536 was not run at n=10

One n=3 run takes 9.5 min, n=5 8.2 min (the bench drops each level's
shares before the next). Per-party ceremony CPU is nearly flat in `n`
(79.6 s → 82.3 s; only the two aggregations grow, 1.0 → 1.9 s and
3.7 → 6.7 s at level 1) and the byte formulas are exact, so n=10 adds no
information the n=3/n=5 pair does not already pin down; it would cost
≈ 20 min and hold `2n` shares of up to 860 MiB each in flight. n=10 and
n=20 at N=65536 are therefore extrapolated with the measured n-slopes.

## 4. Path to production

Wall-time model per party: `DKG + ceremony(S) + serialize + transfer`, where
transfer = bytes / link rate. Below uses the measured per-party CPU numbers
and a 100 Mbit/s effective peer link (12.5 MB/s) for the network column;
scale by your actual link. Ceremony bytes assume the **full level set**
needed by the circuit (19 levels for L20; the 24 ladder levels for L39).

### 4.1 N = 32768, L = 20 (128-bit), all 19 levels keyed

| committee | DKG CPU /party | dealt out /party | ceremony CPU /party | ceremony up /party | ceremony down /party | committee volume | wire time @100 Mbit/s (up+down) |
|---|---|---|---|---|---|---|---|
| 5 (measured) | 2.9 s | 40 MiB | 8.7 s | 1.77 GiB | 7.07 GiB | 8.84 GiB | ≈ 12 min |
| 10 (measured) | 5.6 s | 90 MiB | 10.1 s | 1.77 GiB | 15.9 GiB | 17.7 GiB | ≈ 25 min |
| 20 ⚠ | ≈ 11 s | 190 MiB | ≈ 13 s | 1.77 GiB | 33.6 GiB | 35.4 GiB | ≈ 50 min |

### 4.2 N = 65536, ladder L = 38 (128-bit), the 24 ladder levels keyed

| committee | DKG CPU /party | dealt out /party | ceremony CPU /party | ceremony up /party | ceremony down /party | committee volume | wire time @100 Mbit/s |
|---|---|---|---|---|---|---|---|
| 3 (measured) | 4.0 s | 76 MiB | 80 s (+ ≈ 45 s serialize) | 14.4 GiB | 28.8 GiB | 43.2 GiB | ≈ 1 h |
| 5 (measured) | 9.5 s | 152 MiB | 82 s (+ ≈ 45 s serialize) | 14.4 GiB | 57.6 GiB | 72.0 GiB | ≈ 1.7 h |
| 10 ⚠ | ≈ 20 s | 342 MiB | ≈ 95 s | 14.4 GiB | 129 GiB | 144 GiB | ≈ 3.4 h |
| 20 ⚠ | ≈ 40 s | 722 MiB | ≈ 120 s | 14.4 GiB | 273 GiB | 288 GiB | ≈ 6.7 h |

**Reading these:** compute is a non-issue everywhere (seconds to ~2 min per
party, once). The DKG transport is modest (≤ 1 GiB committee-wide at n=20).
The relinearization ceremony's **download volume ∝ n · N · Σ L_ℓ²** is the
only thing that does not fit a commodity node at the ladder shape: 14.4 GiB
upload and 130–270 GiB download per node, plus the same again in DHT
storage if shares are content-addressed and replicated (which is what
broke live run 13 at the demo shape already).

### 4.3 Levers, in order of leverage

1. **Seed-compressed CRP / "a" halves (−50 % of ceremony bytes).** Both R1
   and R2 shares carry `h1`, whose aggregate `Σ a_j·s_i + e` is the key's
   `c1`; the `a_j` themselves are seed-derived, but `h1` is not
   compressible. What IS compressible: the R2 `h1'` and the final key's `c1`
   are re-derivable from R1's aggregate, and the ceremony already ships
   `R1Aggregated` back to parties — a node that holds `r1_agg` needs only
   `h0'` from each R2 share. Sending `h0'` only in round 2 removes 25 % of
   the ceremony bytes today; making the key's `c1` a seed (the single-key
   `CkksRelinearizationKey::new_leveled` already generates `c1` from a
   seed) removes another quarter of the stored key. Net ≈ −50 % on the
   wire for the same protocol.
2. **Generate only the levels the circuit multiplies at (−60–90 %).** The
   L20 numbers above key all 19 levels; the statistics policy needs ONE
   (level 0), the sign ladder needs 24 of 37. `Σ L_ℓ²` for the ladder set is
   already 2/3 of the full-chain sum, so the win is small for the ladder
   but total for shallow policies: a 1-level policy at N=32768/L20 is
   126 MiB up / 1.1 GiB down at n=10 instead of 1.77 / 15.9 GiB.
3. **Fewer sign-extraction iterations (cubic in fewer limbs).** Ceremony
   volume ∝ `Σ L_ℓ²` ≈ `L³/3`. Each iteration removed drops 3 limbs:
   12 → 8 iterations (L 38 → 26) cuts ceremony bytes by ≈ 3.1× AND the DKG
   payload by 32 %; log₂Q falls to 1045 bits — still above the 881-bit
   N=32768 ceiling, so N=65536 stays required (with a wide margin), unless
   the ladder is narrowed to ~2^36 limbs. The 2 %-gap binarization needs
   12 iterations at f(y)=(1.5−0.5y²)y;
   a better-conditioned polynomial (e.g. the composite minimax
   polynomials of Lee–Lee–Kim–No 2021, degree-7 blocks) reaches the same
   gap in ~5 levels-per-iteration-equivalents, i.e. ≈ half the limbs.
4. **Key-switching-key hoisting / hybrid key switching (the structural
   fix).** The RNS-decomposition key has `L_ℓ` decomposition digits, so
   key size ∝ `L_ℓ²`. Hybrid (special-modulus, `dnum` digits) key switching
   — Han–Ki 2019 / the "CKKS with special primes" variant already noted as
   the natural follow-up in `relin_key.rs` — shrinks the key to
   `dnum · (L_ℓ + k)` polys with `dnum` ≈ 2–4: **≈ 10× smaller keys at
   L=37**, and the same factor on both ceremony rounds because Protocol 2
   is digit-agnostic (each `h0[j]/h1[j]` becomes one per digit). Combined
   with lever 1 this brings the n=10 ladder from 129 GiB to ≈ 6–8 GiB
   download per node. It also fixes lever 5's noise. This is the item to
   build.
5. **Precision at scale (must fix before any secure deployment).** Table
   2.4 shows the multiparty relinearized product is off by 1–3 % at
   N ≥ 32768 (vs 1e-4 at N=512): key-switch noise ∝ `n · N · q_max · B_err`
   and N grew 64–128×. With Δ = 2^40 over 40/45-bit limbs the rescale
   cannot absorb it. Options: hybrid key switching (lever 4) with a special
   prime P ≈ q_max divides the noise by P; or Δ = 2^45–2^50 with 50-bit
   limbs (costs limbs → security budget); or relinearize before rescale at
   the widest level only. Any of these must be re-verified with the
   `mult.max_abs_error` metric this benchmark prints.
6. **Operational**: publish shares per level as they are produced (already
   chunked in interfold), keep R1 aggregates in RAM only for the level in
   flight (the bench drops each level's shares before the next, peaking at
   ≈ 5 GiB for n=3 at N=65536 — a node at n=10 needs ≈ 17 GiB without this
   discipline), and never snapshot share buffers.

### 4.4 Recommendation

- **Statistics / shallow policies at N=32768, L≤20**: production-shaped
  today. DKG ≈ 3–6 s per party, 40–90 MiB of dealt shares out, one or two
  keyed levels ⇒ ≤ 250 MiB ceremony upload, ≤ 2.3 GiB download at n=10,
  ≈ 4 min on a 100 Mbit link. Ship with lever 2 (only keyed levels) and
  the precision fix of lever 5 verified for the actual policy depth.
- **Sign-extraction winner mode at 128-bit (N=65536, 39 limbs)**: not
  deployable on the current key-switching design — 14 GiB up / 130 GiB
  down per node at n=10 and 1–3 % relin error. Order of work:
  (a) hybrid key switching in `ckks/relin_key.rs` + digit-aware
  `trckks/relin_gen.rs` (lever 4, fixes 5), (b) drop `h1'` from round 2
  and seed the key's `c1` (lever 1), (c) shorten the ladder with a
  better sign polynomial (lever 3). Target after (a)+(b): ≈ 0.7 GiB up,
  ≈ 6 GiB down per node at n=10, ≈ 1.5 min of CPU, ≈ 10 min on a 100 Mbit
  link — a one-time cost per committee that is acceptable.
- Re-run `trckks_dkg_bench --preset secure65536-ladder --parties 5,10`
  after (a) to replace the ⚠ rows with measurements; the JSON schema is
  stable so the tables can be regenerated from `/tmp/trckks-bench/*.json`.

## 5. Hybrid key switching (measured, 2026-09-02)

Lever 4 of §4.3 is now implemented: `ckks/hybrid.rs` (single-key
`CkksHybridRelinKey` / generic `CkksHybridKeySwitchKey`) and
`trckks/hybrid_gen.rs` (two-round multiparty `CkksHybridRelinKeyGenerator`,
same Protocol 2 over `Q·P` with the digit gadget). Reference: Han–Ki,
*Better Bootstrapping for Approximate HE* (eprint 2019/688 §3); RNS form as
Lattigo `rlwe` `GadgetProduct` / `RKGProtocol`. Enabled per parameter set by
`CkksParametersBuilder::set_special_moduli_sizes(&[k × 60])` (+ optional
`set_dnum`); ciphertexts stay over `Q`, only key material carries the `P`
limbs. Default digit size `alpha = k` limbs ⇒ `dnum = ceil(L/k)`.

**What changes structurally.** The RNS-decomposition key has `L_ℓ` digits
of `L_ℓ` limbs at EVERY level (`2·L_ℓ²` polys per level, `Σ_ℓ L_ℓ² ≈ L³/3`
for a full ladder). The hybrid key has `dnum` digits of `L + k` limbs ONCE
(`2·dnum·(L+k)` polys, all levels). Key-switch noise drops from
`≈ n·L_ℓ·q_max·N·B_err` to `≈ n·dnum·N·B_err·D_j/P` (`D_j ≤ 2^{40k+5}`,
`P = 2^{60k}` ⇒ ÷ 2^{~20k}), which is what fixes the 1–3 % secure-N relin
error of §2.4.

Commands (same presets/rows as §1; `--chain-compare` also runs the four
RNS level-0..3 ceremonies to measure the depth-4 chain under BOTH keys):

```
cargo build --release --example trckks_dkg_bench
./target/release/examples/trckks_dkg_bench --preset demo512-2limb      --parties 3,5,10 --runs 3 --keyswitch hybrid --special-primes 1 --json /tmp/trckks-bench/hybrid-demo512-2limb.json
./target/release/examples/trckks_dkg_bench --preset demo512-ladder     --parties 3,5,10 --runs 3 --keyswitch hybrid --special-primes 3 --chain-compare --json /tmp/trckks-bench/hybrid-demo512-ladder.json
./target/release/examples/trckks_dkg_bench --preset secure32768-L20    --parties 3,5    --runs 3 --keyswitch hybrid --special-primes 2 --chain-compare --json /tmp/trckks-bench/hybrid-secure32768-L20.json
./target/release/examples/trckks_dkg_bench --preset secure65536-ladder --parties 3      --runs 1 --keyswitch hybrid --special-primes 3 --chain-compare --json /tmp/trckks-bench/hybrid-secure65536-ladder-n3.json
./target/release/examples/trckks_dkg_bench --preset secure65536-ladder --parties 5      --runs 1 --keyswitch hybrid --special-primes 3 --json /tmp/trckks-bench/hybrid-secure65536-ladder-n5.json
```

### 5.1 Ceremony: hybrid (ONE key, all levels) vs RNS (per-level keys, §2.2)

| preset | n | k / dnum | RNS levels keyed | **RNS up /party** | **hybrid up /party** | RNS down /party | **hybrid down /party** | RNS ceremony CPU | **hybrid CPU** | RNS key(s) | **hybrid key** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| demo512-2limb | 3 / 5 / 10 | 1 / 2 | 1 | 45.1 KiB | 75.2 KiB | 90 / 180 / 406 KiB | 150 / 301 / 677 KiB | 0.2 ms | 0.18–0.20 ms | 22.5 KiB | 37.6 KiB |
| demo512-ladder | 3 / 5 / 10 | 3 / 13 | 24 (ladder) | 115.1 MiB | **5.41 MiB** (÷ 21) | 230 MiB / 460 MiB / 1.01 GiB | 10.8 / 21.7 / 48.7 MiB | 405–493 ms | **10.8–13.0 ms** | 57.5 MiB (24 keys) | **2.71 MiB** |
| secure32768-L20 | 3 | 2 / 10 | 19 (all) | 1.77 GiB | **144.5 MiB** (÷ 12.5) | 3.53 GiB | **289 MiB** | 10.4–13.9 s | **0.33–0.36 s** | 0.88 GiB (19 keys) | **72.3 MiB** |
| secure32768-L20 | 5 | 2 / 10 | 19 (all) | 1.77 GiB | 144.5 MiB | 7.07 GiB | **578 MiB** | 7.6–8.7 s | **0.35–0.44 s** | 0.88 GiB | 72.3 MiB |
| secure65536-ladder | 3 | 3 / 13 | 24 (ladder) | 14.38 GiB | **693 MiB** (÷ 21) | 28.8 GiB | **1.35 GiB** | 79.6 s (+45 s ser.) | **1.72 s** (+1.4 s ser.) | 7.19 GiB (24 keys) | **346 MiB** |
| secure65536-ladder | 5 | 3 / 13 | 24 (+L35) | 14.39 GiB | 693 MiB | 57.6 GiB | **2.71 GiB** | 82.3 s | **1.80 s** | 7.19 GiB | 346 MiB |

(`hybrid up` = R1 + R2 share = 2 × key bytes; `down` = `(n−1) ×` up. The
"RNS key(s)" column is the sum of the per-level keys a node must store;
the hybrid key alone serves every level — 37 levels at the ladder.)

Per-party hybrid ceremony detail (median): `secure32768-L20` n=5 — u gen
4.8 ms, R1 gen 182 ms, R1 serialize 299 ms, R1 agg 46 ms, R2 gen 169 ms,
R2 agg 36 ms; `secure65536-ladder` n=3 — u gen 26 ms, R1 gen 844 ms, R1
serialize 1394 ms, R1 agg 73 ms, R2 gen 713 ms, R2 agg 69 ms. Whole-bench
wall time (DKG + ceremony + decrypt + chain, 1 run) at N=65536: 4.3 min at
n=3 (incl. the four RNS comparison ceremonies), 2.4 min at n=5 — vs 8–10
min before, with no 860 MiB shares in flight.

At the 2-limb demo shape hybrid is 1.7× LARGER (`dnum·(L+k) = 2·3 = 6`
polys vs `L² = 4`): the win is `L/dnum`-fold and only starts at `L ≥ 4`.

### 5.2 Precision: relin error, hybrid vs RNS

`mult.max_abs_error` is the §2.4 metric (one product of `[1.5,-2]×[2,4]` at
the deepest keyed level, threshold-decrypted). `chain_rel_error` is new:
the max RELATIVE error of `x^16` after a depth-4 mul→relin→rescale chain
from level 0 (joint-secret decrypt), under the RNS level keys and under the
one hybrid key, same run.

| preset | n | RNS product abs err (§2.4) | **hybrid product abs err** | RNS depth-4 rel err | **hybrid depth-4 rel err** |
|---|---|---|---|---|---|
| demo512-2limb | 3 / 5 / 10 | 9e-4 / 6e-4 / 7e-4 | 5e-4 / 6e-4 / 2e-3 | — | 3e-9 / 2e-8 / 1e-8 |
| demo512-ladder | 3 / 5 / 10 | 1e-4 / 9e-5 / 2e-4 | 2e-5 / 1e-5 / 2e-5 | 5.4e-4 / 1.3e-3 / 8.2e-4 | **4.6e-8 / 6.0e-8 / 1.5e-7** |
| secure32768-L20 | 3 / 5 | 0.065 / 0.135 | **1.3e-4 / 2.5e-4** | **5.3 / 0.97** (garbage) | **3.7e-6 / 6.9e-6** |
| secure65536-ladder | 3 / 5 | 0.108 / 0.103 | **2.5e-4 / 4.0e-4** | **6.5** (garbage) / — | **9.2e-6 / 9.2e-6** |

The RNS depth-4 chain at secure N does not decrypt at all (relative error
≥ 1: each of the four relinearizations injects ~1–3 % noise that the next
squaring amplifies), while the hybrid chain is at 1e-5 — the ×500
single-product improvement (0.1 → 2.5e-4) becomes a ×10⁵–10⁶ gap over a
real circuit. The unit test
`trckks::hybrid_gen::tests::hybrid_vs_rns_depth_four_multiparty_precision_and_size`
(N=8192, 8 limbs, n=5) pins this: RNS 5e-2..4e-1 vs hybrid ≤ 2e-6 run to
run, asserting ≥ 10× and correct decryption, plus the key-size bound
`hybrid ≤ (dnum·(L+k)/Σ L_ℓ² + 5 %) × Σ per-level keys` (measured 21.5 %
vs bound 19.7 %+5 %). `ckks::hybrid::tests::single_key_sign_extraction_ladder_n512`
runs the 12-iteration sign-extraction chain (45 + 37×40 bits, Δ=2^40, k=3)
with ONE key and decrypts saturated ±1 within 0.05.

Relinearization cost per operation rises (`mult.relin_ms`: 2.5 → 10.5 ms
at N=32768/L20, 15.4 → 20 ms at N=65536) because the hybrid switch does
`dnum` basis extensions to `L_ℓ + k` limbs plus a mod-down; still
negligible against the ceremony.

### 5.3 Updated path to production

Wall-time model as in §4 (per-party CPU + bytes / 100 Mbit/s):

| shape | committee | ceremony CPU /party | up /party | down /party | committee volume | wire @100 Mbit/s | relin err (depth-4 chain) |
|---|---|---|---|---|---|---|---|
| N=32768, L=20, hybrid k=2 | 5 (measured) | 0.4 s | 145 MiB | 578 MiB | 723 MiB | ≈ 1 min | 7e-6 |
| N=32768, L=20, hybrid k=2 | 10 ⚠ | ≈ 0.6 s | 145 MiB | 1.27 GiB | 1.41 GiB | ≈ 2 min | — |
| N=65536, ladder L=38, hybrid k=3 | 5 (measured) | 1.8 s (+1.4 s ser.) | 693 MiB | 2.71 GiB | 3.38 GiB | ≈ 5 min | 9e-6 |
| N=65536, ladder L=38, hybrid k=3 | 10 ⚠ | ≈ 2.2 s | 693 MiB | 6.1 GiB | 6.8 GiB | ≈ 10 min | — |
| N=65536, ladder L=38, hybrid k=3 | 20 ⚠ | ≈ 3 s | 693 MiB | 12.9 GiB | 13.5 GiB | ≈ 20 min | — |

Compared with §4.2 (129 GiB down per node at n=10, 1–3 % relin error) the
sign-extraction winner mode at 128-bit is now inside the "one-time cost per
committee" envelope the §4.4 recommendation asked for, with the precision
problem gone. Remaining levers, in order: (b) lever 1 (send only `h0'` in
round 2 and seed the key's `a_j` from the CRP seed — the `a_j` of a hybrid
key ARE `h1` of round 1, so a party holding `r1_agg` needs only `h0'`:
another −25 % up / −50 % stored key), (c) lever 3 (shorter ladder), and
tuning `k`/`dnum` per shape: larger `k` (fewer, bigger digits) shrinks the
key ∝ `1/k` at the cost of `k` more limbs per poly and a larger `Q·P` for
the security estimate. **The HE-standard bound applies to `Q·P`, not `Q`:**
`log₂(Q·P)` = 805 + 120 = **925 > 881** at `secure32768-L20` with k=2
(60-bit) — the measured rows above are therefore NOT 128-bit as run; use
k=1 (60-bit, `Q·P` = 865 bits, dnum=20) or two 38-bit special primes
(`Q·P` = 881) there, or drop one 40-bit limb. At the ladder,
1525 + 180 = 1705 < 1772 holds with k=3. Re-run the L20 row with the
chosen `--special-primes` before quoting it as secure.

Operational: the interfold ceremony machine can drop the per-level loop —
one `(round, chunk)` stream per party; `CkksHybridRelinKeyShare::to_bytes`
is 72 MiB at L20 / 346 MiB at the ladder (still > the 25 MiB DHT document
cap, so chunking stays).
