#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Render one `trckks_dkg_bench --app …` JSON file as a markdown row of the
`BENCHMARKS_TRCKKS.md` §6.3 measured-cost table (one row per committee
size in the file). Usage:

    python3 crates/fhe/scripts/trckks_bench_row.py /tmp/trckks-bench/secure-s1-stats-stats-n3.json

Append to the report with `>> crates/fhe/BENCHMARKS_TRCKKS.md` after
placing the cursor under the §6.3 table (or paste the printed line).
"""

import json
import sys


def fmt_bytes(b: float) -> str:
    for unit, div in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if b >= div:
            return f"{b / div:.2f} {unit}" if unit != "KiB" else f"{b / div:.1f} KiB"
    return f"{b:.0f} B"


def fmt_ms(ms: float) -> str:
    if ms >= 60_000:
        return f"{ms / 60_000:.1f} min"
    if ms >= 1000:
        return f"{ms / 1000:.2f} s"
    return f"{ms:.1f} ms"


def med(metrics: dict, key: str, default: float = float("nan")) -> float:
    entry = metrics.get(key)
    return entry["median"] if entry else default


def row(result: dict) -> str:
    m = result["metrics"]
    n = result["parties"]
    app = result.get("app") or "—"
    walls = med(m, "app.walls_close", float("nan"))
    walls_s = "✅" if walls == 1.0 else ("❌" if walls == 0.0 else "n/a")
    signs = ""
    if "app.signs_total" in m:
        signs = f" ({int(med(m, 'app.signs_correct'))}/{int(med(m, 'app.signs_total'))} signs)"
    return (
        f"| {result['preset']} | {app} | {n} | {result.get('users', '')} | "
        f"{fmt_ms(med(m, 'dkg.per_party_total_ms'))} | {fmt_bytes(med(m, 'dkg.dealt_bytes_per_party_out'))} | "
        f"{fmt_ms(med(m, 'relin.hybrid.per_party_ms'))} | {fmt_bytes(med(m, 'relin.upload_bytes_per_party'))} / "
        f"{fmt_bytes(med(m, 'relin.download_bytes_per_party'))} | {fmt_bytes(med(m, 'relin.hybrid.key_bytes'))} | "
        f"{fmt_bytes(med(m, 'app.user_ct_bytes'))} | {fmt_ms(med(m, 'app.eval_ms'))} | "
        f"{fmt_bytes(med(m, 'app.decrypt_share_bytes'))} | {fmt_ms(med(m, 'app.decrypt_combine_ms'))} | "
        f"{med(m, 'app.max_abs_error'):.1e} (rel {med(m, 'app.max_rel_error'):.1e}){signs} | "
        f"{int(med(m, 'app.sm_bits_used'))} / {int(med(m, 'app.sm_bits_required'))} {walls_s} | "
        f"{result['runs']} |"
    )


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for path in sys.argv[1:]:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        for result in doc["results"]:
            print(row(result))


if __name__ == "__main__":
    main()
