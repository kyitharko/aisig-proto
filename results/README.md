# results/

Generated outputs. Do not edit by hand.

| File | What | Status |
| --- | --- | --- |
| `case_comparison.md`, `.json` | `cargo run --release --bin eval` over chain and lookup labels | current (r3.1) |
| `session_cases.md`, `.json` | same run, RQ5 session-slice labels (34 reviewed) | current (s1) |
| `enforcement_cases.md`, `.json` | same run, RQ6 enforcement labels (28 reviewed) | current (e2) |
| `freshness_cases.md`, `.json` | same run, RQ7 freshness-slice labels (34 reviewed) | current (f2) |
| `rq8_privacy.md`, `.json` | same run, RQ8 Q1 privacy slice: field disclosure + linkability (16 reviewed) | current |
| `rq8_latency.md`, `.json` | same run, RQ8 Q2 latency slice: modeled responder-delay scenarios (6 reviewed) | current |
| `rq8_onboarding.md`, `.json` | same run, RQ8 Q3 onboarding slice: per-party step inventory + artifact byte sizes (17 reviewed) | current |
| `bench_20261017T025341Z.md`, `.json` | `scripts/bench.sh`, git `8309871`, HEAD rerun for the RQ8 Q2 slice (same machine) | current (RQ8 Q2) |
| `bench_20261015T201455Z.md`, `.json` | `scripts/bench.sh`, git `21487fc`, after the negative-ε rejection in the time paths | **historical (round 3)** |
| `bench_20261014T192333Z.md`, `.json` | `scripts/bench.sh`, git `526a3c6`, exact-object status keys | **historical (r3)** |
| `bench_20261014T183348Z.md`, `.json` | `scripts/bench.sh`, git `9412502`, status keyed by (id, version) | **historical (r2)**; the status stage it measured no longer exists |

RQ7 `tests/cases/freshness_cases.toml` (34 reviewed, f2) is matched by the RQ7 implementation
and reported in `freshness_cases.md`/`.json`; the owner has approved all 34 expected outcomes.

Benchmark file timestamps are UTC; the current run is `bench_20261017T025341Z` (2026-10-17 UTC).
