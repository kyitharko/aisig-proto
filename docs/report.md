# Stage 1–4 report — RQ4 chain verifier prototype

**Date:** 2026-10-15. **Branch:** `feature/chain-verifier-prototype` (local only).
All numbers below were produced by the commands listed; files in `results/` are the raw
outputs. Nothing here is extrapolated.

## Research-question status

| RQ | Status in this prototype |
| --- | --- |
| RQ1 organization identity / first admin | **Assumed.** In-memory registry fixture pinning (org_id, K_O). |
| RQ2 asset binding | **Assumed.** In-memory binding fixture. |
| RQ3 delegation non-amplification | **Partly exercised.** Fixed depth-3 chain only. |
| RQ4 grant scope semantics | **Implemented and tested** against owner-reviewed labels (spec r2). |
| RQ5 tester/session binding | **Unresolved.** `tester_key` is signed but never challenged (non-case K01). |
| RQ6 enforcement of agent actions | **Unresolved.** `scope_query` is a lookup; TestClass→action mapping undefined. |
| RQ7 revocation freshness | **Unresolved.** Status is an instant, always-current in-memory fixture. |
| RQ8 privacy / latency / onboarding | Only single-machine CPU latency measured. |

## Checks run

| Command | Outcome |
| --- | --- |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | no warnings |
| `cargo test --all-targets` | 28 tests passed, 0 failed (15 unit, 5 reviewed-case, 6 property, 2 scope-oracle) |
| `AISIG_PROPTEST_SEED=1` and `=20261015`, property + oracle tests | all passed |
| `cargo run --release --bin eval` | results below; re-running reproduced identical files |
| `scripts/bench.sh` (N = 10 000, R = 10) | results below |

Harness check: changing one label (M01's reason) in a scratch copy made
`chain_verifier_matches_labels` fail with the expected mismatch message. The original
labels file was restored and verified byte-identical before committing.

## E1/E2 — labelled cases (`results/case_comparison.md`)

| Verifier / subset | Cases | False accept | False reject | Indeterminate | R-vs-I mismatch | Exact stage+reason |
| --- | --- | --- | --- | --- | --- | --- |
| chain-aware, all | 88 | 0 | 0 | 8 | 0 | 88 |
| chain-aware, reviewed only | 82 | 0 | 0 | 8 | 0 | 82 |
| signature-only, all | 88 | 70 | 2 | 0 | 0 | n/a |
| signature-only, reviewed only | 82 | 66 | 0 | 0 | 0 | n/a |

- The chain-aware verifier agreed with every label (88/88), including the six proposed
  ones. Agreement with labels is empirical evidence about this implementation on these
  inputs, not a proof of soundness (threat-model §5).
- All 8 Indeterminate outputs are on cases labelled Indeterminate; none on Accept labels.
- Scope queries: 10/10 match.
- The baseline rejected only S01, S02, S03, S07, D09, D10 and P01: broken signatures,
  a missing slot, or a slot whose signer key did not match. It accepted the other 70
  non-Accept cases, including the unpinned/copied roots (R01, R02), canonical-form and
  duplicate-field attacks (S04–S06), all delegation, scope, binding, time, status and
  audience failures. It falsely rejected V09/V10 because it needs the root slot. These
  measurements are consistent with the threat-model hypotheses; none was contradicted.

## Property and oracle tests

- Default seed `104372539625493`; 128 cases per chain property, 512 for the scope oracle.
- Chain properties: random valid grants accepted; any signature bit flip →
  `Reject / S / InvalidSignature{obj}`; any payload bit flip → Reject at F, N or S;
  added out-of-envelope target → `Reject / P / TargetOutsideEnvelope`; clock outside the
  window by > ε → `Expired{G}` / `NotYetValid{G}`; each unavailable evidence source → its
  Indeterminate, never Accept.
- Scope oracle: SO1 (named counterexample, relabelled to universe paths `/a`, `/a/b`,
  `/a/c`) behaves as spec §4.3 states. SO2 found no disagreement between implementation
  admissibility/ScopeWithin and the enumeration oracle over 512 random scope pairs per seed.

## E3 — CPU benchmark (`results/bench_20261014T183348Z.md`)

Intel Core i7-6700 @ 3.40 GHz, 8 logical cores, Linux 7.0.0-31-generic, governor
`powersave`, rustc 1.98.0, release profile, single-threaded, git `9412502`.
Medians across 10 runs of 10 000 timed calls; nanoseconds per call.

| Series | p50 | p95 | p99 |
| --- | --- | --- | --- |
| timer overhead (empty call) | 38 | 48 | 54 |
| signature verification ×3 | 126 870 | 180 804 | 236 236 |
| typed policy (linkage + policy) | 169 | 173 | 180 |
| simulated status lookup ×3 | 133 | 150 | 212 |
| full chain verify (decode → status) | 230 649 | 355 817 | 438 477 |

Observations, stated only as far as the data supports:

- In this fixture, signature verification dominates the checked stages. Typed policy and
  in-memory status lookup are each within a few hundred ns, only a few times the timer
  overhead, so their exact values are close to measurement resolution.
- Full verification is ~100 µs more than the three signature checks at p50. The
  remainder is mainly decode work (strict parse, canonical re-encode, public-key point
  validation); it was not profiled further.
- The `powersave` governor and an unpinned core add variance (for example, policy p99
  ranged 174–806 ns across runs). Numbers from another machine or governor will differ.
- The status series measures an in-memory HashMap only. It says nothing about RQ7.

## Deviations from the plan, and open items

- `ed25519-dalek` 3.0 (current release) was used rather than 2.x as first planned; the
  spec text was updated. `verify_strict` is used.
- Labels still **proposed** and awaiting owner review: V09, V10, M04 (clarified
  mutation), M20, M21, P03 (depends on the spec §7.2 conditional-evaluation rule). The
  implementation agrees with all six as currently labelled.
- Baseline "exact match" is not meaningful (its reasons are not comparable) and is shown
  as n/a.
- No remote was configured and nothing was pushed, per owner instruction.
