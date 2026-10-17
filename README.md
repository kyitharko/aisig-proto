# aisig-proto — provider-verified authorization chains (research prototype)

Private research prototype. It asks whether an AI-agent provider P can check that an
engagement grant for security testing is backed by a non-amplifying chain of authority:
pinned organization root → admin delegation → issuer delegation → tester grant.

**Status:** spec draft r3.1 with owner decisions applied; Rust prototype, reviewed-case
harness, property tests and CPU benchmark implemented; r3 added exact-object status
identity, registry-record checks and named scope lookups; r3.1 removed the public
pre-decoded decision API. All 94 chain and 15 lookup labels are owner-reviewed
(see [docs/experiment.md](docs/experiment.md)). RQ5 slice s1 adds a separate session
proof-of-possession decision ([docs/session.md](docs/session.md); 34 reviewed session
labels). RQ6 slice e2 adds a provider-mediated synthetic tool adapter
([docs/enforcement.md](docs/enforcement.md); 28 reviewed labels, synthetic effects only).
A negative clock uncertainty (ε < 0) is rejected at every time path, never clamped.
Results: [docs/report.md](docs/report.md).

Everything here is synthetic: organizations, keys, `.test` hosts and databases. Nothing
scans, connects to, or tests any real target. No real credentials, client data or live
assets are in this repository.

## Documents

- [docs/spec.md](docs/spec.md) — glossary, data model, signed bytes, scope semantics, decision rule, owner decisions
- [docs/threat-model.md](docs/threat-model.md) — actors, threats in scope, non-goals, what tests can and cannot show
- [docs/experiment.md](docs/experiment.md) — base fixture, 94 chain cases and 15 scope lookups with review status, oracle, metrics, benchmark protocol
- [docs/limitations.md](docs/limitations.md) — what an Accept does and does not mean
- [docs/session.md](docs/session.md) — RQ5 slice s1: challenge/response proof of possession bound to a provider session
- [docs/enforcement.md](docs/enforcement.md) — RQ6 slice e2 (implemented, synthetic): provider-mediated synthetic tool adapter
- [docs/freshness.md](docs/freshness.md) — RQ7 slice f2 (implemented; labels reviewed): status freshness and bounded revocation delay
- [docs/rq8.md](docs/rq8.md) — RQ8: privacy leakage (Q1 slice 1, 16 reviewed observations), CPU vs end-to-end latency (Q2 slice 1: measured CPU + 6 reviewed modeled responder-delay scenarios), onboarding/cost (Q3 slice 1: step inventory + measured artifact byte sizes, 17 reviewed; human/monetary/storage cost not inferred); no privacy/latency/cost number over a real deployment claimed
- [docs/report.md](docs/report.md) — what was run and what it produced

## Status closeout

Reviewed label counts: **chain 94, lookup 15, session 34, enforcement 28, freshness 34, RQ8 Q1
16, RQ8 Q2 6, RQ8 Q3 17** — all owner-reviewed (RQ8 as fixture-specific synthetic observations).
Plainly: **RQ1/RQ2 are trusted assumptions** (unverified in-memory fixtures); **RQ3 is only
partly exercised** (fixed depth-3 chain, non-amplification); **real tool enforcement and real
deployment measurements remain open** (RQ6 mediates only modeled effects; real latency, network/
O4 metadata and human/monetary/storage cost are unmeasured). The **Q2 modeled RTT is not a real
latency and the Q3 step counts are not an operational cost.** Two things *are* measured: the
local CPU benchmark (wall-clock on one machine, not process CPU time) and the Q3 canonical
artifact byte sizes (from the synthetic fixture) — but byte sizes are a size measurement only,
not a measure of transport or operational cost. See [docs/report.md](docs/report.md) "Final
synthetic-prototype closeout" for the reproducibility commands and the exact benchmark
environment/commit.

## Research questions

- RQ1 (organization identity) and RQ2 (asset binding): **assumed**, as trusted in-memory fixtures.
- RQ4 (grant scope semantics, non-amplification): **this prototype**.
- RQ5 (tester/session binding): **slice s1, reviewed** (34 labels) — session proof of possession, separate decision; channel binding and relay resistance not addressed.
- RQ6 (tool effect enforcement): **slice e2, implemented (synthetic)** — a provider-side mediator for synthetic tool operations ([docs/enforcement.md](docs/enforcement.md)); 28 reviewed labels; only modeled in-memory effects, no live tool enforcement.
- RQ7 (revocation freshness): **slice f2 implemented** — whole-interval status-freshness policy over a signed, timestamped responder statement ([docs/freshness.md](docs/freshness.md)); 34 labels, all **reviewed** (owner-approved; the implementation matches them). Runs behind a separate freshness-slice runner; the chain/session/enforcement outcomes are unchanged.
- RQ8 (privacy / latency / onboarding): **Q1 slice 1 implemented (synthetic)** — field-disclosure inventory and identical-vs-reissued linkability ([docs/rq8.md](docs/rq8.md)); 16 **reviewed** observations (owner-approved). A structural observation over top-level field names, not a privacy guarantee; O4 network metadata unmeasured. **Q2 slice 1**: a rerun CPU benchmark plus 6 **reviewed** modeled responder-delay scenarios (measured CPU, modeled delay and unmeasured real end-to-end latency kept separate). **Q3 slice 1**: a per-party step inventory (O/A/U/T/P/R; critical path open) and measured bundle-slot artifact byte sizes (17 reviewed); no human/monetary/storage cost inferred. No RQ8 number over a real deployment is claimed.

## Layout

```
src/codec.rs        envelopes, strict parse, canonical JSON, signed bytes (stage F)
src/crypto.rs       Ed25519 verify over exact bytes (ed25519-dalek), key ids (stage S)
src/model.rs        typed payloads and assets, decode-time validation
src/asset.rs        within, admissibility, ScopeWithin, exact_node_lookup, subtree_lookup
src/policy.rs       linkage (L) and policy (P) predicates — pure, no crypto
src/evidence.rs     registry / binding / clock / status traits, exact-object StatusKey, fixtures
src/verifier.rs     ValidChain_P decision procedure
src/baseline.rs     deliberately weak signature-only verifier
src/session.rs      RQ5 s1: challenge issuance/redemption, SessionDecision (separate from chain)
src/experiment/     synthetic fixture, case mutations, label loading, reporting
src/bin/eval.rs     runs all labelled cases through both verifiers
src/bin/bench.rs    CPU micro-benchmark
tests/cases/reviewed_cases.toml   the label oracle (never edited to match output)
tests/reviewed_cases.rs           exact label agreement
tests/scope_oracle.rs             independent brute-force set oracle (SO1–SO3)
tests/properties.rs               property-based valid chains and mutations
tests/predecoded_api.rs           public API boundary (decoded bodies bound to payloads)
tests/session_cases.rs            RQ5 session labels (tests/cases/session_cases.toml)
scripts/bench.sh                  benchmark with environment capture
results/                          generated outputs (see results/README.md)
```

## Commands

Requires Rust stable (tested with rustc 1.98.0). From the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets                      # unit, reviewed cases, property tests
cargo test --doc                              # API-boundary doctests (incl. compile_fail)
cargo test --all-targets -- --nocapture       # also prints the proptest seed
AISIG_PROPTEST_SEED=1 cargo test --test properties --test scope_oracle   # another seed
cargo run --release --bin eval                # writes results/case_comparison.*, session_cases.*, enforcement_cases.*, freshness_cases.*
scripts/bench.sh                              # writes results/bench_<UTC>.{json,md}
N=2000 R=5 scripts/bench.sh                   # shorter benchmark
```

The default proptest seed is `104372539625493` (`0x5EED_2026_1015`). Failure
persistence is disabled, so a seed fully determines a run.

## Git

This repository is local only. Work happens on `feature/chain-verifier-prototype`;
nothing has been pushed and no remote is configured.

## License

Not chosen. The owner will decide separately. Until then, no license is granted.
