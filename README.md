# aisig-proto — provider-verified authorization chains (research prototype)

Private research prototype. It asks whether an AI-agent provider P can check that an
engagement grant for security testing is backed by a non-amplifying chain of authority:
pinned organization root → admin delegation → issuer delegation → tester grant.

**Status:** spec draft r3 with owner decisions applied; Rust prototype, reviewed-case
harness, property tests and CPU benchmark implemented; r3 adds exact-object status
identity, registry-record checks and named scope lookups. Five chain labels and five
lookup labels are still *proposed* (see [docs/experiment.md](docs/experiment.md)). Results: [docs/report.md](docs/report.md).

Everything here is synthetic: organizations, keys, `.test` hosts and databases. Nothing
scans, connects to, or tests any real target. No real credentials, client data or live
assets are in this repository.

## Documents

- [docs/spec.md](docs/spec.md) — glossary, data model, signed bytes, scope semantics, decision rule, owner decisions
- [docs/threat-model.md](docs/threat-model.md) — actors, threats in scope, non-goals, what tests can and cannot show
- [docs/experiment.md](docs/experiment.md) — base fixture, 93 chain cases and 15 scope lookups with review status, oracle, metrics, benchmark protocol
- [docs/limitations.md](docs/limitations.md) — what an Accept does and does not mean
- [docs/report.md](docs/report.md) — what was run and what it produced

## Research questions

- RQ1 (organization identity) and RQ2 (asset binding): **assumed**, as trusted in-memory fixtures.
- RQ4 (grant scope semantics, non-amplification): **this prototype**.
- RQ5 (tester/session binding), RQ6 (tool effect enforcement), RQ7 (revocation freshness):
  **unresolved, not implemented**.

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
src/experiment/     synthetic fixture, case mutations, label loading, reporting
src/bin/eval.rs     runs all labelled cases through both verifiers
src/bin/bench.rs    CPU micro-benchmark
tests/cases/reviewed_cases.toml   the label oracle (never edited to match output)
tests/reviewed_cases.rs           exact label agreement
tests/scope_oracle.rs             independent brute-force set oracle (SO1–SO3)
tests/properties.rs               property-based valid chains and mutations
scripts/bench.sh                  benchmark with environment capture
results/                          generated outputs (see results/README.md)
```

## Commands

Requires Rust stable (tested with rustc 1.98.0). From the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets                      # unit, reviewed cases, property tests
cargo test --all-targets -- --nocapture       # also prints the proptest seed
AISIG_PROPTEST_SEED=1 cargo test --test properties --test scope_oracle   # another seed
cargo run --release --bin eval                # writes results/case_comparison.{md,json}
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
