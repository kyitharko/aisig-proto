# aisig-proto — provider-verified authorization chains (research prototype)

Private research prototype. It asks whether an AI-agent provider P can check that an
engagement grant for security testing is backed by a non-amplifying chain of authority:
pinned organization root → admin delegation → issuer delegation → tester grant.

**Status: Stage 0 — specification draft awaiting owner review.** There is no verifier code
yet. All expected test labels are *proposed*.

Everything here is synthetic: organizations, keys, `.test` hosts and databases. Nothing
scans, connects to, or tests any real target.

## Documents

- [docs/spec.md](docs/spec.md) — glossary, data model, signed bytes, decision rule, open questions
- [docs/threat-model.md](docs/threat-model.md) — actors, threats in scope, non-goals
- [docs/experiment.md](docs/experiment.md) — base fixture, 84 proposed chain cases, metrics, benchmark protocol
- [docs/limitations.md](docs/limitations.md) — what an Accept does and does not mean

## Research questions

- RQ1 (organization identity) and RQ2 (asset binding): **assumed**, as trusted fixtures.
- RQ4 (grant scope semantics, non-amplification): **this prototype**.
- RQ5 (tester/session binding), RQ6 (tool effect enforcement), RQ7 (revocation freshness):
  **unresolved, not implemented**.

## Planned commands (available after Stages 1–4)

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
scripts/bench.sh            # release build; writes results/bench_*.json and .md
```

## License

Not chosen. The owner will decide separately. Until then, no license is granted.
