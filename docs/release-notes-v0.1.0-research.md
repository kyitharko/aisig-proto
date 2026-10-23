# v0.1.0-research — draft GitHub pre-release notes

This is an **AI-assisted, synthetic research prototype** of provider-side
authorization for AI-agent tool proposals. It is not independently audited or
ready to enforce actions against real systems. The demo's only modeled effect
is an in-memory append; it does not fetch a page, run a scan, access a real DB
or contact a target.

## Included

- Rust prototype for signed delegation, grant scope and evidence checks;
  separate session, synthetic action mediation and signed-status freshness
  slices. The RQ1–RQ3 AssetAuthority slice demonstrates a pinned synthetic
  root, signed records and two independently verified delegation paths.
- CPU-only local demo using n8n, Ollama and `qwen3:1.7b`, plus a script for
  setup, fixed controls, the model matrix and an offline visual report.
- Apache-2.0 license for the project's own materials; downloaded weights,
  dependencies, n8n and Ollama retain their separate licenses.

## Reproducible evidence

- Reviewed label agreements: chain 94/94, scope lookup 15/15, session 34/34,
  enforcement 28/28, freshness 34/34, RQ8 privacy 16/16, modeled latency
  6/6 and onboarding 17/17. The separate RQ1–RQ3 slice reports 25/25.
- In the [manual-02 replication](https://github.com/kyitharko/aisig-proto/blob/v0.1.0-research/results/model_demo/manual_replication_20261022/README.md),
  13/13 preregistered controls matched. All 30/30 model cells completed:
  4 Allow, 13 Deny, 8 Indeterminate and 5 no mediation. Allow produced one
  modeled effect; all other categories produced zero. The excluded `/app/admin`
  target was proposed in 5/10 boundary-prompt runs; the other 5 produced no
  actionable tool call. These counts are observations from one small model,
  not estimates of a general refusal, safety or determinism rate.
- The [offline visual report](https://github.com/kyitharko/aisig-proto/blob/v0.1.0-research/results/model_demo/manual_replication_20261022/visual_report.html)
  includes the observations, discussion and conclusion. The results are
  checked against the committed inputs and can be regenerated.

## Reproduce and inspect

Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, `cargo run --release --bin eval` and `cargo run --bin eval_rq123`.
For a local n8n/Ollama run, follow
[automated-experiments.md](https://github.com/kyitharko/aisig-proto/blob/v0.1.0-research/docs/automated-experiments.md);
it requires Docker and separately downloaded model weights. Keep new runs in
the ignored `local-experiments/` directory and validate them before publication.

## Limits and open work

Organization vetting and real asset control are assumptions; the signed
manifest pins a declared synthetic snapshot. Live tool enforcement is not
implemented; real end-to-end latency, network metadata and operational cost
are not measured. The
fixed-path RQ1–RQ3 slice is not a general delegation discovery system.
Read the [threat model](https://github.com/kyitharko/aisig-proto/blob/v0.1.0-research/docs/threat-model.md),
[limitations](https://github.com/kyitharko/aisig-proto/blob/v0.1.0-research/docs/limitations.md) and
[security policy](https://github.com/kyitharko/aisig-proto/blob/v0.1.0-research/SECURITY.md)
before adapting any component.

The version label and these notes are a **draft**. Create the tag and GitHub
pre-release only after the exact public branch tip and these claims are checked.
