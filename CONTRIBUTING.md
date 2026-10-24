# Contributing to aisig-proto

This repository is an AI-assisted **synthetic research prototype**, not a production
authorization service. Contributions that clarify the model, reproduce a result,
identify a counterexample, or improve the tests and documentation are welcome.

## Before opening an issue

- Read the [scope and limitations](docs/limitations.md) and the
  [experiment protocol](docs/experiment.md).
- Use the bug-report or experiment-reproduction issue form. Include the commit,
  exact command, expected and observed outcomes, and a minimal synthetic fixture.
- For a security finding, follow [SECURITY.md](SECURITY.md) instead of posting
  exploit details publicly.
- Never include real target details, access tokens, private keys, client data,
  private network addresses, or unsanitized n8n exports.

## Proposing a change

Open a pull request with a small, reviewable diff and explain the intended
decision rule. For a new or changed security case, document the rule and proposed
expected outcome before implementation. Keep new labels `proposed` until the
project owner reviews them. Do not change reviewed expected outcomes merely to
make a test pass; explain and review any such change explicitly.

Run the relevant offline checks from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc
python3 scripts/test_run_prepublication_experiment.py
python3 scripts/test_aisig_lab.py
python3 scripts/test_prepare_model_publication.py
cargo run --release --bin eval
cargo run --bin eval_rq123
git diff --exit-code -- results/
```

The CI workflow runs these checks on pull requests. It does not start Docker,
Ollama, n8n, or real network tools. See
[automated experiments](docs/automated-experiments.md) for the separate local
model procedure. If you cannot run a check, say so in the PR.

By submitting a contribution, you agree that your original contribution is
available under this repository's [Apache-2.0 license](LICENSE). Do not add
third-party material without identifying its source and license.
