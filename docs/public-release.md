# Public release preparation

**Status: preparation, not publication.** The current source snapshot has no remote and has
not been pushed. Complete the model simulation and review its actual results before publishing
a demo claim. Source publication can proceed separately if the prototype limitations are clear.

## License and provenance

- Proposed license for this release: Apache-2.0 (`LICENSE`, `Cargo.toml`). It permits free use,
  modification and redistribution, including commercial use, and contains an express patent
  grant. Confirm that the repository owner has authority to license every committed file and
  that any borrowed material and dependencies have compatible terms. Model weights and the n8n
  runtime have their own licenses; do not bundle them or imply they are Apache-2.0 licensed.
- Keep the README's AI-assisted development disclosure and production-use limitations visible.
  Reviewed expected labels and green tests do not constitute an independent security audit.
- Preserve `publish = false` unless crates.io publication is deliberately planned.

## Local branch audit before changing visibility

1. Inspect **all history and tags**, not only the current ZIP, for credentials, private keys,
   personal/client data, sensitive URLs, large model weights, generated build files and excluded
   archives. The fixture keys are deterministic and explicitly synthetic; check every other key.
2. Check `.gitignore`, tracked files, dependencies and their licenses; run the documented fmt,
   clippy, full `cargo test` (including doctests) and `eval` gates on the exact release commit.
3. Keep a private way to report vulnerabilities (for example GitHub private vulnerability
   reporting, if enabled). Do not publish unreviewed production security claims.
4. Reconcile the README, exported n8n workflow, model demo trace and results with the exact
   release commit; tag a
   clearly marked research-prototype version and write release notes with scope and limitations.

## Discovery and communication

- Use a short repository description and relevant GitHub topics such as `rust`,
  `ai-security`, `authorization`, `security-research` and `agent-safety`. GitHub's topic feature
  helps people find related projects:
  <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics>.
- Lead the README with a 30-second quickstart, a small diagram of model proposal → provider
  decision → synthetic effect, one representative trace and a link to reproducible results.
- Publish a short screen recording and a technical write-up comparing model proposals and
  mediator decisions. State sample size, model version, synthetic scope and open assumptions.
  Share the release URL with relevant Rust and AI security communities; avoid claims of a live
  deployment or measured real-world revocation/latency. GitHub releases provide a stable URL
  for notes and artifacts: <https://docs.github.com/en/repositories/releasing-projects-on-github>.

Publication and outward announcements should follow a review of the final repository, license,
model outputs and exact public URL. This file does not create a GitHub repository or a live API.
