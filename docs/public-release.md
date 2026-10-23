# Public release preparation

This checklist records the preparation of the synthetic research prototype for a public
repository. The model demo and manual replication have been executed and their sanitized
results committed. Apply the checks below to the exact commit being published; this document
does not indicate whether a GitHub remote or release exists at the time it is read.

## License and provenance

- Selected license for this release: Apache-2.0 — already in place (`LICENSE` is the unmodified
  Apache License 2.0; `Cargo.toml` sets `license = "Apache-2.0"`). It permits free use,
  modification and redistribution, including commercial use, and contains an express patent
  grant. It covers the project's own committed material: original Rust/source code, repository
  documentation, the synthetic fixtures and cases, and the original generated results and
  visualizations the owner can license. It does **not** extend to separately licensed items that
  are not bundled here — downloaded model weights, the third-party Rust dependencies (fetched at
  build time, each under its own terms), and the Ollama and n8n software (referenced as Docker
  images, not vendored); do not imply any of those are Apache-2.0 licensed. The README's
  production-use warning is a non-binding caution, not an added license restriction. Confirm the
  owner has authority to license every committed file before publishing.
- Keep the README's AI-assisted development disclosure and production-use limitations visible.
  Reviewed expected labels and green tests do not constitute an independent security audit.
- Preserve `publish = false` unless crates.io publication is deliberately planned.

## First public repository: `kyitharko/aisig-proto`

The proposed GitHub repository name is `aisig-proto`, matching the README and Rust crate.
The public API returned no public repository with that name at preparation time; confirm
availability in the owner's account when creating it. Create an **empty** repository (do not
initialize another README, license, or `.gitignore`). Publish only the audited
`public/chain-verifier-prototype` branch as `main`. Never use `--all`, `--mirror`, or a
push of all tags from the local repository: its private branches must remain local.

## Four owner sign-offs

1. **Rights and license:** the chosen Apache-2.0 text and crate metadata are present.
   **Owner action:** confirm authority to license every committed code, document, fixture,
   model-output excerpt and original visual. The history scan cannot establish legal
   ownership or the absence of unknown private material.
2. **Release identity and notes:** a draft for `v0.1.0-research` is in
   [release-notes-v0.1.0-research.md](release-notes-v0.1.0-research.md). It matches
   `Cargo.toml` 0.1.0 while marking this a research prototype. **Owner action:** check
   the exact final commit, then create this tag and a GitHub *pre-release* pointing to it.
   Do not tag or attach the private history bundle.
3. **Private security reports:** [SECURITY.md](../SECURITY.md) provides the policy.
   **Owner action after creating the public repository:** enable GitHub private
   vulnerability reporting in Settings → Advanced Security and verify that
   “Report a vulnerability” is visible on the repository's Advisories page.
4. **Final human read:** check the README opening, this document, the release notes,
   [report.md](report.md), the [manual-02 evidence](../results/model_demo/manual_replication_20261022/README.md),
   and the [visual report](../results/model_demo/manual_replication_20261022/visual_report.html).
   **Owner action:** approve the wording, sample size, synthetic limitations, and public
   contact address. No independent security audit is claimed.

## Publication sequence

1. Commit these release documents on `public/chain-verifier-prototype`; run the gates on
   that new exact commit, confirm `git status --short` is empty, and independently check
   `git rev-parse HEAD`. The earlier `28a99c6` audit does not automatically cover a new
   commit; review the new diff and scan newly added files before publishing.
2. After the rights confirmation and final human read, in the `kyitharko` GitHub
   account create an **empty public** `aisig-proto` repository.
   Do not tick the README, `.gitignore` or license initialization boxes.
3. In the local repository, inspect `git remote -v`. If no `origin` exists, add
   `https://github.com/kyitharko/aisig-proto.git` as `origin`. Push only
   `public/chain-verifier-prototype:main` with `git push -u origin
   public/chain-verifier-prototype:main`. Confirm that GitHub `main` points to the
   reviewed commit; never push `feature/*`, `private/*`, `--all` or `--mirror`.
4. Enable private vulnerability reporting and verify the button; add the description,
   topics and social preview. Create the `v0.1.0-research` tag on the verified `main`
   commit and publish a GitHub **pre-release** using the reviewed draft notes. Share
   the URL only after checking the rendered README, release notes and result links.

## Local branch audit before changing visibility

1. Inspect **all history and tags**, not only the current ZIP, for credentials, private keys,
   personal/client data, sensitive URLs, large model weights, generated build files and excluded
   archives. The fixture keys are deterministic and explicitly synthetic; check every other key.
2. Check `.gitignore`, tracked files, dependencies and their licenses; run the documented fmt,
   clippy, full `cargo test` (including doctests) and `eval` gates on the exact release commit.
3. Confirm the security-reporting channel and avoid production security claims.
4. Reconcile the README, exported n8n workflow, model demo trace and results with the exact
   release commit. The draft notes and policy above are not a published GitHub release.

## Discovery and communication

- Suggested repository description (edit to fit GitHub's About field):
  `Research prototype: provider-side authorization of AI-agent tool proposals (Rust + n8n; synthetic only).`
- Set topics `rust`, `ai-security`, `agent-security`, `authorization`, and
  `security-research`, and upload [`assets/social-preview.png`](assets/social-preview.png)
  under **Settings → Social preview**. Pin the published repository to the maintainer's
  GitHub profile if it represents their current work. GitHub's topic feature helps people
  find related projects:
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

For the screen-recording sequence, use [demo-walkthrough.md](demo-walkthrough.md). A
separate publication kit contains an article draft, a short post and a simple measurement
worksheet; those drafts need the final public URL and a human review before posting.
