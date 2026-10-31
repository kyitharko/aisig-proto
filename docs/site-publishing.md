# Documentation website maintenance

The source documents stay in `docs/` and `results/`. The website is a
reading layer, not a new source of truth. [Documentation map](README.md)
orders the research questions, method, results, and reproduction guides.

## Publication path

Website releases are controlled by a separate, permanent **`docs-publish`**
branch; `main` is never deployed directly. The `docs-site.yml` workflow stages a
**limited selection** of Markdown and visual reports with
`scripts/build_docs_site.py`, builds them with GitHub Pages' Jekyll action, and
checks the rendered links. The flow is:

1. **Open a pull request.** The workflow builds and link-checks the site and
   uploads `_site` as a downloadable **`docs-preview`** artifact (under the PR's
   workflow run → *Artifacts*). Pull requests never deploy.
2. **Inspect `docs-preview`** to confirm the rendered pages and links.
3. **Merge the approved changes into `main`.** Merging to `main` still does not
   deploy.
4. **Deliberately promote to `docs-publish`:** create the branch from, or
   fast-forward it to, the approved `main` commit (for example
   `git push origin <approved-main-sha>:refs/heads/docs-publish`). That push —
   with no `paths` filter — triggers the deploy, as does a manual
   `workflow_dispatch` run selected on `docs-publish`.
5. The deploy job (and only it) holds `pages: write` / `id-token: write` and
   publishes the Pages artifact. A PR, or a manual run on `main` or any other
   ref, is **not** deployed.

Before the first deploy, set **Settings → Pages → Build and deployment →
Source** to **GitHub Actions**. If the `github-pages` environment has a branch
restriction (**Settings → Environments → github-pages → Deployment branches**),
it must permit **`docs-publish`**, or the deploy will be blocked. The project
URL is `https://kyitharko.github.io/aisig-proto/`.

## What is published

- Markdown in `docs/` and selected Markdown in `results/`, plus the
  sanitized visual reports and distribution SVGs for the recorded model demos.
- Layout and CSS in `site/`. The site index summarizes the current synthetic
  results, while original dated records remain unchanged.
- Links to code, workflow JSON and raw result JSON point back to the GitHub
  repository rather than copying those files to the Pages artifact. The builder
  (`scripts/build_docs_site.py`) rewrites each such relative link to an absolute
  GitHub URL **pinned to the exact commit that produced the build** — the
  workflow passes that commit to `--ref` (the PR head for a preview, the
  promoted `docs-publish` commit for a deployment). A reader therefore sees the
  code and JSON as they were in the documentation snapshot, not whatever `main`
  later becomes. Release-note links that intentionally cite the historical
  `v0.1.0-research` tag are left on that tag.
- Not every link is pinned, and that is deliberate. A few hand-authored links
  point to the repository's **current** terms rather than a snapshot: the page
  footer's **License** link (`blob/main/LICENSE`), the **security policy** link
  in the reading map (`blob/main/SECURITY.md`), and the masthead/footer links to
  the repository root. These are navigational and legal references, not evidence
  for a result, so tracking `main` is correct for them.

Raw model exports, local experiment files, keys, downloaded model weights,
Rust source, and Docker files are **not staged**. The website is no more
authoritative than its linked versioned source. Review new docs and
sanitization before merging: a public `.md` file in `docs/` or `results/`
will be included in the next site build.

## Check locally

```sh
python3 scripts/test_docs_site.py
python3 scripts/build_docs_site.py --output site-staging
```

The build command requires a **new** output directory. Delete the generated
`site-staging/` before another local run. The GitHub workflow also builds
Jekyll HTML and runs `python3 scripts/check_docs_site.py _site` to catch
broken internal links. It does not modify case labels or experiment results.

The released `v0.1.0-research` tag remains a historical snapshot; the live
site tracks whatever approved `main` commit was promoted to `docs-publish`.
When citing a result, cite the linked dated evidence and commit/tag, not the
mutable homepage alone.
