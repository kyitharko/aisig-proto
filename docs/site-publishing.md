# Documentation website maintenance

The source documents stay in `docs/` and `results/`. The website is a
reading layer, not a new source of truth. [Documentation map](README.md)
orders the research questions, method, results, and reproduction guides.

## Publication path

The `docs-site.yml` workflow stages a **limited selection** of Markdown and
visual reports with `scripts/build_docs_site.py`, builds them with GitHub
Pages' Jekyll action, and checks the rendered links. Pull requests build and
check the site without deploying it. A successful push to `main` deploys
the staged site after the repository's Pages source has been set to
**GitHub Actions**.

The project URL is `https://kyitharko.github.io/aisig-proto/`. If it does not
load, check **Settings → Pages → Build and deployment → Source** and choose
**GitHub Actions**; then run `Documentation site` under **Actions** using
`workflow_dispatch` or push a new docs change. The site is public.

## What is published

- Markdown in `docs/` and selected Markdown in `results/`, plus the
  sanitized visual reports and distribution SVGs for the recorded model demos.
- Layout and CSS in `site/`. The site index summarizes the current synthetic
  results, while original dated records remain unchanged.
- Links to code, workflow JSON, raw result JSON, security policy and license
  point back to the GitHub repository rather than copying those files to
  the Pages artifact.

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

The released `v0.1.0-research` tag remains a historical snapshot; this
site tracks the current `main` branch. When citing a result, cite the
linked dated evidence and commit/tag, not the mutable homepage alone.
