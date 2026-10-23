# Manual-02: prepare a reviewable publication candidate

The successful `manual-02` run reported **13/13** fixed controls and **30/30**
model executions. Its raw files remain in the ignored `local-experiments/`
directory. The console output suggests 4 Allow, 13 Deny, 8 Indeterminate and
5 no-mediation observations; these counts must be checked against the **actual
JSON** before publication. An earlier interrupted `full-*` folder is incomplete
and is not a source for this procedure.

This preparation makes a new, ignored copy. It does not modify the raw run,
commit results, create a remote, or publish a repository.

## 1. Prepare and validate a copy

Run from the repository root on the Docker host:

```sh
python3 scripts/test_prepare_model_publication.py

python3 scripts/prepare_model_publication.py \
  --input-dir local-experiments/manual-02/full-20261022T105748Z-668695e4 \
  --candidate-dir local-experiments/manual-02/publication-candidate-20261022

python3 scripts/prepare_model_publication.py \
  --check-dir local-experiments/manual-02/publication-candidate-20261022
```

Choose a **new** candidate directory if rerunning this procedure: the script
refuses to overwrite an existing copy. A nonzero exit means the candidate
failed; inspect the error and keep the source folder untouched. The script
requires a successful full-run manifest, all thirteen exact preregistered
control outcomes, every planned model cell, completed n8n executions,
consistent effect deltas, committed workflow/prompt hashes, a recomputable
variant/scenario fingerprint and raw model call ↔ **recorded classifier**
proposal consistency. It also checks the collector-recorded model identity.
The controller's echoed proposal was not retained in this matrix, so this
comparison alone does not independently attest what the controller received.
The imported workflow
bytes themselves were not retained, so their collector-reported hash cannot be
independently recomputed from these files.

The candidate contains exactly these six files:

| File | Purpose |
| --- | --- |
| `controls_results.json` | Preregistered control outcomes; controller address becomes `100.x.y.z` |
| `model_matrix.json` | Thirty recorded model, provider and effect observations |
| `publication_manifest.json` | Validated times, run ID, Git commit and number of removed secret-like keys; no local path |
| `visual_report.html` | Offline chart, full result table, discussion and conclusion |
| `decision_distribution.svg` | Standalone outcome chart |
| `README.md` | Source summary, measured counts, limits and SHA-256 of both sanitized JSON files |

The script removes recursively named token/credential/secret fields and rejects
remaining IPv4 literals and common home-directory paths. The gate regenerates
the HTML, SVG and README from the candidate inputs to check byte-for-byte
agreement. **Pattern checks do not prove absence of every possible sensitive
value**; a human must still inspect the six files before they leave the host.
The original `run_manifest.json` contains a local path and is never copied.

## 2. Review the result and its meaning

Read the candidate's `README.md`, open `visual_report.html` locally, and inspect
the JSON before sharing. Confirm these values from the candidate, not only
the earlier terminal output:

- Controls: **13/13** match the preregistered decision, parse class and effect.
- Planned executions: **30/30** complete and no effect-invariant failures.
- Decision distribution: **4 Allow / 13 Deny / 8 Indeterminate / 5 no mediation**
  if this is the same completed run shown in the terminal.
- For every Allow, the **modeled** in-memory effect delta is 1; for every other
  outcome it is 0. No mediation means no actionable proposal was received,
  not a provider Deny or an inferred model refusal.
- The v2 boundary prompt's observed proposals and no-call cases are shown
  separately; do not infer a general model reliability or determinism rate
  from two repeats per scenario.

The HTML includes a chart and discussion, but this is still a small synthetic
experiment. No real target was contacted, and it does not establish real tool
enforcement, independent organizational/asset evidence or deployment latency.
The ignored raw folder and any interrupted run remain local.

## 3. Package **only after** the candidate gate and human read

This optional local ZIP is a review artifact, **not** the original raw run:

```sh
python3 - <<'PY'
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

folder = Path('local-experiments/manual-02/publication-candidate-20261022')
names = ('README.md', 'publication_manifest.json', 'controls_results.json',
         'model_matrix.json', 'visual_report.html', 'decision_distribution.svg')
with ZipFile('zip/aisig-manual-02-candidate.zip', 'x', ZIP_DEFLATED) as archive:
    for name in names:
        archive.write(folder / name, arcname=name)
print('Created zip/aisig-manual-02-candidate.zip')
PY
```

If the file already exists, `ZipFile(..., 'x')` refuses to replace it. Supply
that candidate ZIP for independent review. After reviewing the exact candidate,
promote it without editing recorded observations:

```sh
python3 scripts/prepare_model_publication.py \
  --promote-dir local-experiments/manual-02/publication-candidate-20261022 \
  --published-dir results/model_demo/manual_replication_20261022

python3 scripts/prepare_model_publication.py \
  --check-dir results/model_demo/manual_replication_20261022
```

Promotion checks the candidate again, creates a publication-specific README
and manifest, and requires the two JSON inputs and HTML/SVG to remain byte-for-byte
identical to the reviewed candidate. It refuses to overwrite a destination.
Keep this replication separate from preregistered run 3 and the earlier manual
replication. Run the repository gates on the exact commit before a public push.
