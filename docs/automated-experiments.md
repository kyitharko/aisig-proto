# Scripted local installation, configuration and experiments

Run these commands **on the Docker host** from the repository root. The single
Python entry point `scripts/aisig_lab.py` wraps the existing Compose stack and
preregistered collector; it does not rewrite experiment labels or the committed
reference results. `local-experiments/` is gitignored. This remains a synthetic
demo: no model-proposed target is contacted and the only effect is an in-memory
append by the Rust controller.

## 0. Check host prerequisites

```sh
python3 scripts/aisig_lab.py doctor
python3 scripts/test_aisig_lab.py
```

The host needs Python 3, Rust/Cargo, Docker Engine with a working daemon, and
Docker Compose. The script **does not run `sudo`, install system packages, or
download installer scripts**. If a prerequisite is missing, use the official
[Rust installation](https://rust-lang.org/tools/install/),
[Docker Engine installation](https://docs.docker.com/engine/install/), and
[Compose installation](https://docs.docker.com/compose/install/) instructions
for your OS, then rerun `doctor`. An ordinary project `setup` may pull the
Compose images; `--pull-model` explicitly downloads `qwen3:1.7b` in Ollama.

## 1. Configure a local-only session (default)

```sh
python3 scripts/aisig_lab.py configure --session manual-02
```

This creates `local-experiments/manual-02/config.json` with mode 0600.
It records **no real key or credential** and starts no service. The session
name cannot contain `/` or `..`; an existing session cannot be overwritten.
For laptop access through a trusted private interface **assigned to the Docker
host**, use a new session and pass its actual address (example placeholder):

```sh
python3 scripts/aisig_lab.py configure --session laptop-02 --access-ip 100.x.y.z
```

Replace the placeholder with your host's own RFC1918 or Tailscale/CGNAT IPv4.
The script checks that it belongs to this host. This option applies the
`demo/compose.access.yml` override, publishing n8n on 5678 and the
**unauthenticated synthetic controller** on 8787 only at the chosen IP; the
base mapping also keeps n8n on loopback. Ollama remains internal. Use only a
single trusted host and private link with n8n sign-in. Never forward those
ports to the internet. The manual [laptop access guide](remote-manual-access.md)
explains the exposure and network requirements in detail.

## 2. Set up the project stack

```sh
python3 scripts/aisig_lab.py setup --session manual-02 --pull-model
```

`setup` checks prerequisites, builds the Rust controller in release mode,
validates and starts the selected Compose stack, optionally pulls the model,
then queries `/v1/scenarios`. It recreates the containers so the newly built
controller is loaded; Compose volumes and saved n8n data remain. Omit
`--pull-model` when only running fixed controls or when the model is already
downloaded. For laptop mode, substitute `laptop-02` in this command; the
script reads its ignored configuration and prints the correct UI/API URLs.

## 3. Run experiments without overwriting published evidence

```sh
# 13 preregistered fixed controls (no model inference)
python3 scripts/aisig_lab.py experiment --session manual-02 --mode controls

# 13 controls, then the 3 × 5 × 2 = 30 model runs
python3 scripts/aisig_lab.py experiment --session manual-02 --mode full
```

Each invocation creates a **new** time-stamped folder under that session.
The wrapper automatically selects the controller URL, sets
`AISIG_OUTPUT_DIR`, calls the existing `run_prepublication_experiment.py`,
and records its exit code and the current Git commit in `run_manifest.json`.
It propagates a nonzero collector exit. A failed or incomplete run is kept
as evidence, **never** marked complete or silently compared as a success.
`--mode full` first checks that `qwen3:1.7b` is installed. After a successful
full collector gate, it builds `visual_report.html` and
`decision_distribution.svg` using the existing validated report generator.
No output is written into the committed `results/` directory.

To regenerate the presentation from one **successful full-run** folder:

```sh
python3 scripts/aisig_lab.py report --session manual-02 \
  --result-dir local-experiments/manual-02/full-<timestamp>-<id>
```

The report command rejects output paths outside the selected ignored session
and rejects runs whose manifest has a failed collector exit. The report
generator additionally validates result coverage and the effect invariant.
Replace `<timestamp>-<id>` with the printed folder name. For manual inspection
of each n8n node, use [manual-experiments.md](manual-experiments.md) and the
[experiment workbook](experiment-workbook.md); these scripts do not change the
model's prompt or invent a proposal.

## 4. Prepare a publication candidate from a successful full run

Use [the manual-02 publication procedure](manual-02-publication.md) to make an
ignored, sanitized copy of a completed run and check its JSON against the
preregistered controls and committed workflow files. The script regenerates
the visual presentation and refuses incomplete, changed or inconsistent
evidence. The copied files need a human review before sharing or committing;
this step does not publish anything.

## 5. Stop without deleting work

```sh
python3 scripts/aisig_lab.py stop --session manual-02
```

This calls Compose `down` **without `-v`**; n8n/Ollama volumes and all ignored
session evidence remain. Review and sanitize any new n8n exports before
publishing them. Do not commit `local-experiments/`, private IPs, credentials,
model weights, or unsanitized traces.

The script uses only Python standard-library modules; its offline tests can
run without Docker or Rust. A real end-to-end setup and 30-model trial must
still be executed on the owner's Docker host.
