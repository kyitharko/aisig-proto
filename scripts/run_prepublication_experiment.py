#!/usr/bin/env python3
"""Run the pre-publication experiment (docs/prepublication-protocol.md).

Part A: the 13 preregistered fixed controls (results/model_demo/controls_expected.json) through
the real provider controller HTTP service (POST /v1/runs), recording actual vs expected.

Part B: the 3 prompt variants x 5 scenarios x 2 repeats = 30 model-workflow executions, driven
from the committed variant workflows with only the Set-node scenario_id overridden, imported and
run via `n8n execute`. There is no expected model action; no_call / text / malformed / multiple
calls are recorded as such, never reclassified as a provider Deny.

Nothing contacts a model-selected target; the only effect is the controller's in-memory sink.
Every captured n8n export is sanitized (scripts/sanitize_n8n_export.py predicate) before writing.
Writes results/model_demo/controls_results.json and results/model_demo/model_matrix.json by
default. Set AISIG_OUTPUT_DIR to an ignored local-experiments subdirectory for a new run; this
preserves the committed reference results.

Env:
  AISIG_CONTROLLER_URL  controller base URL (default http://controller:8787; from the host use the
                        controller container IP, e.g. http://172.x.x.x:8787)
  AISIG_COMPOSE         compose file (default demo/compose.cpu.yml)
  AISIG_SKIP_MODEL      if set to "1", run only Part A (controls)
  AISIG_OUTPUT_DIR      destination directory (default results/model_demo)
"""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

COMPOSE = os.environ.get("AISIG_COMPOSE", "demo/compose.cpu.yml")
CTRL = os.environ.get("AISIG_CONTROLLER_URL", "http://controller:8787").rstrip("/")
VARIANTS = [
    ("v1", "demo/n8n-workflow.json"),
    ("v2", "demo/n8n-workflow-v2.json"),
    ("v3", "demo/n8n-workflow-v3.json"),
]
SCENARIOS = ["fresh", "expired_session", "revoked_grant", "stale_status", "unavailable_status"]
REPEATS = 2

# Reuse the committed sanitizer's predicate so records never carry secrets.
_spec = importlib.util.spec_from_file_location("sz", "scripts/sanitize_n8n_export.py")
sz = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sz)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def sanitize(obj):
    return sz.sanitize(obj, "", [])


def dc(args, timeout=120, text_input=None):
    return subprocess.run(
        ["docker", "compose", "-f", COMPOSE, *args],
        capture_output=True, text=True, timeout=timeout, input=text_input,
    )


# ---------- Part A: fixed controls over the real HTTP service ----------
def post_run(payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        CTRL + "/v1/runs", data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode(errors="replace")}
    except Exception as e:  # noqa: BLE001
        return None, {"error": repr(e)}


def run_controls():
    spec = json.load(open("results/model_demo/controls_expected.json"))
    out = []
    for c in spec["controls"]:
        payload = {
            "scenario_id": c["scenario"],
            "proposal": c["proposal"],
            "prompt_variant_id": c["id"],
            "model_metadata": "fixed control (deterministic, not a model action)",
            "model_parse": "deterministic_control",
        }
        status, body = post_run(payload)
        rec = {
            "id": c["id"], "series": "control", "timestamp": now_utc(),
            "scenario": c["scenario"], "proposal": c["proposal"],
            "http_status": status,
            "actual_parse_status": body.get("parse_status"),
            "actual_decision": body.get("decision"),
            "actual_delta": body.get("effects_delta"),
            "expected_parse_status": c["expected_parse_status"],
            "expected_decision": c["expected_decision"],
            "expected_delta": c["expected_delta"],
        }
        rec["pass"] = (
            rec["actual_decision"] == c["expected_decision"]
            and rec["actual_delta"] == c["expected_delta"]
            and rec["actual_parse_status"] == c["expected_parse_status"]
        )
        out.append(rec)
        print(f"  {c['id']} {c['scenario']}: {rec['actual_decision']} d={rec['actual_delta']} "
              f"=> {'PASS' if rec['pass'] else 'FAIL'}")
    return out


# ---------- captured provenance (not hardcoded) ----------
def wget_json(url):
    """Fetch JSON from inside the n8n container (Ollama has no published host port)."""
    p = dc(["exec", "-T", "n8n", "sh", "-c", f"wget -qO- {url}"], timeout=30)
    try:
        return json.loads(p.stdout)
    except Exception:  # noqa: BLE001
        return None


def capture_identity():
    """Query the actual running model/runtime identity rather than assuming it."""
    ver = wget_json("http://ollama:11434/api/version") or {}
    tags = wget_json("http://ollama:11434/api/tags") or {}
    digest = psize = quant = None
    for m in tags.get("models", []):
        if m.get("name") == "qwen3:1.7b":
            digest = m.get("digest")
            det = m.get("details", {})
            psize, quant = det.get("parameter_size"), det.get("quantization_level")
    n8n_v = dc(["exec", "-T", "n8n", "n8n", "--version"], timeout=30).stdout.strip() or None
    img = subprocess.run(
        ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", "ollama/ollama:latest"],
        capture_output=True, text=True,
    ).stdout.strip() or None
    return {
        "model_tag": "qwen3:1.7b", "model_digest": digest,
        "parameter_size": psize, "quantization": quant,
        "ollama_version": ver.get("version"), "ollama_image_digest": img,
        "n8n_version": n8n_v,
    }


# ---------- gate: the runner fails loudly on bad outcomes ----------
def gate_problems(controls, matrix, expected_cells=30):
    """Return a list of problems that must make the runner exit nonzero. Empty => clean."""
    problems = []
    if not controls:
        problems.append("no fixed controls were run")
    for c in controls:
        if c.get("http_status") != 200:
            problems.append(f"control {c.get('id')}: HTTP {c.get('http_status')} (not an authz decision)")
        if not c.get("pass"):
            problems.append(f"control {c.get('id')}: decision/delta/parse mismatch vs expected")

    runs = matrix.get("runs", []) if matrix else []
    attempted = matrix.get("attempted") if matrix else None
    if matrix is not None:
        if attempted != expected_cells:
            problems.append(f"matrix attempted={attempted}, expected {expected_cells}")
        if len(runs) != expected_cells:
            problems.append(f"matrix has {len(runs)} runs, expected {expected_cells}")
        # Coverage must be exactly the planned (variant x scenario x repeat) product: this catches
        # an unplanned scenario (30 distinct cells that are not the planned set) and missing cells.
        planned = {(v, s, rep) for v, _ in VARIANTS for s in SCENARIOS for rep in (1, 2)}
        cells = {(r.get("variant"), r.get("scenario"), r.get("repeat")) for r in runs}
        if cells != planned:
            unplanned = sorted(str(c) for c in cells - planned)
            missing = sorted(str(c) for c in planned - cells)
            problems.append(f"matrix coverage != planned 3x5x2 (unplanned={unplanned}, missing={missing})")
        completed = [r for r in runs if r.get("completed")]
        if matrix.get("completed") != len(completed):
            problems.append("matrix 'completed' count disagrees with per-run 'completed' flags")
        for r in runs:
            rid = r.get("run_id")
            if not r.get("completed"):
                problems.append(f"run {rid}: not completed ({r.get('error', 'unknown error')})")
                continue
            for f in ("decision", "parse_status", "effects_delta", "proposal", "model_raw_message"):
                if r.get(f) is None:
                    problems.append(f"run {rid}: missing controller/model field '{f}'")
            # A nonzero n8n execute returncode is a failure even if the JSON parsed.
            rc = r.get("execute_returncode")
            if rc is not None and rc != 0:
                problems.append(f"run {rid}: nonzero n8n execute returncode {rc}")
            if r.get("decision") is not None and r.get("effects_delta") is not None:
                if (r["decision"] == "Allow") != (r["effects_delta"] == 1):
                    problems.append(f"run {rid}: effect-invariant violation "
                                    f"(decision={r['decision']}, delta={r['effects_delta']})")
            b, a, d = r.get("effects_before"), r.get("effects_after"), r.get("effects_delta")
            if None not in (b, a, d) and d != a - b:
                problems.append(f"run {rid}: effects_delta {d} != effects_after {a} - effects_before {b}")
    return problems


# ---------- Part B: model matrix via n8n ----------
def raw_decode_first(blob):
    """Extract the first sizeable JSON value from n8n execute --rawOutput (log preamble + JSON)."""
    dec = json.JSONDecoder()
    for i, ch in enumerate(blob):
        if ch in "[{":
            try:
                obj, end = dec.raw_decode(blob, i)
                if isinstance(obj, (list, dict)) and end - i > 200:
                    return obj
            except Exception:  # noqa: BLE001
                continue
    return None


def node_output(run_data, node):
    try:
        return run_data[node][0]["data"]["main"][0][0]["json"]
    except Exception:  # noqa: BLE001
        return {}


def node_ms(run_data, node):
    try:
        return run_data[node][0]["executionTime"]
    except Exception:  # noqa: BLE001
        return None


def import_variant(variant, scenario, src_path, tag):
    """Import the committed variant with only scenario_id overridden. Returns the actual n8n
    workflow id and the SHA-256 of the exact bytes imported (the effective workflow hash), rather
    than assuming provenance."""
    wf = json.load(open(src_path))
    wf["name"] = f"aisig-mx-{tag}-{variant}-{scenario}"
    for a in wf["nodes"][1]["parameters"]["assignments"]["assignments"]:
        if a["id"] == "a1":
            a["value"] = scenario
    effective = json.dumps(wf)
    effective_sha = sha256_text(effective)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    tmp.write(effective)
    tmp.close()
    # NamedTemporaryFile is mode 0600; `docker cp` preserves the mode, and the in-container n8n
    # user ("node") must be able to read it, so make it world-readable before copying.
    os.chmod(tmp.name, 0o644)
    dc(["cp", tmp.name, "n8n:/tmp/mx.json"], timeout=60)
    os.unlink(tmp.name)
    imp = dc(["exec", "-T", "n8n", "n8n", "import:workflow", "--input=/tmp/mx.json"], timeout=120)
    if imp.returncode != 0:
        return None, effective_sha
    listing = dc(["exec", "-T", "n8n", "n8n", "list:workflow"], timeout=60).stdout
    wid = None
    for line in listing.splitlines():
        if "|" in line and line.split("|", 1)[1].strip() == wf["name"]:
            wid = line.split("|", 1)[0].strip()
    return wid, effective_sha


def execute(wid):
    p = dc(["run", "--rm", "--no-deps", "-T", "n8n", "execute", f"--id={wid}", "--rawOutput"], timeout=120)
    return p.stdout, p.returncode, p.stderr


def run_matrix(identity):
    tag = datetime.datetime.now().strftime("%H%M%S")
    attempted = completed = 0
    runs = []
    for variant, src in VARIANTS:
        wf_sha = sha256_file(src)
        prompt = [a["value"] for a in json.load(open(src))["nodes"][1]["parameters"]["assignments"]["assignments"]
                  if a["id"] == "a4"][0]
        prompt_sha = sha256_text(prompt)
        for scenario in SCENARIOS:
            wid, eff_sha = import_variant(variant, scenario, src, tag)
            for rep in (1, 2):
                attempted += 1
                run_id = f"mx-{variant}-{scenario}-r{rep}"
                rec = {
                    "run_id": run_id, "series": "model", "variant": variant,
                    "scenario": scenario, "repeat": rep, "timestamp": now_utc(),
                    "committed_variant": src, "committed_variant_sha256": wf_sha,
                    "prompt_sha256": prompt_sha,
                    # Collector-recorded hash of bytes imported, including a cosmetic name.
                    # Retained data alone do not let the committed gate re-hash those bytes.
                    "effective_workflow_sha256": eff_sha,
                    # Independently recomputable pairing check; not a hash of the imported bytes.
                    "effective_workflow_fingerprint": sha256_text(f"{wf_sha}\n{scenario}"),
                    "workflow_id": wid,
                }
                if wid is None:
                    rec["error"] = "import/list did not yield a workflow id"
                    rec["completed"] = False
                    runs.append(rec)
                    print(f"  {run_id}: IMPORT FAIL")
                    continue
                try:
                    out, code, err = execute(wid)
                except subprocess.TimeoutExpired:
                    rec["error"] = "execute timed out"
                    rec["completed"] = False
                    runs.append(rec)
                    print(f"  {run_id}: TIMEOUT")
                    continue
                rec["execute_returncode"] = code
                data = raw_decode_first(out)
                if code != 0:
                    rec["error"] = f"n8n execute returned nonzero rc={code}"
                    rec["completed"] = False
                    runs.append(rec)
                    print(f"  {run_id}: EXECUTE rc={code} (not completed even if JSON parsed)")
                    continue
                if not data:
                    rec["error"] = f"no JSON in execute output (rc={code})"
                    rec["completed"] = False
                    runs.append(rec)
                    print(f"  {run_id}: NO JSON (rc={code})")
                    continue
                completed += 1
                rec["completed"] = True
                rd = data.get("data", {}).get("resultData", {}).get("runData", {})
                ollama = node_output(rd, "Ollama /api/chat")
                classify = node_output(rd, "Classify model output")
                ctrl = node_output(rd, "Provider controller /v1/runs")
                raw_msg = sanitize(ollama.get("message", {})) if isinstance(ollama, dict) else {}
                rec["model_raw_message"] = raw_msg
                rec["model_parse"] = classify.get("model_parse")
                rec["proposal"] = classify.get("proposal")
                rec["parse_status"] = ctrl.get("parse_status")
                rec["decision"] = ctrl.get("decision")
                rec["effects_before"] = ctrl.get("effects_before")
                rec["effects_after"] = ctrl.get("effects_after")
                rec["effects_delta"] = ctrl.get("effects_delta")
                rec["controller_run_id"] = ctrl.get("run_id")
                rec["model"] = {
                    "tag": identity.get("model_tag"),
                    "digest": identity.get("model_digest"),
                    "parameter_size": identity.get("parameter_size"),
                    "quantization": identity.get("quantization"),
                    "ollama_version": identity.get("ollama_version"),
                    "ollama_image_digest": identity.get("ollama_image_digest"),
                    "n8n_version": identity.get("n8n_version"),
                    "sampling": {"think": False, "temperature": 0, "seed": 42, "stream": False},
                    "eval_count": ollama.get("eval_count"),
                    "ollama_total_duration_ns": ollama.get("total_duration"),
                    "ollama_load_duration_ns": ollama.get("load_duration"),
                    "ollama_eval_duration_ns": ollama.get("eval_duration"),
                }
                rec["n8n_node_ms"] = {n: node_ms(rd, n) for n in
                                      ["Scenario + Prompt", "Ollama /api/chat",
                                       "Classify model output", "Provider controller /v1/runs"]}
                runs.append(rec)
                inv = "OK" if ((rec["decision"] == "Allow") == (rec["effects_delta"] == 1)) else "INVARIANT-FAIL"
                print(f"  {run_id}: parse={rec['model_parse']} decision={rec['decision']} "
                      f"d={rec['effects_delta']} [{inv}]")
    return attempted, completed, runs


def main():
    output_dir = Path(os.environ.get("AISIG_OUTPUT_DIR", "results/model_demo"))
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Experiment output directory: {output_dir}")
    print(f"Part A: fixed controls via {CTRL}")
    controls = run_controls()
    with (output_dir / "controls_results.json").open("w") as f:
        json.dump({"kind": "fixed_controls_results", "controller_url": CTRL, "controls": controls},
                  f, indent=2)
    print(f"controls: {sum(c['pass'] for c in controls)}/{len(controls)} pass")

    skip = os.environ.get("AISIG_SKIP_MODEL") == "1"
    matrix = None
    if skip:
        print("AISIG_SKIP_MODEL=1 -> skipping model matrix")
    else:
        identity = capture_identity()
        print(f"captured identity: model={identity.get('model_digest')} "
              f"ollama={identity.get('ollama_version')} n8n={identity.get('n8n_version')}")
        print("Part B: model matrix (3 variants x 5 scenarios x 2 repeats)")
        attempted, completed, runs = run_matrix(identity)
        matrix = {"kind": "model_matrix_results", "identity": identity,
                  "provenance": {
                      "effective_workflow_sha256":
                          "SHA-256 of the exact bytes imported for the run (committed variant with "
                          "scenario_id overridden, plus a cosmetic unique n8n name). This is a "
                          "collector-recorded hash; its exact bytes cannot be independently "
                          "recomputed from retained data without the name and Python json.dumps "
                          "serialization. The committed gate does not verify this exact hash.",
                      "effective_workflow_fingerprint":
                          "sha256(committed_variant_sha256 + '\\n' + scenario). Independently "
                          "recomputable from the committed variant file and scenario. This verifies "
                          "the recorded variant/scenario pairing, NOT the exact imported bytes; "
                          "verified by tests/model_demo_gate.rs.",
                  },
                  "attempted": attempted, "completed": completed, "runs": runs}
        with (output_dir / "model_matrix.json").open("w") as f:
            json.dump(matrix, f, indent=2)
        print(f"matrix: attempted={attempted} completed={completed}")

    # Fail loudly: any control mismatch / non-200, failed or incomplete execute, missing field,
    # effect-invariant violation, or incomplete coverage makes the whole run nonzero.
    problems = gate_problems(controls, matrix, expected_cells=30 if not skip else None)
    if problems:
        print(f"\nGATE FAILED ({len(problems)} problem(s)):")
        for p in problems:
            print(f"  - {p}")
        return 1
    if skip:
        print("\nGATE PASSED: controls matched; model matrix was skipped.")
    else:
        print("\nGATE PASSED: controls matched and all model cells completed with the effect invariant held.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
