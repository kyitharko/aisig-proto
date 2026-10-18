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
Writes results/model_demo/controls_results.json and results/model_demo/model_matrix.json.

Env:
  AISIG_CONTROLLER_URL  controller base URL (default http://controller:8787; from the host use the
                        controller container IP, e.g. http://172.x.x.x:8787)
  AISIG_COMPOSE         compose file (default demo/compose.cpu.yml)
  AISIG_SKIP_MODEL      if set to "1", run only Part A (controls)
"""
import datetime
import hashlib
import importlib.util
import json
import os
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
    wf = json.load(open(src_path))
    wf["name"] = f"aisig-mx-{tag}-{variant}-{scenario}"
    for a in wf["nodes"][1]["parameters"]["assignments"]["assignments"]:
        if a["id"] == "a1":
            a["value"] = scenario
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(wf, tmp)
    tmp.close()
    # NamedTemporaryFile is mode 0600; `docker cp` preserves the mode, and the in-container n8n
    # user ("node") must be able to read it, so make it world-readable before copying.
    os.chmod(tmp.name, 0o644)
    dc(["cp", tmp.name, "n8n:/tmp/mx.json"], timeout=60)
    os.unlink(tmp.name)
    dc(["exec", "-T", "n8n", "n8n", "import:workflow", "--input=/tmp/mx.json"], timeout=120)
    listing = dc(["exec", "-T", "n8n", "n8n", "list:workflow"], timeout=60).stdout
    wid = None
    for line in listing.splitlines():
        if "|" in line and line.split("|", 1)[1].strip() == wf["name"]:
            wid = line.split("|", 1)[0].strip()
    return wid


def execute(wid):
    p = dc(["run", "--rm", "--no-deps", "-T", "n8n", "execute", f"--id={wid}", "--rawOutput"], timeout=120)
    return p.stdout, p.returncode, p.stderr


def run_matrix():
    tag = datetime.datetime.now().strftime("%H%M%S")
    attempted = completed = 0
    runs = []
    for variant, src in VARIANTS:
        wf_sha = sha256_file(src)
        prompt = [a["value"] for a in json.load(open(src))["nodes"][1]["parameters"]["assignments"]["assignments"]
                  if a["id"] == "a4"][0]
        prompt_sha = sha256_text(prompt)
        for scenario in SCENARIOS:
            wid = import_variant(variant, scenario, src, tag)
            for rep in (1, 2):
                attempted += 1
                run_id = f"mx-{variant}-{scenario}-r{rep}"
                rec = {
                    "run_id": run_id, "series": "model", "variant": variant,
                    "scenario": scenario, "repeat": rep, "timestamp": now_utc(),
                    "workflow_file": src, "workflow_sha256": wf_sha, "prompt_sha256": prompt_sha,
                    "committed_variant": src,
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
                data = raw_decode_first(out)
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
                    "tag": "qwen3:1.7b",
                    "digest_sha256": "8f68893c685c3ddff2aa3fffce2aa60a30bb2da65ca488b61fff134a4d1730e7",
                    "ollama_version": "0.40.6",
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
    print(f"Part A: fixed controls via {CTRL}")
    controls = run_controls()
    json.dump({"kind": "fixed_controls_results", "controller_url": CTRL, "controls": controls},
              open("results/model_demo/controls_results.json", "w"), indent=2)
    print(f"controls: {sum(c['pass'] for c in controls)}/{len(controls)} pass")

    if os.environ.get("AISIG_SKIP_MODEL") == "1":
        print("AISIG_SKIP_MODEL=1 -> skipping model matrix")
        return
    print("Part B: model matrix (3 variants x 5 scenarios x 2 repeats)")
    attempted, completed, runs = run_matrix()
    json.dump({"kind": "model_matrix_results", "attempted": attempted, "completed": completed,
               "runs": runs}, open("results/model_demo/model_matrix.json", "w"), indent=2)
    print(f"matrix: attempted={attempted} completed={completed}")


if __name__ == "__main__":
    sys.exit(main())
