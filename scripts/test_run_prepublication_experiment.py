#!/usr/bin/env python3
"""Regression tests for the experiment runner's failure gate (scripts/run_prepublication_experiment.py).

Run from the repository root:  python3 scripts/test_run_prepublication_experiment.py

These prove that the runner must FAIL (nonzero / non-empty problem list) when:
  - 0/13 (or any) fixed controls mismatch, or a control returns a non-200 HTTP status;
  - an n8n import/execute fails or is incomplete (it must not be counted as completed);
  - a completed run is missing controller fields, or violates the Allow<=>delta==1 invariant;
  - the model matrix does not cover all expected cells.
Before the fix the runner has no `gate_problems` function at all — it always exits 0 — so these
tests fail (red), documenting the defect. After the fix they pass.
"""
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("runner", "scripts/run_prepublication_experiment.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def good_controls():
    return [{"id": f"DC{i:02d}", "http_status": 200, "pass": True} for i in range(1, 14)]


def good_matrix():
    runs = []
    for v in ("v1", "v2", "v3"):
        for s in ("fresh", "expired_session", "revoked_grant", "stale_status", "unavailable_status"):
            for rep in (1, 2):
                allow = (s == "fresh" and v in ("v1", "v3"))
                runs.append({
                    "run_id": f"mx-{v}-{s}-r{rep}", "variant": v, "scenario": s, "repeat": rep,
                    "completed": True, "decision": "Allow" if allow else "Deny / scope / X",
                    "parse_status": "tool_call", "effects_delta": 1 if allow else 0,
                    "proposal": {"operation": "web.get", "target": "web:https://app.acme.test:443/app/reports"},
                    "model_raw_message": {"tool_calls": [{"function": {"name": "propose_action"}}]},
                })
    return {"attempted": 30, "completed": 30, "runs": runs}


TESTS = []
def test(fn): TESTS.append(fn); return fn


@test
def test_runner_has_a_failure_gate():
    assert hasattr(runner, "gate_problems"), (
        "runner has no gate_problems -> it exits 0 even on 0/13 controls or failed executes")


@test
def test_clean_results_have_no_problems():
    assert runner.gate_problems(good_controls(), good_matrix(), expected_cells=30) == []


@test
def test_zero_control_matches_is_a_failure():
    controls = [{"id": f"DC{i:02d}", "http_status": 200, "pass": False} for i in range(1, 14)]
    probs = runner.gate_problems(controls, good_matrix(), expected_cells=30)
    assert probs, "0/13 control matches must be a gate failure, not success"


@test
def test_non_200_control_is_a_failure():
    controls = good_controls()
    controls[0] = {"id": "DC01", "http_status": 500, "pass": False}
    assert runner.gate_problems(controls, good_matrix(), expected_cells=30)


@test
def test_failed_execute_is_not_completed_and_fails_gate():
    m = good_matrix()
    m["runs"][0] = {"run_id": "mx-v1-fresh-r1", "variant": "v1", "scenario": "fresh",
                    "repeat": 1, "completed": False, "error": "execute timed out"}
    m["completed"] = 29
    probs = runner.gate_problems(good_controls(), m, expected_cells=30)
    assert probs, "a failed/incomplete execute must fail the gate and not count as completed"


@test
def test_missing_controller_field_fails_gate():
    m = good_matrix()
    m["runs"][5]["decision"] = None
    assert runner.gate_problems(good_controls(), m, expected_cells=30)


@test
def test_effect_invariant_violation_fails_gate():
    m = good_matrix()
    m["runs"][0]["decision"] = "Allow"
    m["runs"][0]["effects_delta"] = 0  # Allow must have delta 1
    assert runner.gate_problems(good_controls(), m, expected_cells=30)


@test
def test_incomplete_cell_coverage_fails_gate():
    m = good_matrix()
    m["runs"] = m["runs"][:28]
    m["attempted"] = 28
    m["completed"] = 28
    assert runner.gate_problems(good_controls(), m, expected_cells=30)


def main():
    failed = 0
    for t in TESTS:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(TESTS) - failed}/{len(TESTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
