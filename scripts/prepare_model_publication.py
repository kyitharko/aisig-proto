#!/usr/bin/env python3
"""Prepare, check and promote a sanitized copy of one completed local model run.

The original local-experiments folder is never modified. The candidate stays in that
gitignored tree until a human reviews it. Promotion creates a separate results copy;
this script does not commit or push anything.
"""

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlsplit

import build_model_visual_report as visual
import sanitize_n8n_export as sanitizer


ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "local-experiments"
RESULTS = ROOT / "results/model_demo"
EXPECTED = ROOT / "results/model_demo/controls_expected.json"
WORKFLOWS = {
    "v1": ROOT / "demo/n8n-workflow.json",
    "v2": ROOT / "demo/n8n-workflow-v2.json",
    "v3": ROOT / "demo/n8n-workflow-v3.json",
}
FILES = ("README.md", "publication_manifest.json", "controls_results.json", "model_matrix.json",
         "visual_report.html", "decision_distribution.svg")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
LOCAL_PATH = re.compile(r"/home/|/Users/|[A-Za-z]:\\Users\\", re.IGNORECASE)


class PublicationError(Exception):
    pass


def require(ok, message):
    if not ok:
        raise PublicationError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def inside(path, parent):
    return path.resolve().is_relative_to(parent.resolve())


def sensitive_paths(node, path="root"):
    hits = []
    if isinstance(node, dict):
        for key, val in node.items():
            item = f"{path}.{key}"
            if sanitizer.is_sensitive(key):
                hits.append(item)
            hits.extend(sensitive_paths(val, item))
    elif isinstance(node, list):
        for i, val in enumerate(node):
            hits.extend(sensitive_paths(val, f"{path}[{i}]"))
    return hits


def check_public_text(data, name):
    text = data.decode("utf-8")
    require(not LOCAL_PATH.search(text), f"{name}: a local filesystem path remains")
    for match in IPV4.finditer(text):
        try:
            ipaddress.IPv4Address(match.group())
        except ipaddress.AddressValueError:
            continue
        raise PublicationError(f"{name}: an IPv4 address remains in the candidate")


def validate_controls(controls):
    expected = read_json(EXPECTED)["controls"]
    rows = controls.get("controls")
    require(isinstance(rows, list) and len(rows) == len(expected) == 13,
            "controls: expected exactly 13 rows")
    by_id = {row.get("id"): row for row in rows}
    require(len(by_id) == 13 and set(by_id) == {row["id"] for row in expected},
            "controls: duplicate or unexpected case ID")
    for entry in expected:
        row = by_id[entry["id"]]
        for field in ("scenario", "proposal", "expected_decision",
                      "expected_parse_status", "expected_delta"):
            require(row.get(field) == entry[field], f"{entry['id']}: {field} drift")
        require(row.get("http_status") == 200 and row.get("pass") is True,
                f"{entry['id']}: failed control or HTTP status")
        for actual, wanted in (("actual_decision", "expected_decision"),
                               ("actual_parse_status", "expected_parse_status"),
                               ("actual_delta", "expected_delta")):
            require(row.get(actual) == entry[wanted], f"{entry['id']}: {actual} mismatch")


def workflow_hashes():
    out = {}
    for variant, path in WORKFLOWS.items():
        data = path.read_bytes()
        workflow = json.loads(data)
        prompts = [a["value"] for node in workflow["nodes"]
                   if node.get("type") == "n8n-nodes-base.set"
                   for a in node["parameters"]["assignments"]["assignments"]
                   if a.get("id") == "a4"]
        require(len(prompts) == 1 and isinstance(prompts[0], str),
                f"{variant}: expected one committed prompt")
        out[variant] = (digest(data), digest(prompts[0].encode("utf-8")))
    return out


def validate_matrix(matrix, controls):
    runs = visual.check(controls, matrix)
    require(matrix.get("kind") == "model_matrix_results", "matrix: wrong kind")
    identity = matrix.get("identity", {})
    require(isinstance(identity, dict), "matrix: invalid runtime identity")
    require(isinstance(identity.get("model_digest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", identity["model_digest"]),
            "matrix: missing model digest")
    require(identity.get("model_tag") == "qwen3:1.7b", "matrix: unexpected model tag")
    require(identity.get("ollama_version") and identity.get("n8n_version"),
            "matrix: missing runtime identity")
    require(isinstance(matrix.get("provenance"), dict) and
            isinstance(matrix["provenance"].get("effective_workflow_fingerprint"), str),
            "matrix: missing fingerprint provenance note")
    hashes = workflow_hashes()
    for row in runs:
        variant, scenario, rep = row["variant"], row["scenario"], row["repeat"]
        label = f"mx-{variant}-{scenario}-r{rep}"
        require(row.get("run_id") == label, f"{label}: unexpected run ID")
        wf_hash, prompt_hash = hashes[variant]
        require(row.get("committed_variant") == str(WORKFLOWS[variant].relative_to(ROOT)),
                f"{label}: workflow path mismatch")
        require(row.get("committed_variant_sha256") == wf_hash
                and row.get("prompt_sha256") == prompt_hash,
                f"{label}: committed workflow/prompt hash mismatch")
        require(row.get("effective_workflow_fingerprint") ==
                digest(f"{wf_hash}\n{scenario}".encode("utf-8")),
                f"{label}: workflow fingerprint mismatch")
        require(isinstance(row.get("effective_workflow_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", row["effective_workflow_sha256"]),
                f"{label}: missing recorded import hash")
        require(isinstance(row.get("workflow_id"), str) and row["workflow_id"],
                f"{label}: missing workflow ID")
        require(row.get("model_parse") == row.get("parse_status"),
                f"{label}: model/controller parse mismatch")
        require(isinstance(row.get("model"), dict) and
                row["model"].get("digest") == identity["model_digest"],
                f"{label}: model digest mismatch")
        raw = row.get("model_raw_message")
        proposal = row.get("proposal")
        require(isinstance(raw, dict) and isinstance(proposal, dict),
                f"{label}: raw message or proposal absent")
        calls = raw.get("tool_calls", [])
        if row["model_parse"] == "tool_call":
            require(isinstance(calls, list) and len(calls) == 1,
                    f"{label}: expected exactly one raw tool call")
            fn = calls[0].get("function", {})
            args = fn.get("arguments", {})
            require(fn.get("name") == "propose_action" and isinstance(args, dict),
                    f"{label}: unexpected raw tool call")
            for field in ("operation", "target", "claimed_class"):
                require(args.get(field) == proposal.get(field),
                        f"{label}: raw/recorded classifier {field} mismatch")
            require(bool(proposal.get("operation")) and bool(proposal.get("target")),
                    f"{label}: empty operation or target")
        elif row["model_parse"] == "no_call":
            require(not calls and proposal.get("operation") is None
                    and proposal.get("target") is None,
                    f"{label}: no-call carries an operation")
        else:
            require(isinstance(calls, list), f"{label}: invalid raw tool_calls")
    return runs


def public_pair(controls, matrix):
    require(isinstance(controls.get("controller_url"), str),
            "controls: missing controller URL")
    parts = urlsplit(controls["controller_url"])
    require(parts.scheme == "http" and parts.port == 8787 and parts.hostname
            and not parts.username and not parts.password
            and not parts.path and not parts.query and not parts.fragment,
            "controls: unexpected controller URL")
    try:
        ipaddress.IPv4Address(parts.hostname)
    except ipaddress.AddressValueError as exc:
        raise PublicationError("controls: expected an IPv4 controller endpoint") from exc
    controls = dict(controls)
    controls["controller_url"] = "http://100.x.y.z:8787"
    removed = []
    controls = sanitizer.sanitize(controls, "controls", removed)
    matrix = sanitizer.sanitize(matrix, "matrix", removed)
    require(not sensitive_paths(controls) and not sensitive_paths(matrix),
            "candidate contains secret-like field names")
    validate_controls(controls)
    validate_matrix(matrix, controls)
    cb, mb = json_bytes(controls), json_bytes(matrix)
    check_public_text(cb, "controls_results.json")
    check_public_text(mb, "model_matrix.json")
    return cb, mb, removed


def publication_manifest(source, manifest, removed):
    require(re.fullmatch(r"full-\d{8}T\d{6}Z-[0-9a-f]{8}", source.name),
            "input folder name is not a full-run ID")
    for field in ("started_utc", "ended_utc"):
        value = manifest.get(field)
        require(isinstance(value, str), f"manifest: {field} missing")
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(date.tzinfo is not None, f"manifest: {field} must have a timezone")
    revision = manifest.get("git_commit")
    require(revision is None or
            (isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision)),
            "manifest: invalid Git commit")
    return {"source_run_id": source.name, "started_utc": manifest["started_utc"],
            "ended_utc": manifest["ended_utc"], "git_commit": revision,
            "removed_sensitive_key_count": len(removed)}


def validate_publication_manifest(manifest):
    fields = {"source_run_id", "started_utc", "ended_utc", "git_commit",
              "removed_sensitive_key_count"}
    require(isinstance(manifest, dict) and
            (set(manifest) == fields or
             (set(manifest) == fields | {"publication_stage"} and
              manifest["publication_stage"] == "publication_copy")),
            "publication manifest: invalid field set")
    name = manifest["source_run_id"]
    require(isinstance(name, str) and
            re.fullmatch(r"full-\d{8}T\d{6}Z-[0-9a-f]{8}", name),
            "publication manifest: invalid run ID")
    require(type(manifest["removed_sensitive_key_count"]) is int and
            0 <= manifest["removed_sensitive_key_count"] <= 10000,
            "publication manifest: invalid redaction count")
    publication_manifest(Path(name), manifest, [])


def readme(manifest, controls, matrix, cb, mb):
    runs = matrix["runs"]
    counts = Counter(visual.kind(r) for r in runs)
    no_calls = [r["run_id"] for r in runs if visual.kind(r) == "No mediation"]
    v2_excluded = sum(r["variant"] == "v2" and
                      str(r["proposal"].get("target") or "").endswith("/app/admin")
                      for r in runs)
    published = manifest.get("publication_stage") == "publication_copy"
    intro = ("This publication copy was made from a validated, ignored candidate.\n"
             "The original local run is unchanged; this copy does not imply a GitHub\n"
             "release or an independent audit of the live stack."
             if published else
             "This is a publication **candidate** copied from one completed, ignored local run.\n"
             "The original input folder was not modified. Review this candidate before moving\n"
             "it into `results/model_demo/`; this script does not commit or publish it.")
    review = ("Review this publication copy" if published else "Check the candidate")
    input_kind = "publication" if published else "candidate"
    return f"""# Separate synthetic replication — {manifest['source_run_id']}

{intro}
Source run ID: `{manifest['source_run_id']}`.

## Method and provenance

- Preregistered controls DC01–DC13 were sent to the synthetic provider HTTP service.
- Three committed prompt variants × five scenarios × two repeats produced 30 n8n
  executions using the collector-recorded qwen3:1.7b model (`think=false`, temperature 0,
  seed 42). Workflow and prompt hashes were compared with committed files.
- The collector started at {manifest['started_utc']} and ended at
  {manifest['ended_utc']}. Its exit code was 0. Its recorded Git HEAD was
  `{manifest.get('git_commit') or 'unavailable'}`. **HEAD alone does not attest
  to uncommitted working-tree edits** or to the exact controller binary/image.
- The recorded `effective_workflow_sha256` is a collector-reported hash of
  imported bytes; the imported bytes were not retained for independent hashing.
  The recomputable fingerprint binds the committed variant hash and scenario,
  not the actual import or container binary.

## Observed outcome

All 13/13 controls matched their preregistered decision, parse and effect delta.
All 30/30 planned model cells completed and passed the per-request effect check.

| Variant | Allow | Deny | Indeterminate | No mediation |
| --- | ---: | ---: | ---: | ---: |
""" + "\n".join(
        f"| {v} | " + " | ".join(str(Counter(visual.kind(r) for r in runs if r['variant'] == v)[k])
                                  for k in visual.KINDS) + " |"
        for v in visual.VARIANTS
    ) + f"""
| **Total** | **{counts['Allow']}** | **{counts['Deny']}** | **{counts['Indeterminate']}** | **{counts['No mediation']}** |

The boundary prompt proposed excluded `/app/admin` in {v2_excluded}/10 v2
executions. No-mediation case IDs: {', '.join(no_calls) if no_calls else 'none'}.
No mediation means no actionable model tool call; it is not a provider Deny or
an inferred model refusal. Allow had one modeled in-memory effect per request;
Deny, Indeterminate and no mediation had zero. This small sample does not
establish a population rate or deterministic model behavior.

See [visual_report.html](visual_report.html) for the chart, all 30 observations,
discussion and conclusion; the standalone graph is
[decision_distribution.svg](decision_distribution.svg).

## Publication checks and limits

Only the `controller_url` in controls was deliberately changed to the
`100.x.y.z` placeholder; {manifest['removed_sensitive_key_count']} secret-like field(s) were removed by
the recursive key sanitizer. The new JSON pair was revalidated after
sanitization; sensitive values are not printed here. {review}
manually for unknown private material before publishing. The original
`run_manifest.json` was not copied because it includes a local output path;
`publication_manifest.json` keeps only validated, sanitized metadata.

| Published input | SHA-256 |
| --- | --- |
| `controls_results.json` | `{digest(cb)}` |
| `model_matrix.json` | `{digest(mb)}` |

The HTML embeds these two **{input_kind}** input hashes, and the HTML/SVG must
regenerate byte-for-byte from them. No real target was contacted; this models
a provider decision and an in-memory effect only. Real tool enforcement,
independent authorization evidence, and deployment latency remain open.
"""


def generate(candidate, cb, mb, summary, note):
    controls, matrix = json.loads(cb), json.loads(mb)
    runs = validate_matrix(matrix, controls)
    candidate.mkdir(mode=0o700)
    (candidate / "controls_results.json").write_bytes(cb)
    (candidate / "model_matrix.json").write_bytes(mb)
    (candidate / "publication_manifest.json").write_bytes(json_bytes(summary))
    (candidate / "README.md").write_text(note, encoding="utf-8")
    html = visual.render(controls, matrix, (digest(cb), digest(mb)))
    (candidate / "visual_report.html").write_text(html, encoding="utf-8")
    (candidate / "decision_distribution.svg").write_text(
        visual.decision_chart(runs) + "\n", encoding="utf-8")


def check_dir(directory):
    require(directory.is_dir() and {p.name for p in directory.iterdir()} == set(FILES),
            "result directory must contain exactly the six expected files")
    for name in FILES:
        require((directory / name).is_file(), f"candidate missing {name}")
        check_public_text((directory / name).read_bytes(), name)
    cb = (directory / "controls_results.json").read_bytes()
    mb = (directory / "model_matrix.json").read_bytes()
    controls, matrix = json.loads(cb), json.loads(mb)
    summary = read_json(directory / "publication_manifest.json")
    validate_publication_manifest(summary)
    require(controls.get("controller_url") == "http://100.x.y.z:8787",
            "candidate has unredacted or unexpected controller URL")
    require(not sensitive_paths(controls) and not sensitive_paths(matrix),
            "candidate has secret-like JSON keys")
    validate_controls(controls)
    runs = validate_matrix(matrix, controls)
    expected_html = visual.render(controls, matrix, (digest(cb), digest(mb)))
    expected_svg = visual.decision_chart(runs) + "\n"
    require((directory / "visual_report.html").read_text(encoding="utf-8") == expected_html,
            "HTML does not match the sanitized JSON inputs")
    require((directory / "decision_distribution.svg").read_text(encoding="utf-8") == expected_svg,
            "SVG does not match the sanitized JSON inputs")
    note = (directory / "README.md").read_text(encoding="utf-8")
    require(note == readme(summary, controls, matrix, cb, mb),
            "README does not match the sanitized JSON and publication manifest")
    return Counter(visual.kind(r) for r in runs)


def prepare(input_dir, candidate):
    source = input_dir.resolve()
    target = candidate.resolve()
    require(inside(source, LOCAL) and source.name.startswith("full-") and source.is_dir(),
            "input must be a completed full-* folder inside local-experiments/")
    require(inside(target, LOCAL) and target != source and not target.exists(),
            "candidate must be a new folder inside local-experiments/")
    require(target.parent.is_dir(), "candidate parent directory does not exist")
    manifest = read_json(source / "run_manifest.json")
    require(manifest.get("mode") == "full" and manifest.get("collector_returncode") == 0,
            "source manifest does not record a successful full run")
    require(manifest.get("output_directory") == str(source.relative_to(ROOT)),
            "source manifest output directory does not match input")
    controls = read_json(source / "controls_results.json")
    matrix = read_json(source / "model_matrix.json")
    cb, mb, removed = public_pair(controls, matrix)
    summary = publication_manifest(source, manifest, removed)
    validate_publication_manifest(summary)
    note = readme(summary, json.loads(cb), json.loads(mb), cb, mb)
    temp = Path(tempfile.mkdtemp(prefix=".aisig_candidate_", dir=target.parent))
    try:
        # generate() creates the directory, so use a child of the temporary root.
        staged = temp / "candidate"
        generate(staged, cb, mb, summary, note)
        counts = check_dir(staged)
        require(not target.exists(), "candidate destination appeared during preparation")
        os.rename(staged, target)
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    print(f"Candidate created at {target} (original untouched)")
    print("Allow={Allow} Deny={Deny} Indeterminate={Indeterminate} No mediation={No mediation}".format(**counts))
    return target


def promote(candidate, published_dir):
    source, target = candidate.resolve(), published_dir.resolve()
    require(inside(source, LOCAL) and source.is_dir(),
            "publication candidate must be inside local-experiments/")
    require(inside(target, RESULTS) and not target.exists()
            and target.parent.is_dir(),
            "publication destination must be a new results/model_demo/ folder")
    check_dir(source)
    cb = (source / "controls_results.json").read_bytes()
    mb = (source / "model_matrix.json").read_bytes()
    summary = read_json(source / "publication_manifest.json")
    require("publication_stage" not in summary, "source must be a candidate")
    summary["publication_stage"] = "publication_copy"
    validate_publication_manifest(summary)
    note = readme(summary, json.loads(cb), json.loads(mb), cb, mb)
    temp = Path(tempfile.mkdtemp(prefix=".aisig_publication_", dir=target.parent))
    try:
        staged = temp / "publication"
        generate(staged, cb, mb, summary, note)
        counts = check_dir(staged)
        for name in ("controls_results.json", "model_matrix.json", "visual_report.html",
                     "decision_distribution.svg"):
            require((source / name).read_bytes() == (staged / name).read_bytes(),
                    f"promoted {name} differs from the reviewed candidate")
        require(not target.exists(), "publication destination appeared during preparation")
        os.rename(staged, target)
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    print(f"Publication copy created at {target} (candidate untouched)")
    print("Allow={Allow} Deny={Deny} Indeterminate={Indeterminate} No mediation={No mediation}".format(**counts))
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input-dir", type=Path, help="completed ignored full-* run")
    source.add_argument("--check-dir", type=Path, help="recheck a candidate or published copy")
    source.add_argument("--promote-dir", type=Path, help="validated ignored candidate to promote")
    parser.add_argument("--candidate-dir", type=Path, help="new ignored publication-candidate folder")
    parser.add_argument("--published-dir", type=Path, help="new results/model_demo folder")
    args = parser.parse_args(argv)
    try:
        if args.check_dir:
            require(args.candidate_dir is None and args.published_dir is None,
                    "--check-dir takes no destination")
            counts = check_dir(args.check_dir)
            print("Result gate passed: 13/13 controls, 30/30 model cells; "
                  "Allow={Allow} Deny={Deny} Indeterminate={Indeterminate} "
                  "No mediation={No mediation}".format(**counts))
        elif args.promote_dir:
            require(args.published_dir is not None and args.candidate_dir is None,
                    "--promote-dir needs --published-dir only")
            promote(args.promote_dir, args.published_dir)
        else:
            require(args.candidate_dir is not None and args.published_dir is None,
                    "--input-dir needs --candidate-dir only")
            prepare(args.input_dir, args.candidate_dir)
    except (PublicationError, ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        parser.exit(1, f"Publication result failed: {exc}\n")


if __name__ == "__main__":
    main()
