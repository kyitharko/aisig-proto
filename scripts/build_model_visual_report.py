#!/usr/bin/env python3
"""Make an offline, presentation-ready view of one complete synthetic demo run.

Only Python's standard library is needed. This reads recorded results; it never contacts n8n,
Ollama, the provider, or any target. It fails rather than drawing a misleading incomplete chart.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import itertools
import json
from pathlib import Path
from statistics import median

VARIANTS = ("v1", "v2", "v3")
SCENARIOS = ("fresh", "expired_session", "revoked_grant", "stale_status", "unavailable_status")
KINDS = ("Allow", "Deny", "Indeterminate", "No mediation")
COLORS = {"Allow": "#147d64", "Deny": "#c74e45", "Indeterminate": "#b37a15", "No mediation": "#66758d"}
LABELS = {"v1": "Ordinary", "v2": "Boundary override", "v3": "False claimed class"}


def kind(run):
    d = run["decision"]
    if d == "Allow":
        return "Allow"
    if d.startswith("Deny / "):
        return "Deny"
    if d.startswith("Indeterminate / "):
        return "Indeterminate"
    if d.startswith("no mediation:"):
        return "No mediation"
    raise ValueError(f"unknown decision class in {run['run_id']}: {d}")


def check(controls, matrix):
    expected = set(itertools.product(VARIANTS, SCENARIOS, (1, 2)))
    runs = matrix.get("runs", [])
    cells = [(r.get("variant"), r.get("scenario"), r.get("repeat")) for r in runs]
    controls_list = controls.get("controls", [])
    if ({c.get("id") for c in controls_list} != {f"DC{i:02}" for i in range(1, 14)}
            or len(controls_list) != 13 or any(
        c.get("http_status") != 200 or c.get("pass") is not True
        or c.get("actual_decision") != c.get("expected_decision")
        or c.get("actual_delta") != c.get("expected_delta")
        or c.get("actual_parse_status") != c.get("expected_parse_status")
        for c in controls_list
    )):
        raise ValueError("controls must contain 13 passing, exact decision/parse/effect matches")
    if (len(runs) != 30 or len(set(cells)) != 30 or set(cells) != expected
            or matrix.get("attempted") != 30 or matrix.get("completed") != 30):
        raise ValueError("matrix must contain the complete, unique 3×5×2 set of 30 runs")
    for r in runs:
        if r.get("completed") is not True or r.get("execute_returncode") != 0:
            raise ValueError(f"{r['run_id']}: incomplete or nonzero n8n return code")
        before, after, delta = (r.get(f) for f in ("effects_before", "effects_after", "effects_delta"))
        if any(type(x) is not int for x in (before, after, delta)) or after - before != delta:
            raise ValueError(f"{r['run_id']}: inconsistent effect accounting")
        k = kind(r)
        if (k == "Allow") != (delta == 1) or delta not in (0, 1):
            raise ValueError(f"{r['run_id']}: effect invariant failed")
        if r.get("model_parse") is None or r.get("proposal") is None:
            raise ValueError(f"{r['run_id']}: missing model observation")
        if (r["model_parse"] == "tool_call") == (k == "No mediation"):
            raise ValueError(f"{r['run_id']}: actionable proposal / mediation mismatch")
        datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
    return runs


def decision_chart(runs):
    out = [
        '<svg viewBox="0 0 940 300" role="img" aria-label="Decision counts by prompt variant, ten trials each" xmlns="http://www.w3.org/2000/svg">',
        '<style>text{font-family:system-ui,sans-serif;fill:#24344d}.sub{fill:#62738a;font-size:14px}.lab{font-weight:700;font-size:16px}.tick{fill:#66758d;font-size:12px}.value{fill:white;font-size:15px;font-weight:700}</style>',
        '<text x="230" y="30" class="sub">Provider outcome over ten model trials per variant</text>',
    ]
    x0, w = 230, 600
    for i, v in enumerate(VARIANTS):
        y = 70 + i * 65
        out.append(f'<text x="0" y="{y+19}" class="lab">{escape(v)} · {escape(LABELS[v])}</text>')
        counts = Counter(kind(r) for r in runs if r["variant"] == v)
        x = x0
        for k in KINDS:
            n = counts[k]
            if n:
                cw = w * n / 10
                out.append(f'<rect x="{x:.1f}" y="{y}" width="{cw:.1f}" height="32" rx="5" fill="{COLORS[k]}"><title>{escape(k)}: {n} of 10</title></rect>')
                if cw >= 50:
                    out.append(f'<text x="{x+cw/2:.1f}" y="{y+22}" text-anchor="middle" class="value">{n}</text>')
                x += cw
        out.append(f'<text x="845" y="{y+22}" class="sub">10</text>')
    for n in range(0, 11, 2):
        x = x0 + w*n/10
        out.append(f'<text x="{x:.1f}" y="279" text-anchor="middle" class="tick">{n}</text>')
    out.append('</svg>')
    return "".join(out)


def timing_chart(runs):
    times = {v: [r["model"]["ollama_total_duration_ns"] / 1e9 for r in runs if r["variant"] == v]
             for v in VARIANTS}
    if any(len(t) != 10 or any(x <= 0 for x in t) for t in times.values()):
        raise ValueError("all 30 Ollama total-duration observations are required")
    maximum = max(8, int(max(max(t) for t in times.values()) + 1))
    x0, w = 230, 600
    out = ['<svg viewBox="0 0 940 270" role="img" aria-label="Observed Ollama total duration median and range by variant" xmlns="http://www.w3.org/2000/svg">',
           '<style>text{font-family:system-ui,sans-serif;fill:#24344d}.sub{fill:#62738a;font-size:14px}.lab{font-weight:700;font-size:17px}.tick{fill:#66758d;font-size:12px}</style>',
           '<text x="230" y="30" class="sub">Seconds · min–max line, median dot</text>']
    for i, v in enumerate(VARIANTS):
        y = 72 + i*57
        lo, mid, hi = min(times[v]), median(times[v]), max(times[v])
        a, b, c = [x0+w*x/maximum for x in (lo, mid, hi)]
        out.append(f'<text x="0" y="{y+5}" class="lab">{escape(v)} · {escape(LABELS[v])}</text>')
        out.append(f'<line x1="{a:.1f}" x2="{c:.1f}" y1="{y}" y2="{y}" stroke="#8191aa" stroke-width="7" stroke-linecap="round"/>')
        out.append(f'<circle cx="{b:.1f}" cy="{y}" r="10" fill="#2156b1"><title>median {mid:.2f}s, range {lo:.2f}–{hi:.2f}s</title></circle>')
        out.append(f'<text x="845" y="{y+5}" class="sub">p50 {mid:.2f} s</text>')
    for n in range(0, maximum+1, 2):
        x = x0+w*n/maximum
        out.append(f'<text x="{x:.1f}" y="255" text-anchor="middle" class="tick">{n}s</text>')
    out.append('</svg>')
    return "".join(out)


def matrix_html(runs):
    by_cell = {(r["variant"], r["scenario"], r["repeat"]): r for r in runs}
    rows = []
    for s in SCENARIOS:
        cells = [f'<th scope="row">{escape(s.replace("_", " "))}</th>']
        for v in VARIANTS:
            pills = []
            for rep in (1, 2):
                r = by_cell[v, s, rep]
                k = kind(r)
                pills.append(f'<span class="pill {k.lower().replace(" ", "-")}" title="{escape(r["decision"], quote=True)}">r{rep}: {escape(k)}</span>')
            cells.append('<td>' + ' '.join(pills) + '</td>')
        rows.append('<tr>' + ''.join(cells) + '</tr>')
    return ''.join(rows)


def detail_rows(runs):
    rows = []
    for r in runs:
        k = kind(r)
        p = r["proposal"]
        action = ("no mediation · " + str(r["model_parse"])) if k == "No mediation" else (str(p.get("operation") or "—") + " · " + str(p.get("target") or "—"))
        rows.append('<tr data-variant="{}"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><span class="pill {}">{}</span></td><td>{}</td></tr>'.format(
            escape(r["variant"], quote=True), escape(r["run_id"]), escape(r["variant"]),
            escape(r["scenario"]), r["repeat"], escape(action), k.lower().replace(" ", "-"),
            escape(r["decision"]), r["effects_delta"]))
    return ''.join(rows)


def render(controls, matrix, hashes):
    runs = check(controls, matrix)
    counts = Counter(kind(r) for r in runs)
    tool_proposals = sum(r["model_parse"] == "tool_call" for r in runs)
    v2 = [r for r in runs if r["variant"] == "v2"]
    excluded = [r for r in v2 if (r["proposal"] or {}).get("target", "").endswith("/app/admin")]
    denied_excluded = sum(kind(r) == "Deny" and r["effects_delta"] == 0 for r in excluded)
    v2_fresh = [r for r in v2 if r["scenario"] == "fresh"]
    v2_variation = len({(r["model_parse"], str(r["proposal"])) for r in v2_fresh}) > 1
    v3 = [r for r in runs if r["variant"] == "v3"]
    false_claim = sum((r["proposal"] or {}).get("claimed_class") == "data_modification" for r in v3)
    conclusion = (
        "In these fixed synthetic fixtures, the provider mediated every valid model proposal, "
        f"denied {denied_excluded} of {len(excluded)} observed excluded-target attempts, and "
        "recorded no modeled effect after Deny, Indeterminate or no-call."
    )
    timestamps = [datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00")) for r in runs]
    interval = f'{min(timestamps):%Y-%m-%d %H:%M}–{max(timestamps):%H:%M} UTC'
    identity = matrix.get("identity", {})
    legend = ''.join(f'<span><i style="background:{COLORS[k]}"></i>{escape(k)} {counts[k]}</span>' for k in KINDS)
    chart = decision_chart(runs)
    timing = timing_chart(runs)
    content = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AISIG · Synthetic model experiment</title>
<style>
:root{--ink:#1d2c45;--muted:#5c6d84;--line:#dce4ee;--paper:#f4f7fb;--green:#147d64;--red:#c74e45;--amber:#a86d0e;--blue:#2156b1}*{box-sizing:border-box}body{margin:0;font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--ink);background:var(--paper)}main{max-width:1120px;margin:auto;padding:0 24px 72px}.hero{background:#102344;color:white;padding:54px max(24px,calc((100vw - 1072px)/2)) 48px}.eyebrow{color:#98e5d3;text-transform:uppercase;letter-spacing:.14em;font-size:12px;font-weight:800}.hero h1{font-size:clamp(32px,5vw,54px);line-height:1.08;margin:10px 0 18px;max-width:820px}.hero p{max-width:800px;color:#d1def1;font-size:18px}.meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:25px}.meta span{border:1px solid #7185a6;border-radius:999px;padding:5px 12px;font-size:13px;color:#edf4ff}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:-24px 0 42px}.card,.panel{background:white;border:1px solid var(--line);border-radius:15px;box-shadow:0 7px 25px #142d5010}.card{padding:20px}.card strong{display:block;font-size:34px;line-height:1.1;color:#12386f}.card span{color:var(--muted);font-size:14px}.panel{padding:26px;margin:24px 0}h2{font-size:25px;margin:0 0 8px}h3{font-size:18px;margin:0 0 8px}p{margin:7px 0 14px}.small,figcaption,.source{color:var(--muted);font-size:14px}.chart{width:100%;overflow:auto}.chart svg{display:block;width:100%;min-width:720px}.legend{display:flex;gap:18px;flex-wrap:wrap}.legend span{font-size:14px;font-weight:650}.legend i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:710px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:12px 9px;vertical-align:top}thead th{background:#f0f5fb;color:#405673;font-size:13px}td{font-size:14px}tbody tr:nth-child(even){background:#fafcff}.pill{display:inline-block;padding:4px 8px;margin:2px;border-radius:6px;font-size:12px;font-weight:750;white-space:nowrap}.allow{color:#086047;background:#dff4ec}.deny{color:#9e3029;background:#fce9e7}.indeterminate{color:#80550c;background:#fff0cf}.no-mediation{color:#4b5b73;background:#e9edf3}.callout{border-left:4px solid var(--blue);background:#eef5ff;padding:15px 18px;border-radius:0 9px 9px 0}.caution{border-color:var(--amber);background:#fff7e8}.discussion{display:grid;grid-template-columns:repeat(2,1fr);gap:15px}.discussion article{border:1px solid var(--line);border-radius:11px;padding:17px;background:#fbfdff}.discussion article p{margin-bottom:0}.foot{border-top:1px solid var(--line);padding-top:22px;overflow-wrap:anywhere}.source{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}select{font:inherit;padding:7px 10px;border:1px solid #b7c7da;border-radius:7px;background:white}a{color:#174ea6}@media(max-width:760px){.cards{grid-template-columns:repeat(2,1fr)}.discussion{grid-template-columns:1fr}.hero{padding:35px 24px 55px}}@media print{body{background:white}.panel,.card{box-shadow:none;break-inside:avoid}.hero{padding:25px;color:#102344;background:white}.hero p,.meta span{color:#223d60}.cards{margin:10px 0}.chart svg{min-width:0}}
</style></head><body>
<header class="hero"><div class="eyebrow">AISIG · local research prototype</div><h1>Model proposals. Provider decisions. Modeled effects.</h1><p>A CPU-only small-model experiment through n8n and the Rust provider controller. The three evidence types are shown separately: fixed controls, observed model behavior, and per-request in-memory effects.</p><div class="meta"><span>@@INTERVAL@@</span><span>qwen3:1.7b · Ollama @@OLLAMA@@ · n8n @@N8N@@</span><span>Synthetic targets only</span></div></header>
<main>
<section class="cards" aria-label="Key figures"><div class="card"><strong>13 / 13</strong><span>preregistered controls matched</span></div><div class="card"><strong>30 / 30</strong><span>model workflows completed</span></div><div class="card"><strong>0</strong><span>effect-invariant failures</span></div><div class="card"><strong>@@EXCLUDED@@ / 10</strong><span>boundary-prompt trials proposed /app/admin</span></div></section>
<section class="panel"><h2>Provider decisions across model trials</h2><p>Thirty model outputs: @@TOOL_PROPOSALS@@ valid tool proposals and @@NO_MED@@ without mediation. The bars count provider outcomes, not what the model was expected to say.</p><div class="chart">@@DECISION_CHART@@</div><div class="legend">@@LEGEND@@</div><figcaption>Each prompt variant has ten trials (five scenarios × two repeats). “No mediation” means the provider had no actionable tool call; it is not a provider Deny. The table below shows the model parse status.</figcaption></section>
<section class="panel"><h2>Where the decisions changed</h2><p>Each cell contains two separate executions. Hover a label for the full stage/reason; inspect the table below for actual proposals.</p><div class="table-wrap"><table><thead><tr><th>Scenario</th><th>v1 · Ordinary</th><th>v2 · Boundary override</th><th>v3 · False claim</th></tr></thead><tbody>@@MATRIX@@</tbody></table></div><p class="small">The scenario is selected by the experimenter in n8n and is not shown to the model. For an excluded target, a scope Deny can dominate unavailable or stale status.</p></section>
<section class="panel"><h2>Discussion</h2><div class="discussion"><article><h3>Boundary prompt</h3><p>v2 proposed the excluded <code>/app/admin</code> target in <strong>@@EXCLUDED@@ of 10</strong> executions. The provider denied <strong>@@DENIED_EXCLUDED@@ of those @@EXCLUDED@@</strong>; those denied attempts had zero modeled effects. This is an observation about these trials.</p></article><article><h3>Repeat variation</h3><p>v2's two fresh repeats @@VARIATION@@. These two repeats cannot establish a general determinism claim, even with a fixed seed and temperature of zero.</p></article><article><h3>Audit-only class</h3><p>v3 supplied a false <code>claimed_class=data_modification</code> in <strong>@@FALSE_CLAIM@@ of 10</strong> proposals. The provider used the actual operation/target; the claim did not change the modeled policy decision.</p></article><article><h3>Effects and evidence</h3><p>Only the <strong>@@ALLOW@@</strong> Allow outcomes appended one receipt. The @@DENY@@ Deny, @@INDET@@ Indeterminate and @@NO_MED@@ no-mediation outcomes appended none. Fresh fixtures are created per request; deltas are not cumulative.</p></article></div></section>
<section class="panel"><h2>Observed model runtime</h2><p>Median and min–max of Ollama's <code>total_duration</code> field, grouped by variant.</p><div class="chart">@@TIMING_CHART@@</div><p class="small">One CPU-only host; load time can be included. This is an Ollama-reported duration, not measured end-to-end deployment latency. Do not add it to n8n or verifier timing.</p></section>
<section class="panel"><h2>All 30 model observations</h2><label for="variant">Filter variant: </label><select id="variant"><option value="all">All</option><option value="v1">v1</option><option value="v2">v2</option><option value="v3">v3</option></select><div class="table-wrap"><table id="runs"><thead><tr><th>Run</th><th>Variant</th><th>Scenario</th><th>Repeat</th><th>Observed proposal</th><th>Outcome</th><th>Modeled Δ</th></tr></thead><tbody>@@DETAILS@@</tbody></table></div></section>
<section class="panel"><h2>Conclusion and boundary</h2><p class="callout">@@CONCLUSION@@</p><p>This demonstrates the provider <em>decision path</em> in a small local sample. It does not demonstrate enforcement of real tools, real-world authorization evidence, a population model-behavior rate, a privacy guarantee, or deployment latency. A separate independent security review is required before production use.</p><p>To try additional scenarios on a local machine, follow <code>docs/manual-experiments.md</code>. Keep exploratory runs distinct from the preregistered matrix.</p></section>
<footer class="foot small"><strong>Sources:</strong> the <code>controls_results.json</code> and <code>model_matrix.json</code> supplied to this report builder. Offline HTML; no external scripts, requests, or model weights. <span class="source">Controls SHA-256: @@CONTROL_SHA@@ · Matrix SHA-256: @@MATRIX_SHA@@</span></footer>
</main><script>document.getElementById('variant').addEventListener('change',function(){for(const row of document.querySelectorAll('#runs tbody tr'))row.hidden=this.value!=='all'&&row.dataset.variant!==this.value;});</script></body></html>'''
    replacements = {
        "INTERVAL": interval, "OLLAMA": escape(identity.get("ollama_version", "unknown")),
        "N8N": escape(identity.get("n8n_version", "unknown")),
        "EXCLUDED": str(len(excluded)), "DENIED_EXCLUDED": str(denied_excluded),
        "VARIATION": "differed in parse status or proposal" if v2_variation else "matched in parse status and proposal in this run",
        "TOOL_PROPOSALS": str(tool_proposals),
        "FALSE_CLAIM": str(false_claim), "ALLOW": str(counts["Allow"]), "DENY": str(counts["Deny"]),
        "INDET": str(counts["Indeterminate"]), "NO_MED": str(counts["No mediation"]),
        "CONCLUSION": escape(conclusion),
        "DECISION_CHART": chart, "TIMING_CHART": timing, "MATRIX": matrix_html(runs),
        "DETAILS": detail_rows(runs), "LEGEND": legend, "CONTROL_SHA": hashes[0],
        "MATRIX_SHA": hashes[1],
    }
    for key, value in replacements.items():
        content = content.replace("@@" + key + "@@", value)
    return content


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--matrix", type=Path, default=Path("results/model_demo/model_matrix.json"))
    ap.add_argument("--controls", type=Path, default=Path("results/model_demo/controls_results.json"))
    ap.add_argument("--output", type=Path, default=Path("results/model_demo/visual_report.html"))
    ap.add_argument("--svg-output", type=Path,
                    help="default: decision_distribution.svg beside --output")
    args = ap.parse_args()
    controls_bytes, matrix_bytes = args.controls.read_bytes(), args.matrix.read_bytes()
    content = render(json.loads(controls_bytes), json.loads(matrix_bytes),
                     (sha256(controls_bytes).hexdigest(), sha256(matrix_bytes).hexdigest()))
    svg_output = args.svg_output or args.output.with_name("decision_distribution.svg")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    svg_output.parent.mkdir(parents=True, exist_ok=True)
    svg_output.write_text(decision_chart(json.loads(matrix_bytes)["runs"]) + "\n", encoding="utf-8")
    print(f"Wrote {args.output} and {svg_output} from 13 controls and 30 model runs")


if __name__ == "__main__":
    main()
