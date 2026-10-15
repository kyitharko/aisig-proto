//! Running labelled cases through both verifiers and summarizing (docs/experiment.md §7).

use serde_json::{json, Value};

use crate::asset::{exact_node_lookup, subtree_lookup, ExactNodeAnswer, SubtreeAnswer};
use crate::decision::{Decision, DecisionClass};
use crate::policy::grant_scope;
use crate::verifier::decode_chain;

use super::cases::CaseLabel;
use super::fixture::{asset_ref, Scenario};
use super::mutations::scenario_for;

pub struct ChainRow {
    pub label: CaseLabel,
    pub chain: Decision,
    pub baseline: Decision,
}

pub struct QueryRow {
    pub label: CaseLabel,
    pub actual: String,
}

pub fn run_chain_cases(labels: &[CaseLabel]) -> Vec<ChainRow> {
    labels
        .iter()
        .filter(|l| l.is_chain())
        .map(|l| {
            let s = scenario_for(&l.id).unwrap_or_else(|| panic!("no mutation for case {}", l.id));
            ChainRow {
                label: l.clone(),
                chain: s.run(),
                baseline: s.run_baseline(),
            }
        })
        .collect()
}

pub fn run_scope_queries(labels: &[CaseLabel]) -> Vec<QueryRow> {
    let bundle = Scenario::base().build();
    let chain = decode_chain(&bundle).expect("base chain decodes");
    let scope = grant_scope(chain.grant().body());
    labels
        .iter()
        .filter(|l| l.kind == "exact_node_query" || l.kind == "subtree_query")
        .map(|l| {
            let probe = asset_ref(&l.probe);
            let answer = if l.kind == "exact_node_query" {
                match exact_node_lookup(&scope, &probe) {
                    ExactNodeAnswer::InScope => "InScope",
                    ExactNodeAnswer::Excluded => "Excluded",
                    ExactNodeAnswer::OutOfScope => "OutOfScope",
                }
            } else {
                match subtree_lookup(&scope, &probe) {
                    SubtreeAnswer::WhollyAllowed => "WhollyAllowed",
                    SubtreeAnswer::PartiallyAllowed => "PartiallyAllowed",
                    SubtreeAnswer::NoneAllowed => "NoneAllowed",
                }
            };
            QueryRow {
                label: l.clone(),
                actual: answer.to_owned(),
            }
        })
        .collect()
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Totals {
    pub cases: usize,
    pub false_accept: usize,
    pub false_reject: usize,
    pub indeterminate: usize,
    pub indeterminate_on_accept_label: usize,
    pub class_mismatch: usize,
    pub exact_match: usize,
}

pub fn totals<'a>(rows: impl Iterator<Item = (&'a CaseLabel, &'a Decision)>) -> Totals {
    let mut t = Totals::default();
    for (label, d) in rows {
        let want = label.expected_class().expect("chain label class");
        let got = d.class();
        t.cases += 1;
        if got == DecisionClass::Accept && want != DecisionClass::Accept {
            t.false_accept += 1;
        }
        if got == DecisionClass::Reject && want == DecisionClass::Accept {
            t.false_reject += 1;
        }
        if got == DecisionClass::Indeterminate {
            t.indeterminate += 1;
            if want == DecisionClass::Accept {
                t.indeterminate_on_accept_label += 1;
            }
        }
        let rv = [DecisionClass::Reject, DecisionClass::Indeterminate];
        if rv.contains(&got) && rv.contains(&want) && got != want {
            t.class_mismatch += 1;
        }
        if label.matches(d) {
            t.exact_match += 1;
        }
    }
    t
}

pub struct Summary {
    pub chain_all: Totals,
    pub chain_reviewed: Totals,
    pub baseline_all: Totals,
    pub baseline_reviewed: Totals,
}

pub fn summarize(rows: &[ChainRow]) -> Summary {
    let rv = |r: &&ChainRow| r.label.is_reviewed();
    Summary {
        chain_all: totals(rows.iter().map(|r| (&r.label, &r.chain))),
        chain_reviewed: totals(rows.iter().filter(rv).map(|r| (&r.label, &r.chain))),
        baseline_all: totals(rows.iter().map(|r| (&r.label, &r.baseline))),
        baseline_reviewed: totals(rows.iter().filter(rv).map(|r| (&r.label, &r.baseline))),
    }
}

fn totals_json(t: &Totals) -> Value {
    json!({
        "cases": t.cases,
        "false_accept": t.false_accept,
        "false_reject": t.false_reject,
        "indeterminate": t.indeterminate,
        "indeterminate_on_accept_label": t.indeterminate_on_accept_label,
        "class_mismatch_reject_vs_indeterminate": t.class_mismatch,
        "exact_stage_reason_match": t.exact_match,
    })
}

pub fn render_json(rows: &[ChainRow], queries: &[QueryRow]) -> Value {
    let s = summarize(rows);
    json!({
        "chain_cases": rows.iter().map(|r| json!({
            "id": r.label.id,
            "label_status": r.label.label_status,
            "expected": r.label.expected_display(),
            "chain_aware": r.chain.to_string(),
            "chain_aware_exact_match": r.label.matches(&r.chain),
            "baseline": r.baseline.to_string(),
            "baseline_class_match": Some(r.baseline.class()) == r.label.expected_class(),
        })).collect::<Vec<_>>(),
        "scope_lookups": queries.iter().map(|q| json!({
            "id": q.label.id,
            "lookup": q.label.kind,
            "label_status": q.label.label_status,
            "probe": q.label.probe,
            "expected": q.label.expected,
            "actual": q.actual,
            "match": q.actual == q.label.expected,
        })).collect::<Vec<_>>(),
        "totals": {
            "chain_aware_all": totals_json(&s.chain_all),
            "chain_aware_reviewed_only": totals_json(&s.chain_reviewed),
            "baseline_all": totals_json(&s.baseline_all),
            "baseline_reviewed_only": totals_json(&s.baseline_reviewed),
        }
    })
}

fn totals_row(name: &str, t: &Totals, exact: bool) -> String {
    let exact = if exact {
        t.exact_match.to_string()
    } else {
        "n/a".to_owned()
    };
    format!(
        "| {name} | {} | {} | {} | {} ({} on Accept labels) | {} | {exact} |\n",
        t.cases,
        t.false_accept,
        t.false_reject,
        t.indeterminate,
        t.indeterminate_on_accept_label,
        t.class_mismatch
    )
}

pub fn render_markdown(rows: &[ChainRow], queries: &[QueryRow]) -> String {
    let s = summarize(rows);
    let mut out = String::new();
    out.push_str("# Case comparison (generated)\n\n");
    out.push_str("Generated by `cargo run --release --bin eval`. Labels come from ");
    out.push_str("`tests/cases/reviewed_cases.toml`; outputs are what the verifiers returned.\n\n");
    out.push_str("## Totals\n\n");
    out.push_str("| Verifier / subset | Cases | False accept | False reject | Indeterminate | R-vs-I mismatch | Exact stage+reason |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    out.push_str(&totals_row("chain-aware, all", &s.chain_all, true));
    out.push_str(&totals_row(
        "chain-aware, reviewed only",
        &s.chain_reviewed,
        true,
    ));
    out.push_str(&totals_row("signature-only, all", &s.baseline_all, false));
    out.push_str(&totals_row(
        "signature-only, reviewed only",
        &s.baseline_reviewed,
        false,
    ));
    out.push_str("\n## Chain cases\n\n");
    out.push_str("| ID | Label status | Expected | Chain-aware | Match | Signature-only |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.label.id,
            r.label.label_status,
            r.label.expected_display(),
            r.chain,
            if r.label.matches(&r.chain) {
                "yes"
            } else {
                "**NO**"
            },
            r.baseline
        ));
    }
    out.push_str("\n## Scope lookups (exact-node and subtree; lookups, not enforcement)\n\n");
    out.push_str("| ID | Lookup | Label status | Probe | Expected | Actual | Match |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for q in queries {
        out.push_str(&format!(
            "| {} | {} | {} | `{}` | {} | {} | {} |\n",
            q.label.id,
            q.label.kind,
            q.label.label_status,
            q.label.probe,
            q.label.expected,
            q.actual,
            if q.actual == q.label.expected {
                "yes"
            } else {
                "**NO**"
            }
        ));
    }
    out
}
