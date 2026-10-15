//! RQ5 session-slice cases (docs/experiment.md §11). Each case runs the scenario it
//! describes and returns the outcome string(s); expected values live only in
//! tests/cases/session_cases.toml. Multi-step outcomes are joined with " ; ".

use std::sync::Barrier;

use serde_json::{json, Value};

use crate::decision::Slot;
use crate::evidence::ObjStatus;
use crate::session::{
    encode_proof, Challenge, ChallengeStore, InMemoryChallengeStore, IssueOutcome, OsRandom,
    SessionDecision, SessionReason, SessionService, RESPONSE_TAG,
};

use super::cases::CaseLabel;
use super::fixture::{put, secret, PostOp, Scenario, Q_AUD};

pub const SESSION: &str = "sess-p-0001";
pub const ISSUE_AT: &str = "2026-10-15T10:00:00Z";
pub const REDEEM_AT: &str = "2026-10-15T10:01:00Z";

pub const SESSION_CASE_IDS: &[&str] = &[
    "SS01", "SS02", "SS03", "SS04", "SS05", "SS06", "SS07", "SS08", "SS09", "SS10", "SS11", "SS12",
    "SS13", "SS14", "SS15", "SS16", "SS17", "SS18", "SS19", "SS20", "SS21", "SS22", "SS23", "SS24",
    "SI01", "SI02", "SI03", "SI04",
];

fn issue_outcome(s: &Scenario, store: &dyn ChallengeStore, session: &str) -> IssueOutcome {
    let p = s.prepare();
    SessionService::new(p.verifier(), store, &OsRandom).issue(&p.bundle, session)
}

/// Issue at ISSUE_AT, then set the clock to REDEEM_AT (ε = 2) for redemption.
fn issue_base(s: &mut Scenario, store: &dyn ChallengeStore) -> Challenge {
    s.set_clock(ISSUE_AT, 2);
    let IssueOutcome::Issued(c) = issue_outcome(s, store, SESSION) else {
        panic!("base issuance must succeed");
    };
    let c = *c;
    s.set_clock(REDEEM_AT, 2);
    c
}

fn redeem(
    s: &Scenario,
    store: &dyn ChallengeStore,
    session: &str,
    proof: Option<&[u8]>,
) -> SessionDecision {
    let p = s.prepare();
    SessionService::new(p.verifier(), store, &OsRandom).redeem(&p.bundle, session, proof)
}

/// Tester response: K(signer) over signed_bytes(tag, challenge wire bytes).
fn proof_with(c: &Challenge, signed: &Challenge, signer: &str, tag: &str) -> Vec<u8> {
    encode_proof(
        &c.challenge_id,
        &secret(signer).sign(tag, &signed.wire_bytes()),
    )
}

fn proof(c: &Challenge, signer: &str) -> Vec<u8> {
    proof_with(c, c, signer, RESPONSE_TAG)
}

fn one(s: &Scenario, store: &dyn ChallengeStore, session: &str, p: Option<&[u8]>) -> String {
    redeem(s, store, session, p).to_string()
}

/// Run session case `id`; `None` for an unknown id.
pub fn run(id: &str) -> Option<String> {
    let store = InMemoryChallengeStore::default();
    let mut s = Scenario::base();
    if let Some(rest) = id.strip_prefix("SI") {
        return Some(run_issue(rest, s, &store));
    }
    let c = issue_base(&mut s, &store);
    let good = proof(&c, "tester-1");
    let out = match id {
        "SS01" => one(&s, &store, SESSION, Some(&good)),
        "SS02" => one(&s, &store, SESSION, None),
        "SS03" => one(&s, &store, SESSION, Some(&proof(&c, "tester-2"))),
        "SS04" => one(&s, &store, SESSION, Some(&proof(&c, "attacker"))),
        "SS05" => {
            let a = one(&s, &store, SESSION, Some(&good));
            let b = one(&s, &store, SESSION, Some(&good));
            format!("{a} ; {b}")
        }
        "SS06" => one(&s, &store, "sess-p-0002", Some(&good)),
        "SS07" => {
            let mut g2 = s.clone();
            put(g2.grant(), "engagement_id", json!("eng-acme-2026-10-15-02"));
            one(&g2, &store, SESSION, Some(&good))
        }
        "SS08" => {
            let mut cq = c.clone();
            cq.audience = Q_AUD.to_owned();
            cq.challenge_id = format!("{}q", c.challenge_id);
            store.insert(cq.clone()).expect("insert");
            one(&s, &store, SESSION, Some(&proof(&cq, "tester-1")))
        }
        "SS09" => {
            s.set_clock("2026-10-15T10:02:00Z", 0);
            one(&s, &store, SESSION, Some(&good))
        }
        "SS10" => {
            s.set_clock("2026-10-15T10:01:59Z", 2);
            one(&s, &store, SESSION, Some(&good))
        }
        "SS11" => {
            s.set_clock("2026-10-15T10:01:57Z", 2);
            one(&s, &store, SESSION, Some(&good))
        }
        "SS12" => {
            store.set_unavailable(true);
            one(&s, &store, SESSION, Some(&good))
        }
        "SS13" => {
            let mut fake = c.clone();
            fake.challenge_id = "0".repeat(32);
            one(&s, &store, SESSION, Some(&proof(&fake, "tester-1")))
        }
        "SS14" => {
            let mut altered: Value = s.grant().clone();
            put(
                &mut altered,
                "test_scope",
                json!({"classes": ["auth_testing"], "kind": "classes"}),
            );
            s.post
                .push(PostOp::ReplacePayloadKeepSig(Slot::Grant, altered));
            one(&s, &store, SESSION, Some(&good))
        }
        "SS15" => {
            s.status.unavailable = true;
            one(&s, &store, SESSION, Some(&good))
        }
        "SS16" => {
            s.status.unavailable = true;
            one(&s, &store, SESSION, Some(&proof(&c, "tester-2")))
        }
        "SS17" => {
            let mut other = c.clone();
            other.session_id = "sess-attacker".to_owned();
            one(
                &s,
                &store,
                SESSION,
                Some(&proof_with(&c, &other, "tester-1", RESPONSE_TAG)),
            )
        }
        "SS18" => one(
            &s,
            &store,
            SESSION,
            Some(&proof_with(&c, &c, "tester-1", "EngagementGrant")),
        ),
        "SS19" => {
            let mut v: Value = serde_json::from_slice(&good).expect("json");
            v["session_id"] = json!(SESSION);
            let bad = serde_json::to_vec(&v).expect("json");
            one(&s, &store, SESSION, Some(&bad))
        }
        "SS20" => {
            let a = one(&s, &store, SESSION, Some(&proof(&c, "tester-2")));
            let b = one(&s, &store, SESSION, Some(&good));
            format!("{a} ; {b}")
        }
        "SS21" => {
            s.status.unavailable = true;
            let a = one(&s, &store, SESSION, Some(&good));
            s.status.unavailable = false;
            let b = one(&s, &store, SESSION, Some(&good));
            format!("{a} ; {b}")
        }
        "SS22" => concurrent(&s, &store, &good, 8),
        "SS23" => {
            s.status.grant = Some(ObjStatus::Revoked);
            one(&s, &store, SESSION, Some(&good))
        }
        "SS24" => {
            s.clock.reading = None;
            one(&s, &store, SESSION, Some(&good))
        }
        _ => return None,
    };
    Some(out)
}

fn run_issue(rest: &str, mut s: Scenario, store: &InMemoryChallengeStore) -> String {
    s.set_clock(ISSUE_AT, 2);
    match rest {
        "01" => {}
        "02" => s.status.grant = Some(ObjStatus::Revoked),
        "03" => store.set_unavailable(true),
        "04" => put(s.grant(), "window.end", json!("2026-10-15T10:01:00Z")),
        _ => return format!("unknown issuance case SI{rest}"),
    }
    issue_outcome(&s, store, SESSION).to_string()
}

/// `n` threads redeem the same proof at once; tally the outcomes.
fn concurrent(s: &Scenario, store: &InMemoryChallengeStore, proof: &[u8], n: usize) -> String {
    let barrier = Barrier::new(n);
    let results: Vec<SessionDecision> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let scenario = s.clone();
                let barrier = &barrier;
                scope.spawn(move || {
                    let p = scenario.prepare();
                    let svc = SessionService::new(p.verifier(), store, &OsRandom);
                    barrier.wait();
                    svc.redeem(&p.bundle, SESSION, Some(proof))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect()
    });
    let accepts = results
        .iter()
        .filter(|d| matches!(d, SessionDecision::Accept(_)))
        .count();
    // A loser counts only when it is specifically a SessionReject carrying
    // ChallengeAlreadyConsumed, never an Indeterminate or any other class.
    let consumed = results
        .iter()
        .filter(|d| {
            matches!(
                d,
                SessionDecision::Reject(f) if f.reason == SessionReason::ChallengeAlreadyConsumed
            )
        })
        .count();
    format!(
        "accepts={accepts} already_consumed={consumed} other={}",
        n - accepts - consumed
    )
}

pub const SESSION_CASES_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/cases/session_cases.toml"
);

pub struct SessionRow {
    pub label: CaseLabel,
    pub actual: String,
}

pub fn run_all(labels: &[CaseLabel]) -> Vec<SessionRow> {
    labels
        .iter()
        .map(|l| SessionRow {
            label: l.clone(),
            actual: run(&l.id).unwrap_or_else(|| format!("no runner for {}", l.id)),
        })
        .collect()
}

pub fn render_markdown(rows: &[SessionRow]) -> String {
    let matched = rows.iter().filter(|r| r.actual == r.label.expected).count();
    let mut out = String::from("# RQ5 session-slice cases (generated)\n\n");
    out.push_str("Generated by `cargo run --release --bin eval`. Labels come from ");
    out.push_str("`tests/cases/session_cases.toml` (all reviewed). Separate from the chain and ");
    out.push_str("lookup results in `case_comparison.md`.\n\n");
    out.push_str(&format!("Matched {matched}/{} labels.\n\n", rows.len()));
    out.push_str("| ID | Kind | Label status | Expected | Actual | Match |\n| --- | --- | --- | --- | --- | --- |\n");
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | {} | `{}` | `{}` | {} |\n",
            r.label.id,
            r.label.kind,
            r.label.label_status,
            r.label.expected,
            r.actual,
            if r.actual == r.label.expected {
                "yes"
            } else {
                "**NO**"
            }
        ));
    }
    out
}

pub fn render_json(rows: &[SessionRow]) -> Value {
    json!({
        "matched": rows.iter().filter(|r| r.actual == r.label.expected).count(),
        "total": rows.len(),
        "cases": rows.iter().map(|r| json!({
            "id": r.label.id,
            "kind": r.label.kind,
            "label_status": r.label.label_status,
            "expected": r.label.expected,
            "actual": r.actual,
            "match": r.actual == r.label.expected,
        })).collect::<Vec<_>>(),
    })
}
