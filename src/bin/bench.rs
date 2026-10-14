//! CPU micro-benchmark (docs/experiment.md §9). Times each series per call with
//! `Instant`, over N iterations × R runs, and reports nearest-rank p50/p95/p99 in ns.
//!
//! Usage: bench [--n N] [--r R] [--warmup W] [--out PREFIX]
//! Environment metadata is read from AISIG_ENV_* variables (set by scripts/bench.sh).

use std::hint::black_box;
use std::time::Instant;

use aisig_proto::crypto;
use aisig_proto::decision::Decision;
use aisig_proto::evidence::{ObjStatus, StatusSource};
use aisig_proto::experiment::fixture::{Scenario, ACME, P_AUD};
use aisig_proto::policy::{check_linkage, check_policy};
use aisig_proto::verifier::decode_chain;
use serde_json::{json, Value};

struct Args {
    n: usize,
    r: usize,
    warmup: usize,
    out: Option<String>,
}

fn parse_args() -> Args {
    let mut a = Args {
        n: 10_000,
        r: 10,
        warmup: 1_000,
        out: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let val = it
            .next()
            .unwrap_or_else(|| panic!("missing value for {flag}"));
        match flag.as_str() {
            "--n" => a.n = val.parse().expect("--n integer"),
            "--r" => a.r = val.parse().expect("--r integer"),
            "--warmup" => a.warmup = val.parse().expect("--warmup integer"),
            "--out" => a.out = Some(val),
            _ => panic!("unknown flag {flag}"),
        }
    }
    a
}

/// Nearest-rank percentile of sorted samples.
fn pct(sorted: &[u64], p: f64) -> u64 {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[(v.len() - 1) / 2]
}

#[derive(Clone)]
struct RunStats {
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
}

fn measure(args: &Args, mut f: impl FnMut() -> bool) -> Vec<RunStats> {
    let mut runs = Vec::with_capacity(args.r);
    for _ in 0..args.r {
        for _ in 0..args.warmup {
            assert!(black_box(f()));
        }
        let mut samples = Vec::with_capacity(args.n);
        for _ in 0..args.n {
            let t0 = Instant::now();
            let ok = black_box(f());
            let dt = t0.elapsed().as_nanos() as u64;
            assert!(ok, "benchmarked operation returned an unexpected result");
            samples.push(dt);
        }
        samples.sort_unstable();
        runs.push(RunStats {
            p50: pct(&samples, 50.0),
            p95: pct(&samples, 95.0),
            p99: pct(&samples, 99.0),
            max: *samples.last().unwrap(),
        });
    }
    runs
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| "unrecorded".to_owned())
}

fn main() {
    let args = parse_args();
    let scenario = Scenario::base();
    let prepared = scenario.prepare();
    let bundle = &prepared.bundle;
    let verifier = prepared.verifier();
    assert_eq!(
        verifier.verify(bundle),
        Decision::Accept,
        "base fixture must verify"
    );
    let chain = decode_chain(bundle).expect("decodes");
    let view = chain.view();
    let root_key = *scenario.registry.records[ACME].root_key.bytes();
    let (a, d, g) = (&chain.admin, &chain.issuer, &chain.grant);
    let status: &dyn StatusSource = &prepared.status;
    let keys = chain.status_keys();

    let series: Vec<(&str, &str, Vec<RunStats>)> = vec![
        (
            "timer_overhead",
            "empty timed call",
            measure(&args, || true),
        ),
        (
            "signature_x3",
            "Ed25519 verify_strict of C_A, D_U, G over pre-decoded payloads",
            measure(&args, || {
                crypto::verify(&root_key, "AdminDelegation", &a.payload, &a.sig)
                    && crypto::verify(
                        a.body.subject_key.bytes(),
                        "IssuerDelegation",
                        &d.payload,
                        &d.sig,
                    )
                    && crypto::verify(
                        d.body.subject_key.bytes(),
                        "EngagementGrant",
                        &g.payload,
                        &g.sig,
                    )
            }),
        ),
        (
            "typed_policy",
            "linkage (stage L) + policy (stage P) on pre-decoded objects",
            measure(&args, || {
                check_linkage(&view, P_AUD).is_ok() && check_policy(&view).is_ok()
            }),
        ),
        (
            "status_key_x3",
            "exact-object status keys of C_A, D_U, G: SHA-256 of signed bytes + key fields",
            measure(&args, || {
                black_box(chain.status_keys())
                    .iter()
                    .all(|(_, k)| k.version >= 1)
            }),
        ),
        (
            "status_lookup_x3",
            "simulated status lookup of C_A, D_U, G with precomputed keys (in-memory HashMap)",
            measure(&args, || {
                keys.iter()
                    .all(|(_, k)| status.status(k) == Ok(ObjStatus::Active))
            }),
        ),
        (
            "full_chain_verify",
            "decode + anchor + signatures + linkage + policy + binding + time + status",
            measure(&args, || verifier.verify(bundle) == Decision::Accept),
        ),
    ];

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let meta = json!({
        "timestamp_utc": env("AISIG_ENV_TIMESTAMP"),
        "git": env("AISIG_ENV_GIT"),
        "rustc": env("AISIG_ENV_RUSTC"),
        "cargo": env("AISIG_ENV_CARGO"),
        "cpu_model": env("AISIG_ENV_CPU"),
        "logical_cores": env("AISIG_ENV_CORES"),
        "kernel": env("AISIG_ENV_KERNEL"),
        "cpu_governor": env("AISIG_ENV_GOVERNOR"),
        "profile": profile,
        "iterations_per_run": args.n,
        "runs": args.r,
        "warmup_per_run": args.warmup,
        "random_seed": "none (deterministic fixture; no randomness in benchmark)",
        "unit": "nanoseconds per call, nearest-rank percentiles",
        "single_threaded": true,
    });

    let mut md = String::new();
    md.push_str("# Benchmark results (generated)\n\n");
    md.push_str("Measured by `scripts/bench.sh`. Per-call wall time via `std::time::Instant`; ");
    md.push_str("each series is N timed calls per run after warm-up, repeated R times. ");
    md.push_str("Values in nanoseconds. Read small series against `timer_overhead`.\n\n");
    md.push_str("## Environment\n\n| Key | Value |\n| --- | --- |\n");
    for (k, v) in meta.as_object().unwrap() {
        let v = v
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| v.to_string());
        md.push_str(&format!("| {k} | {v} |\n"));
    }
    md.push_str("\n## Median across runs\n\n| Series | What | p50 | p95 | p99 | p99 range across runs |\n| --- | --- | --- | --- | --- | --- |\n");

    let mut series_json: Vec<Value> = Vec::new();
    for (name, what, runs) in &series {
        let col = |f: fn(&RunStats) -> u64| runs.iter().map(f).collect::<Vec<_>>();
        let (p50s, p95s, p99s) = (col(|r| r.p50), col(|r| r.p95), col(|r| r.p99));
        let (lo, hi) = (*p99s.iter().min().unwrap(), *p99s.iter().max().unwrap());
        md.push_str(&format!(
            "| {name} | {what} | {} | {} | {} | {lo}–{hi} |\n",
            median(p50s.clone()),
            median(p95s.clone()),
            median(p99s.clone())
        ));
        println!(
            "{name:18} p50={:>8} p95={:>8} p99={:>8} ns (median of {} runs; p99 range {lo}-{hi})",
            median(p50s.clone()),
            median(p95s.clone()),
            median(p99s.clone()),
            runs.len()
        );
        series_json.push(json!({
            "series": name,
            "what": what,
            "median_p50_ns": median(p50s),
            "median_p95_ns": median(p95s),
            "median_p99_ns": median(p99s),
            "runs": runs.iter().map(|r| json!({"p50": r.p50, "p95": r.p95, "p99": r.p99, "max": r.max})).collect::<Vec<_>>(),
        }));
    }
    md.push_str("\n## Per-run values\n\n| Series | Run | p50 | p95 | p99 | max |\n| --- | --- | --- | --- | --- | --- |\n");
    for (name, _, runs) in &series {
        for (i, r) in runs.iter().enumerate() {
            md.push_str(&format!(
                "| {name} | {} | {} | {} | {} | {} |\n",
                i + 1,
                r.p50,
                r.p95,
                r.p99,
                r.max
            ));
        }
    }

    if let Some(prefix) = &args.out {
        let doc = json!({"meta": meta, "series": series_json});
        std::fs::write(
            format!("{prefix}.json"),
            serde_json::to_string_pretty(&doc).unwrap() + "\n",
        )
        .expect("write json");
        std::fs::write(format!("{prefix}.md"), md).expect("write md");
        println!("wrote {prefix}.json and {prefix}.md");
    }
}
