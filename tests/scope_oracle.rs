//! Independent set oracle for spec §4 (SO1, SO2 in docs/experiment.md §6).
//!
//! The oracle enumerates a finite universe of concrete nodes and decides containment with
//! its own string-prefix code. It never calls `AssetRef::within` or `scope_within`.

use std::collections::BTreeSet;

use aisig_proto::asset::{is_admissible, scope_within, Scope};
use aisig_proto::experiment::fixture::asset_ref;
use aisig_proto::model::AssetRef;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

const DEFAULT_SEED: u64 = 0x5EED_2026_1015;

fn seed() -> u64 {
    std::env::var("AISIG_PROPTEST_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED)
}

fn config() -> Config {
    let seed = seed();
    eprintln!("scope_oracle proptest rng_seed = {seed}");
    Config {
        cases: 512,
        rng_seed: RngSeed::Fixed(seed),
        failure_persistence: None,
        ..Config::default()
    }
}

/// Oracle node keys: `w:/a/b` (one fixed web origin) and `d:c1/d1/s1`.
fn universe() -> Vec<String> {
    let mut out = vec!["w:/".to_owned()];
    let segs = ["a", "b", "c"];
    let mut frontier = vec![String::new()];
    for _ in 0..3 {
        let mut next = Vec::new();
        for p in &frontier {
            for s in segs {
                let q = format!("{p}/{s}");
                out.push(format!("w:{q}"));
                next.push(q);
            }
        }
        frontier = next;
    }
    for c in ["c1", "c2"] {
        out.push(format!("d:{c}"));
        for d in ["d1", "d2"] {
            out.push(format!("d:{c}/{d}"));
            for s in ["s1", "s2"] {
                out.push(format!("d:{c}/{d}/{s}"));
            }
        }
    }
    out
}

/// Oracle containment of a node in the subtree named by `asset`, by string prefix only.
fn oracle_contains(asset: &str, node: &str) -> bool {
    if asset == "w:/" {
        return node.starts_with("w:");
    }
    node == asset || node.starts_with(&format!("{asset}/"))
}

fn to_asset(key: &str) -> AssetRef {
    if let Some(p) = key.strip_prefix("w:") {
        asset_ref(&format!("web:https://app.acme.test:443{p}"))
    } else {
        asset_ref(&format!("db:{}", key.strip_prefix("d:").unwrap()))
    }
}

struct OracleScope<'a> {
    inc: &'a [String],
    exc: &'a [String],
}

impl OracleScope<'_> {
    fn allowed(&self, u: &[String]) -> BTreeSet<String> {
        u.iter()
            .filter(|n| self.inc.iter().any(|i| oracle_contains(i, n)))
            .filter(|n| !self.exc.iter().any(|e| oracle_contains(e, n)))
            .cloned()
            .collect()
    }

    /// No included entry has every one of its nodes removed by the exclusions.
    fn admissible(&self, u: &[String]) -> bool {
        self.inc.iter().all(|i| {
            u.iter()
                .filter(|n| oracle_contains(i, n))
                .any(|n| !self.exc.iter().any(|e| oracle_contains(e, n)))
        })
    }
}

fn keys(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// SO1: the named counterexample from spec §4.3.
#[test]
fn so1_named_counterexample() {
    let u = universe();
    let (p_inc, p_exc) = (keys(&["w:/a"]), keys(&["w:/a/b"]));
    let (c_inc, c_exc) = (keys(&["w:/a/c", "w:/a/b"]), keys(&["w:/a/b"]));
    let parent_o = OracleScope {
        inc: &p_inc,
        exc: &p_exc,
    };
    let child_o = OracleScope {
        inc: &c_inc,
        exc: &c_exc,
    };
    // Oracle: effective permission is within the parent, but the child is inadmissible.
    assert!(child_o.allowed(&u).is_subset(&parent_o.allowed(&u)));
    assert!(!child_o.admissible(&u));

    let conv = |v: &[String]| v.iter().map(|k| to_asset(k)).collect::<Vec<_>>();
    let (pi, pe, ci, ce) = (conv(&p_inc), conv(&p_exc), conv(&c_inc), conv(&c_exc));
    let parent = Scope {
        included: &pi,
        excluded: &pe,
    };
    let child = Scope {
        included: &ci,
        excluded: &ce,
    };
    assert!(
        !is_admissible(&child),
        "implementation must flag the child inadmissible"
    );
    assert!(
        scope_within(&child, &parent).is_err(),
        "raw ScopeWithin is false here, as documented"
    );
}

fn scope_strategy(n: usize) -> impl Strategy<Value = (Vec<usize>, Vec<usize>)> {
    (
        prop::collection::vec(0..n, 1..4),
        prop::collection::vec(0..n, 0..4),
    )
}

proptest! {
    #![proptest_config(config())]

    /// SO2: admissibility and ScopeWithin agree with the enumeration oracle.
    #[test]
    fn so2_scope_within_matches_oracle(
        (ci, ce) in scope_strategy(54),
        (pi, pe) in scope_strategy(54),
    ) {
        let u = universe();
        prop_assert_eq!(u.len(), 54);
        let pick = |ix: &[usize]| ix.iter().map(|i| u[*i].clone()).collect::<Vec<_>>();
        let (ci, ce, pi, pe) = (pick(&ci), pick(&ce), pick(&pi), pick(&pe));
        let child_o = OracleScope { inc: &ci, exc: &ce };
        let parent_o = OracleScope { inc: &pi, exc: &pe };
        let oracle_subset = child_o.allowed(&u).is_subset(&parent_o.allowed(&u));
        let oracle_admissible = child_o.admissible(&u);

        let conv = |v: &[String]| v.iter().map(|k| to_asset(k)).collect::<Vec<_>>();
        let (aci, ace, api, ape) = (conv(&ci), conv(&ce), conv(&pi), conv(&pe));
        let child = Scope { included: &aci, excluded: &ace };
        let parent = Scope { included: &api, excluded: &ape };
        let impl_within = scope_within(&child, &parent).is_ok();

        prop_assert_eq!(is_admissible(&child), oracle_admissible);
        if impl_within {
            prop_assert!(oracle_subset, "ScopeWithin accepted but oracle subset is false");
        }
        if oracle_admissible {
            prop_assert_eq!(impl_within, oracle_subset);
        }
    }
}
