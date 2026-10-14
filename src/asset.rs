//! Asset containment and scope-set semantics (spec §2.2, §4).

use crate::model::{AssetRef, DatabaseSchema};

impl AssetRef {
    /// within(self, other): every concrete asset denoted by `self` is denoted by `other`.
    pub fn within(&self, other: &AssetRef) -> bool {
        match (self, other) {
            (AssetRef::Web(a), AssetRef::Web(b)) => {
                a.scheme == b.scheme
                    && a.host == b.host
                    && a.port == b.port
                    && a.segments.len() >= b.segments.len()
                    && a.segments[..b.segments.len()] == b.segments[..]
            }
            (AssetRef::Db(a), AssetRef::Db(b)) => db_within(a, b),
            _ => false,
        }
    }
}

fn db_within(a: &DatabaseSchema, b: &DatabaseSchema) -> bool {
    if a.cluster != b.cluster {
        return false;
    }
    match (&b.database, &b.schema) {
        (None, _) => true,
        (Some(db), None) => a.database.as_ref() == Some(db),
        (Some(db), Some(s)) => a.database.as_ref() == Some(db) && a.schema.as_ref() == Some(s),
    }
}

/// An included/excluded pair: C_A.bounds, D_U.envelope, or G's targets/exclusions.
#[derive(Clone, Copy, Debug)]
pub struct Scope<'a> {
    pub included: &'a [AssetRef],
    pub excluded: &'a [AssetRef],
}

/// The first included entry fully removed by the scope's own exclusions, if any (spec §4.2).
pub fn first_inadmissible<'a>(s: &Scope<'a>) -> Option<&'a AssetRef> {
    s.included
        .iter()
        .find(|i| s.excluded.iter().any(|e| i.within(e)))
}

pub fn is_admissible(s: &Scope<'_>) -> bool {
    first_inadmissible(s).is_none()
}

/// Which ScopeWithin condition failed, for the first failing child target (spec §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeViolation<'a> {
    /// Condition 1: no parent included entry contains the target.
    OutsideParent(&'a AssetRef),
    /// Condition 2: the target lies entirely inside a parent exclusion.
    InParentExclusion(&'a AssetRef),
    /// Condition 3: a parent exclusion inside the target is not excluded by the child.
    MissingParentExclusion {
        target: &'a AssetRef,
        exclusion: &'a AssetRef,
    },
}

/// ScopeWithin(child, parent). Equals Allowed(child) ⊆ Allowed(parent) when the child is
/// admissible (spec §4.3); callers must check admissibility first.
pub fn scope_within<'a>(child: &Scope<'a>, parent: &Scope<'a>) -> Result<(), ScopeViolation<'a>> {
    for g in child.included {
        if !parent.included.iter().any(|p| g.within(p)) {
            return Err(ScopeViolation::OutsideParent(g));
        }
        if parent.excluded.iter().any(|e| g.within(e)) {
            return Err(ScopeViolation::InParentExclusion(g));
        }
        for e in parent.excluded.iter().filter(|e| e.within(g)) {
            if !child.excluded.iter().any(|c| e.within(c)) {
                return Err(ScopeViolation::MissingParentExclusion {
                    target: g,
                    exclusion: e,
                });
            }
        }
    }
    Ok(())
}

/// Exact-node lookup result (spec §4.4). Describes one node only, never its subtree.
/// Not authorization or enforcement (RQ6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactNodeAnswer {
    InScope,
    Excluded,
    OutOfScope,
}

/// Classify the single node at the top of `node` against Allowed(scope) (spec §4.4).
///
/// The answer covers that node only: `/app` can be `InScope` while `/app/admin` is
/// `Excluded`. Use [`subtree_lookup`] for questions about a whole subtree.
pub fn exact_node_lookup(scope: &Scope<'_>, node: &AssetRef) -> ExactNodeAnswer {
    if !scope.included.iter().any(|i| node.within(i)) {
        ExactNodeAnswer::OutOfScope
    } else if scope.excluded.iter().any(|e| node.within(e)) {
        ExactNodeAnswer::Excluded
    } else {
        ExactNodeAnswer::InScope
    }
}

/// Subtree lookup result (spec §4.4): how much of a probe subtree lies in Allowed(scope).
/// Not authorization or enforcement (RQ6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubtreeAnswer {
    WhollyAllowed,
    PartiallyAllowed,
    NoneAllowed,
}

/// Classify the whole subtree denoted by `probe` using effective-set semantics (spec §4.4).
pub fn subtree_lookup(scope: &Scope<'_>, probe: &AssetRef) -> SubtreeAnswer {
    let single = std::slice::from_ref(probe);
    let probe_scope = Scope {
        included: single,
        excluded: &[],
    };
    // A scope with no exclusions is admissible, so ScopeWithin is exact here (spec §4.3).
    if scope_within(&probe_scope, scope).is_ok() {
        return SubtreeAnswer::WhollyAllowed;
    }
    // Laminar sets: N(i) ∩ N(probe) is the subtree of the deeper node, and it is entirely
    // removed iff that node lies within some exclusion.
    let any_allowed = scope.included.iter().any(|i| {
        let deeper = if probe.within(i) {
            probe
        } else if i.within(probe) {
            i
        } else {
            return false;
        };
        !scope.excluded.iter().any(|e| deeper.within(e))
    });
    if any_allowed {
        SubtreeAnswer::PartiallyAllowed
    } else {
        SubtreeAnswer::NoneAllowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Scheme, WebOriginPath};

    fn web(path: &str) -> AssetRef {
        let segments = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        AssetRef::Web(WebOriginPath {
            scheme: Scheme::Https,
            host: "app.acme.test".into(),
            port: 443,
            segments,
        })
    }

    fn db(c: &str, d: Option<&str>, s: Option<&str>) -> AssetRef {
        AssetRef::Db(DatabaseSchema {
            cluster: c.into(),
            database: d.map(String::from),
            schema: s.map(String::from),
        })
    }

    #[test]
    fn segment_prefix_not_string_prefix() {
        assert!(web("/app/x").within(&web("/app")));
        assert!(web("/app").within(&web("/app")));
        assert!(!web("/application").within(&web("/app")));
        assert!(web("/anything").within(&web("/")));
        assert!(!web("/app").within(&db("c", None, None)));
    }

    #[test]
    fn db_hierarchy() {
        let billing = db("cluster1", Some("main"), Some("billing"));
        assert!(billing.within(&db("cluster1", None, None)));
        assert!(billing.within(&db("cluster1", Some("main"), None)));
        assert!(!db("cluster1", Some("main"), None).within(&billing));
        assert!(!billing.within(&db("cluster2", None, None)));
    }

    #[test]
    fn spec_counterexample_is_inadmissible() {
        let p_inc = [web("/app")];
        let p_exc = [web("/app/private")];
        let c_inc = [web("/app/reports"), web("/app/private")];
        let c_exc = [web("/app/private")];
        let parent = Scope {
            included: &p_inc,
            excluded: &p_exc,
        };
        let child = Scope {
            included: &c_inc,
            excluded: &c_exc,
        };
        assert_eq!(first_inadmissible(&child), Some(&web("/app/private")));
        assert!(scope_within(&child, &parent).is_err());
    }

    #[test]
    fn exact_node_vs_subtree_for_app_and_admin() {
        // Base-grant shape: target /app, exclusions /app/admin and /app/private.
        let inc = [web("/app")];
        let exc = [web("/app/admin"), web("/app/private")];
        let g = Scope {
            included: &inc,
            excluded: &exc,
        };
        // The node /app is in scope, but its subtree is only partially allowed.
        assert_eq!(
            exact_node_lookup(&g, &web("/app")),
            ExactNodeAnswer::InScope
        );
        assert_eq!(
            subtree_lookup(&g, &web("/app")),
            SubtreeAnswer::PartiallyAllowed
        );
        // /app/admin: excluded as a node and as a whole subtree.
        assert_eq!(
            exact_node_lookup(&g, &web("/app/admin")),
            ExactNodeAnswer::Excluded
        );
        assert_eq!(
            subtree_lookup(&g, &web("/app/admin")),
            SubtreeAnswer::NoneAllowed
        );
        assert_eq!(
            subtree_lookup(&g, &web("/app/admin/users/7")),
            SubtreeAnswer::NoneAllowed
        );
        // A subtree with no excluded descendants is wholly allowed.
        assert_eq!(
            subtree_lookup(&g, &web("/app/reports")),
            SubtreeAnswer::WhollyAllowed
        );
        // Outside every target.
        assert_eq!(
            exact_node_lookup(&g, &web("/other")),
            ExactNodeAnswer::OutOfScope
        );
        assert_eq!(
            subtree_lookup(&g, &web("/other")),
            SubtreeAnswer::NoneAllowed
        );
        // A probe wider than the target contains allowed nodes and others.
        assert_eq!(
            exact_node_lookup(&g, &web("/")),
            ExactNodeAnswer::OutOfScope
        );
        assert_eq!(
            subtree_lookup(&g, &web("/")),
            SubtreeAnswer::PartiallyAllowed
        );
    }
}
