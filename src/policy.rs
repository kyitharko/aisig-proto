//! Linkage and policy predicates (spec §5, stages L and P).
//!
//! Pure functions over decoded payloads. No cryptography and no evidence lookups:
//! key ids were computed at decode time, and signatures are checked elsewhere.

use crate::asset::{first_inadmissible, scope_within, Scope, ScopeViolation};
use crate::decision::{Aspect, Obj, Reason};
use crate::model::{
    max_rps, AdminDelegation, AdminRight, Constraint, EngagementGrant, IssuerDelegation, TestClass,
    TestScope, KNOWN_CONSTRAINTS,
};

/// Borrowed view of the three chain objects.
#[derive(Clone, Copy, Debug)]
pub struct ChainView<'a> {
    pub admin: &'a AdminDelegation,
    pub issuer: &'a IssuerDelegation,
    pub grant: &'a EngagementGrant,
}

/// Stage L (spec §5.1).
pub fn check_linkage(c: &ChainView<'_>, audience: &str) -> Result<(), Reason> {
    let (a, d, g) = (c.admin, c.issuer, c.grant);
    if a.org_id != d.org_id || d.org_id != g.org_id {
        return Err(Reason::TenantMismatch);
    }
    for (obj, aud) in [
        (Obj::Admin, &a.audience),
        (Obj::Issuer, &d.audience),
        (Obj::Grant, &g.audience),
    ] {
        if aud != audience {
            return Err(Reason::WrongAudience(obj));
        }
    }
    if d.issuer_key_id != a.subject_key.key_id() {
        return Err(Reason::IssuerKeyMismatch(Obj::Issuer));
    }
    if d.parent.id != a.id {
        return Err(Reason::ParentMismatch(Obj::Issuer));
    }
    if d.parent.version != a.version {
        return Err(Reason::ParentVersionMismatch(Obj::Issuer));
    }
    if g.issuer_key_id != d.subject_key.key_id() {
        return Err(Reason::IssuerKeyMismatch(Obj::Grant));
    }
    if g.parent.id != d.id {
        return Err(Reason::ParentMismatch(Obj::Grant));
    }
    if g.parent.version != d.version {
        return Err(Reason::ParentVersionMismatch(Obj::Grant));
    }
    Ok(())
}

/// Stage P (spec §5.2): critical constraints, admissibility, CanDelegate, MayIssue.
pub fn check_policy(c: &ChainView<'_>) -> Result<(), Reason> {
    check_critical_constraints(c)?;
    check_admissibility(c)?;
    can_delegate(c.admin, c.issuer)?;
    may_issue(c.issuer, c.grant)
}

fn has_unknown_critical(cs: &[Constraint]) -> bool {
    cs.iter()
        .any(|x| x.critical && !KNOWN_CONSTRAINTS.contains(&x.name.as_str()))
}

fn check_critical_constraints(c: &ChainView<'_>) -> Result<(), Reason> {
    for (obj, cs) in [
        (Obj::Admin, &c.admin.constraints),
        (Obj::Issuer, &c.issuer.constraints),
        (Obj::Grant, &c.grant.constraints),
    ] {
        if has_unknown_critical(cs) {
            return Err(Reason::UnsupportedCriticalConstraint(obj));
        }
    }
    Ok(())
}

pub fn admin_scope(a: &AdminDelegation) -> Scope<'_> {
    Scope {
        included: &a.bounds.included,
        excluded: &a.bounds.excluded,
    }
}

pub fn issuer_scope(d: &IssuerDelegation) -> Scope<'_> {
    Scope {
        included: &d.envelope.included,
        excluded: &d.envelope.mandatory_exclusions,
    }
}

pub fn grant_scope(g: &EngagementGrant) -> Scope<'_> {
    Scope {
        included: &g.targets,
        excluded: &g.exclusions,
    }
}

fn check_admissibility(c: &ChainView<'_>) -> Result<(), Reason> {
    for (obj, scope) in [
        (Obj::Admin, admin_scope(c.admin)),
        (Obj::Issuer, issuer_scope(c.issuer)),
        (Obj::Grant, grant_scope(c.grant)),
    ] {
        if first_inadmissible(&scope).is_some() {
            return Err(Reason::InadmissibleScope(obj));
        }
    }
    Ok(())
}

fn ceiling_within(child: &Option<Vec<TestClass>>, parent: &Option<Vec<TestClass>>) -> bool {
    match (parent, child) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(ch)) => ch.iter().all(|x| p.contains(x)),
    }
}

fn limit_within(child: Option<u64>, parent: Option<u64>) -> bool {
    match (parent, child) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(ch)) => ch <= p,
    }
}

/// CanDelegate(C_A, D_U) (spec §5.2 step 3).
pub fn can_delegate(a: &AdminDelegation, d: &IssuerDelegation) -> Result<(), Reason> {
    if !a.rights.contains(&AdminRight::MayDelegateGrantIssuer) {
        return Err(Reason::MissingDelegationRight);
    }
    if scope_within(&issuer_scope(d), &admin_scope(a)).is_err() {
        return Err(Reason::DelegationAmplifies(Aspect::Assets));
    }
    if !ceiling_within(&d.envelope.test_ceiling, &a.bounds.test_ceiling) {
        return Err(Reason::DelegationAmplifies(Aspect::TestCeiling));
    }
    if !limit_within(
        d.envelope.max_engagement_seconds,
        a.bounds.max_engagement_seconds,
    ) {
        return Err(Reason::DelegationAmplifies(Aspect::MaxDuration));
    }
    if !a.validity.contains_window(&d.validity) {
        return Err(Reason::DelegationAmplifies(Aspect::Validity));
    }
    if !limit_within(max_rps(&d.constraints), max_rps(&a.constraints)) {
        return Err(Reason::DelegationAmplifies(Aspect::Constraints));
    }
    Ok(())
}

/// MayIssue(D_U, G) (spec §5.2 step 4).
pub fn may_issue(d: &IssuerDelegation, g: &EngagementGrant) -> Result<(), Reason> {
    match scope_within(&grant_scope(g), &issuer_scope(d)) {
        Ok(()) => {}
        Err(ScopeViolation::OutsideParent(_)) => return Err(Reason::TargetOutsideEnvelope),
        Err(ScopeViolation::InParentExclusion(_)) => {
            return Err(Reason::TargetInMandatoryExclusion)
        }
        Err(ScopeViolation::MissingParentExclusion { .. }) => {
            return Err(Reason::MissingMandatoryExclusion)
        }
    }
    if let Some(ceiling) = &d.envelope.test_ceiling {
        let ok = match &g.test_scope {
            TestScope::Unrestricted => false,
            TestScope::Classes { classes } => classes.iter().all(|x| ceiling.contains(x)),
        };
        if !ok {
            return Err(Reason::TestScopeAmplifies);
        }
    }
    if !d.validity.contains_window(&g.window) {
        return Err(Reason::WindowExceedsParent);
    }
    if let Some(max) = d.envelope.max_engagement_seconds {
        if g.window.duration_seconds() > max as i64 {
            return Err(Reason::DurationExceedsMax);
        }
    }
    if !limit_within(max_rps(&g.constraints), max_rps(&d.constraints)) {
        return Err(Reason::ConstraintAmplifies);
    }
    Ok(())
}
