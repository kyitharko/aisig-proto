//! Decision, stage and reason taxonomy (spec §7, §3, §5, §6).

use std::fmt;

/// Verification stages in their fixed evaluation order (spec §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stage {
    Format,
    Anchor,
    Signature,
    Linkage,
    Policy,
    Binding,
    Time,
    Status,
}

impl Stage {
    pub fn letter(self) -> &'static str {
        match self {
            Stage::Format => "F",
            Stage::Anchor => "N",
            Stage::Signature => "S",
            Stage::Linkage => "L",
            Stage::Policy => "P",
            Stage::Binding => "B",
            Stage::Time => "T",
            Stage::Status => "X",
        }
    }
}

/// A signed object or registry record a reason refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Obj {
    Root,
    Admin,
    Issuer,
    Grant,
}

impl fmt::Display for Obj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Obj::Root => "root",
            Obj::Admin => "C_A",
            Obj::Issuer => "D_U",
            Obj::Grant => "G",
        })
    }
}

/// A bundle slot (spec §2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Slot {
    Root,
    Admin,
    Issuer,
    Grant,
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Slot::Root => "root",
            Slot::Admin => "admin",
            Slot::Issuer => "issuer",
            Slot::Grant => "grant",
        })
    }
}

/// Which bound a delegation amplified (spec §5.2 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Aspect {
    Assets,
    TestCeiling,
    MaxDuration,
    Validity,
    Constraints,
}

impl fmt::Display for Aspect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Aspect::Assets => "assets",
            Aspect::TestCeiling => "test_ceiling",
            Aspect::MaxDuration => "max_duration",
            Aspect::Validity => "validity",
            Aspect::Constraints => "constraints",
        })
    }
}

/// Every reason the verifier can report. Display output matches the case tables.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    // F — format / decoding
    MissingRequiredObject(Slot),
    WrongObjectType(Slot),
    MalformedEnvelope,
    UnsupportedAlgorithm,
    DuplicateField,
    NonCanonicalEncoding,
    MalformedField,
    UnsupportedVersion,
    UnknownField,
    MissingRequiredField,
    UnknownEnumValue,
    MalformedTime,
    NonCanonicalTime,
    MalformedWindow,
    MalformedKey,
    MalformedAsset,
    NonCanonicalAsset,
    UnsupportedAssetSyntax,
    DuplicateConstraintName,
    // N — anchor
    RegistryUnavailable,
    UnpinnedOrganization,
    RootOrgMismatch,
    RootAlgorithmMismatch,
    RootKeyNotPinned,
    RootUsageMismatch,
    RootNotActive,
    // S — signatures
    InvalidSignature(Obj),
    // L — linkage
    TenantMismatch,
    WrongAudience(Obj),
    IssuerKeyMismatch(Obj),
    ParentMismatch(Obj),
    ParentVersionMismatch(Obj),
    // P — policy
    UnsupportedCriticalConstraint(Obj),
    InadmissibleScope(Obj),
    MissingDelegationRight,
    DelegationAmplifies(Aspect),
    TargetOutsideEnvelope,
    TargetInMandatoryExclusion,
    MissingMandatoryExclusion,
    TestScopeAmplifies,
    WindowExceedsParent,
    DurationExceedsMax,
    ConstraintAmplifies,
    // B — binding
    NoBindingEvidence,
    AssetBoundToOtherOrg,
    BindingUnavailable,
    // T — time
    ClockUnavailable,
    InvalidClockReading,
    NotYetValid(Obj),
    Expired(Obj),
    ClockUncertainty(Obj),
    // X — status
    StatusUnavailable,
    StatusUnknown(Obj),
    Revoked(Obj),
    Superseded(Obj),
}

impl Reason {
    /// Parameterless format-stage reasons, by name. Used to carry typed decode errors
    /// through serde's string-based error channel (see `codec::FormatError`).
    pub fn from_format_code(code: &str) -> Option<Reason> {
        use Reason::*;
        Some(match code {
            "MalformedEnvelope" => MalformedEnvelope,
            "UnsupportedAlgorithm" => UnsupportedAlgorithm,
            "DuplicateField" => DuplicateField,
            "NonCanonicalEncoding" => NonCanonicalEncoding,
            "MalformedField" => MalformedField,
            "UnsupportedVersion" => UnsupportedVersion,
            "UnknownField" => UnknownField,
            "MissingRequiredField" => MissingRequiredField,
            "UnknownEnumValue" => UnknownEnumValue,
            "MalformedTime" => MalformedTime,
            "NonCanonicalTime" => NonCanonicalTime,
            "MalformedWindow" => MalformedWindow,
            "MalformedKey" => MalformedKey,
            "MalformedAsset" => MalformedAsset,
            "NonCanonicalAsset" => NonCanonicalAsset,
            "UnsupportedAssetSyntax" => UnsupportedAssetSyntax,
            "DuplicateConstraintName" => DuplicateConstraintName,
            _ => return None,
        })
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Reason::*;
        match self {
            MissingRequiredObject(s) => write!(f, "MissingRequiredObject{{{s}}}"),
            WrongObjectType(s) => write!(f, "WrongObjectType{{{s}}}"),
            InvalidSignature(o) => write!(f, "InvalidSignature{{{o}}}"),
            WrongAudience(o) => write!(f, "WrongAudience{{{o}}}"),
            IssuerKeyMismatch(o) => write!(f, "IssuerKeyMismatch{{{o}}}"),
            ParentMismatch(o) => write!(f, "ParentMismatch{{{o}}}"),
            ParentVersionMismatch(o) => write!(f, "ParentVersionMismatch{{{o}}}"),
            UnsupportedCriticalConstraint(o) => write!(f, "UnsupportedCriticalConstraint{{{o}}}"),
            InadmissibleScope(o) => write!(f, "InadmissibleScope{{{o}}}"),
            DelegationAmplifies(a) => write!(f, "DelegationAmplifies{{{a}}}"),
            NotYetValid(o) => write!(f, "NotYetValid{{{o}}}"),
            Expired(o) => write!(f, "Expired{{{o}}}"),
            ClockUncertainty(o) => write!(f, "ClockUncertainty{{{o}}}"),
            StatusUnknown(o) => write!(f, "StatusUnknown{{{o}}}"),
            Revoked(o) => write!(f, "Revoked{{{o}}}"),
            Superseded(o) => write!(f, "Superseded{{{o}}}"),
            // Parameterless variants print their name.
            other => write!(f, "{other:?}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub stage: Stage,
    pub reason: Reason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecisionClass {
    Accept,
    Reject,
    Indeterminate,
}

impl fmt::Display for DecisionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The three-valued outcome of ValidChain_P (spec §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Reject(Finding),
    Indeterminate(Finding),
}

impl Decision {
    pub fn reject(stage: Stage, reason: Reason) -> Self {
        Decision::Reject(Finding { stage, reason })
    }

    pub fn indeterminate(stage: Stage, reason: Reason) -> Self {
        Decision::Indeterminate(Finding { stage, reason })
    }

    pub fn class(&self) -> DecisionClass {
        match self {
            Decision::Accept => DecisionClass::Accept,
            Decision::Reject(_) => DecisionClass::Reject,
            Decision::Indeterminate(_) => DecisionClass::Indeterminate,
        }
    }

    pub fn finding(&self) -> Option<&Finding> {
        match self {
            Decision::Accept => None,
            Decision::Reject(f) | Decision::Indeterminate(f) => Some(f),
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.finding() {
            None => f.write_str("Accept"),
            Some(x) => write!(f, "{} / {} / {}", self.class(), x.stage.letter(), x.reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_matches_case_table_spelling() {
        let d = Decision::reject(
            Stage::Policy,
            Reason::DelegationAmplifies(Aspect::TestCeiling),
        );
        assert_eq!(
            d.to_string(),
            "Reject / P / DelegationAmplifies{test_ceiling}"
        );
        let d = Decision::indeterminate(Stage::Anchor, Reason::RegistryUnavailable);
        assert_eq!(d.to_string(), "Indeterminate / N / RegistryUnavailable");
        assert_eq!(
            Reason::MissingRequiredObject(Slot::Issuer).to_string(),
            "MissingRequiredObject{issuer}"
        );
        assert_eq!(
            Reason::InvalidSignature(Obj::Issuer).to_string(),
            "InvalidSignature{D_U}"
        );
    }

    #[test]
    fn format_codes_round_trip() {
        for r in [
            Reason::NonCanonicalTime,
            Reason::DuplicateConstraintName,
            Reason::MalformedKey,
        ] {
            assert_eq!(Reason::from_format_code(&r.to_string()), Some(r));
        }
        assert_eq!(Reason::from_format_code("RootNotActive"), None);
    }
}
