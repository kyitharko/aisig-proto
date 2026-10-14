//! Loading the reviewed case labels (tests/cases/reviewed_cases.toml).
//!
//! The labels file is the oracle. Nothing in this crate writes to it.

use serde::Deserialize;

use crate::decision::{Decision, DecisionClass};

pub const CASES_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/cases/reviewed_cases.toml"
);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseFile {
    pub case: Vec<CaseLabel>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLabel {
    pub id: String,
    /// `chain`, `exact_node_query` or `subtree_query`.
    pub kind: String,
    /// `Accept`, `Reject`, `Indeterminate`, or a scope answer (`InScope`, `Excluded`, `OutOfScope`).
    pub expected: String,
    #[serde(default)]
    pub stage: String,
    #[serde(default)]
    pub reason: String,
    /// Asset shorthand for scope queries.
    #[serde(default)]
    pub probe: String,
    /// `reviewed`, `reviewed-by-instruction`, or `proposed`.
    pub label_status: String,
    #[serde(default)]
    pub note: String,
}

impl CaseLabel {
    pub fn is_chain(&self) -> bool {
        self.kind == "chain"
    }

    pub fn is_reviewed(&self) -> bool {
        self.label_status.starts_with("reviewed")
    }

    /// The label in `Decision`'s display form, e.g. `Reject / P / TargetOutsideEnvelope`.
    pub fn expected_display(&self) -> String {
        if self.expected == "Accept" {
            "Accept".to_owned()
        } else {
            format!("{} / {} / {}", self.expected, self.stage, self.reason)
        }
    }

    pub fn expected_class(&self) -> Option<DecisionClass> {
        match self.expected.as_str() {
            "Accept" => Some(DecisionClass::Accept),
            "Reject" => Some(DecisionClass::Reject),
            "Indeterminate" => Some(DecisionClass::Indeterminate),
            _ => None,
        }
    }

    /// Exact agreement: class, stage and reason.
    pub fn matches(&self, d: &Decision) -> bool {
        d.to_string() == self.expected_display()
    }
}

pub fn load(path: &str) -> Result<Vec<CaseLabel>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let file: CaseFile = toml::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    Ok(file.case)
}

pub fn load_default() -> Result<Vec<CaseLabel>, String> {
    load(CASES_PATH)
}
