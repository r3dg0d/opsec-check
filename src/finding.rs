//! Finding model and severity (no numeric "privacy scores").

use serde::{Deserialize, Serialize};

/// Honest severity labels only — never mapped to a fake 0–100 score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context that is useful but does not imply a problem by itself.
    Informational,
    /// Worth reviewing; may or may not be wrong depending on threat model.
    AttentionRecommended,
    /// Something looks misconfigured or unexpectedly exposed for privacy.
    ConfigurationIssue,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::AttentionRecommended => "attention recommended",
            Self::ConfigurationIssue => "configuration issue",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Informational => 0,
            Self::AttentionRecommended => 1,
            Self::ConfigurationIssue => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub check: String,
    pub severity: Severity,
    pub title: String,
    /// Plain-language explanation of why this matters for privacy/OPSEC.
    pub why_it_matters: String,
    pub detail: String,
    /// Honest caveat about what this check cannot prove.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remediation_hints: Vec<String>,
    /// Sibling tool that could dig deeper, if installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_tool: Option<String>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        check: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        why: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            check: check.into(),
            severity,
            title: title.into(),
            why_it_matters: why.into(),
            detail: detail.into(),
            limitation: None,
            remediation_hints: Vec::new(),
            related_tool: None,
        }
    }

    pub fn with_limitation(mut self, lim: impl Into<String>) -> Self {
        self.limitation = Some(lim.into());
        self
    }

    pub fn with_hints(mut self, hints: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.remediation_hints = hints.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.related_tool = Some(tool.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPresence {
    pub name: String,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub tool: String,
    pub version: String,
    pub generated_at: String,
    pub hostname: String,
    pub findings: Vec<Finding>,
    pub sibling_tools: Vec<ToolPresence>,
    pub limitations: Vec<String>,
}

impl AuditReport {
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max_by_key(|s| s.rank())
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut info = 0;
        let mut attn = 0;
        let mut cfg = 0;
        for f in &self.findings {
            match f.severity {
                Severity::Informational => info += 1,
                Severity::AttentionRecommended => attn += 1,
                Severity::ConfigurationIssue => cfg += 1,
            }
        }
        (info, attn, cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_labels_are_honest() {
        assert_eq!(Severity::Informational.as_str(), "informational");
        assert_eq!(
            Severity::AttentionRecommended.as_str(),
            "attention recommended"
        );
        assert_eq!(Severity::ConfigurationIssue.as_str(), "configuration issue");
    }

    #[test]
    fn worst_severity_picks_config() {
        let mut r = AuditReport {
            tool: "opsec-check".into(),
            version: "0.1.0".into(),
            generated_at: "now".into(),
            hostname: "box".into(),
            findings: vec![
                Finding::new("a", "t", Severity::Informational, "t", "w", "d"),
                Finding::new("b", "t", Severity::ConfigurationIssue, "t", "w", "d"),
            ],
            sibling_tools: vec![],
            limitations: vec![],
        };
        assert_eq!(r.worst_severity(), Some(Severity::ConfigurationIssue));
        r.findings.pop();
        assert_eq!(r.worst_severity(), Some(Severity::Informational));
    }
}
