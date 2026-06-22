use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RiskAssessment {
    pub score: u8,
    pub level: RiskLevel,
    pub reasons: Vec<String>,
    pub confusable_with: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskAssessment {
    pub fn from_score(score: u8, reasons: Vec<String>, confusable_with: Option<String>) -> Self {
        Self {
            score,
            level: level_for_score(score),
            reasons,
            confusable_with,
        }
    }
}

pub fn level_for_score(score: u8) -> RiskLevel {
    match score {
        0..=29 => RiskLevel::Low,
        30..=59 => RiskLevel::Medium,
        60..=79 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

pub fn assess_package_name(name: &str) -> RiskAssessment {
    let normalized = normalize_name(name);
    for trusted in high_trust_packages() {
        let trusted_normalized = normalize_name(trusted);
        if name != *trusted
            && (normalized == trusted_normalized
                || edit_distance(&normalized, &trusted_normalized) <= 2)
        {
            return RiskAssessment::from_score(
                30,
                vec![format!("possible namesquat: confusable with {trusted}")],
                Some(trusted.to_string()),
            );
        }
    }
    RiskAssessment::from_score(0, Vec::new(), None)
}

pub fn combine_risk(base_score: u8, base_reasons: &[String], name: &str) -> RiskAssessment {
    let name_risk = assess_package_name(name);
    let mut score = base_score.saturating_add(name_risk.score).min(100);
    let mut reasons = base_reasons.to_vec();
    reasons.extend(name_risk.reasons.clone());
    if reasons.is_empty() && score >= 10 {
        reasons.push("package has limited trust metadata".to_string());
    }
    if score > 100 {
        score = 100;
    }
    RiskAssessment::from_score(score, reasons, name_risk.confusable_with)
}

fn high_trust_packages() -> &'static [&'static str] {
    &["prettier", "react", "eslint", "typescript", "is-odd"]
}

fn normalize_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter_map(|ch| match ch {
            '-' | '_' => None,
            '0' => Some('o'),
            '1' | 'l' | 'í' | 'ì' | 'ï' | 'î' => Some('i'),
            'á' | 'à' | 'ä' | 'â' => Some('a'),
            'é' | 'è' | 'ë' | 'ê' => Some('e'),
            'ó' | 'ò' | 'ö' | 'ô' => Some('o'),
            'ú' | 'ù' | 'ü' | 'û' => Some('u'),
            ch if ch.is_ascii_alphanumeric() => Some(ch),
            _ => None,
        })
        .collect()
}

fn edit_distance(left: &str, right: &str) -> usize {
    let mut costs = (0..=right.len()).collect::<Vec<_>>();
    for (i, left_ch) in left.chars().enumerate() {
        let mut previous = costs[0];
        costs[0] = i + 1;
        for (j, right_ch) in right.chars().enumerate() {
            let temp = costs[j + 1];
            costs[j + 1] = if left_ch == right_ch {
                previous
            } else {
                1 + previous.min(costs[j]).min(costs[j + 1])
            };
            previous = temp;
        }
    }
    costs[right.len()]
}

#[cfg(test)]
mod tests {
    use super::{assess_package_name, level_for_score, RiskLevel};

    #[test]
    fn risk_levels_match_policy() {
        assert_eq!(level_for_score(0), RiskLevel::Low);
        assert_eq!(level_for_score(30), RiskLevel::Medium);
        assert_eq!(level_for_score(60), RiskLevel::High);
        assert_eq!(level_for_score(80), RiskLevel::Critical);
    }

    #[test]
    fn detects_case_confusable_package() {
        let risk = assess_package_name("is-Odd");
        assert_eq!(risk.confusable_with.as_deref(), Some("is-odd"));
        assert!(risk.score >= 30);
    }
}
