//! Offline namesquat check for names that were never imported. Uses the same
//! list and thresholds as registry/internal/audit/namesquat.go.

use serde::Serialize;

const POPULAR_PACKAGES: &str =
    include_str!("../../../registry/internal/audit/popular_packages.txt");

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NamesquatWarning {
    pub confusable_with: String,
}

fn popular() -> impl Iterator<Item = &'static str> {
    POPULAR_PACKAGES
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

pub fn namesquat(name: &str) -> Option<NamesquatWarning> {
    if name.is_empty() || popular().any(|p| p == name) {
        return None;
    }
    let normalized = normalize_name(name);
    for candidate in popular() {
        let target = normalize_name(candidate);
        let threshold = match target.chars().count() {
            n if n >= 8 => 2,
            n if n >= 5 => 1,
            _ => 0,
        };
        if normalized == target
            || (threshold > 0 && edit_distance(&normalized, &target) <= threshold)
        {
            return Some(NamesquatWarning {
                confusable_with: candidate.to_string(),
            });
        }
    }
    None
}

fn normalize_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter_map(|ch| match ch {
            '-' | '_' | '.' => None,
            '0' => Some('o'),
            '1' | 'l' | 'í' | 'ì' | 'ï' | 'î' => Some('i'),
            'á' | 'à' | 'ä' | 'â' => Some('a'),
            'é' | 'è' | 'ë' | 'ê' => Some('e'),
            'ó' | 'ò' | 'ö' | 'ô' => Some('o'),
            'ú' | 'ù' | 'ü' | 'û' => Some('u'),
            ch if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '@' || ch == '/' => {
                Some(ch)
            }
            _ => None,
        })
        .collect()
}

/// Optimal-string-alignment distance (Levenshtein plus transpositions).
fn edit_distance(left: &str, right: &str) -> usize {
    let a: Vec<char> = left.chars().collect();
    let b: Vec<char> = right.chars().collect();
    let mut rows = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in rows.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            rows[i][j] = (rows[i - 1][j] + 1)
                .min(rows[i][j - 1] + 1)
                .min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                rows[i][j] = rows[i][j].min(rows[i - 2][j - 2] + 1);
            }
        }
    }
    rows[a.len()][b.len()]
}

#[cfg(test)]
mod tests {
    use super::namesquat;

    #[test]
    fn matches_registry_namesquat_cases() {
        // Same table as registry/internal/audit TestNamesquat.
        for (name, flagged) in [
            ("lodash", false),
            ("l0dash", true),
            ("lodahs", true),
            ("expres", true),
            ("react", false),
            ("preact", false),
            ("my-internal-tool", false),
            ("is-0dd", true),
        ] {
            assert_eq!(namesquat(name).is_some(), flagged, "{name}");
        }
    }
}
