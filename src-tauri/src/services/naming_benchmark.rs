use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticReview {
    Useful,
    Incorrect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamingBenchmarkCase {
    pub entry_address: String,
    /// First value is the canonical symbol; additional values are explicit
    /// human-approved aliases. The evaluator never invents semantic matches.
    pub expected_names: Vec<String>,
    pub suggested_name: Option<String>,
    #[serde(default)]
    pub confidence: u8,
    #[serde(default)]
    pub automatically_applied: bool,
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub model_calls: u32,
    /// Optional human review of behavioral usefulness. This is deliberately
    /// separate from exact symbol recovery and is never inferred by code.
    #[serde(default)]
    pub semantic_review: Option<SemanticReview>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamingBenchmarkSuite {
    pub name: String,
    pub cases: Vec<NamingBenchmarkCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamingBenchmarkReport {
    pub suite_name: String,
    pub total_functions: usize,
    pub proposed_names: usize,
    pub abstentions: usize,
    pub correct_proposals: usize,
    pub incorrect_proposals: usize,
    pub automatically_applied: usize,
    pub correct_automatic_names: usize,
    pub unsafe_automatic_names: usize,
    /// Integer ratios avoid floating-point drift in persisted comparisons.
    pub proposal_coverage_per_mille: u16,
    pub proposal_precision_per_mille: u16,
    pub automatic_precision_per_mille: u16,
    pub semantically_reviewed: usize,
    pub semantically_useful: usize,
    pub semantically_incorrect: usize,
    pub semantic_precision_per_mille: Option<u16>,
    pub elapsed_ms: u64,
    pub model_calls: u32,
}

fn normalized_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn ratio_per_mille(numerator: usize, denominator: usize) -> u16 {
    if denominator == 0 {
        return 0;
    }
    ((numerator.saturating_mul(1_000) / denominator).min(1_000)) as u16
}

fn proposal_is_correct(case: &NamingBenchmarkCase) -> bool {
    let Some(suggestion) = case.suggested_name.as_deref() else {
        return false;
    };
    let normalized = normalized_name(suggestion);
    !normalized.is_empty()
        && case
            .expected_names
            .iter()
            .any(|expected| normalized_name(expected) == normalized)
}

pub fn evaluate_suite(suite: &NamingBenchmarkSuite) -> Result<NamingBenchmarkReport, String> {
    for case in &suite.cases {
        if case.expected_names.is_empty()
            || case
                .expected_names
                .iter()
                .any(|name| name.trim().is_empty())
        {
            return Err(format!(
                "benchmark case '{}' must contain at least one non-empty expected name",
                case.entry_address
            ));
        }
        if case.confidence > 100 {
            return Err(format!(
                "benchmark case '{}' has confidence above 100",
                case.entry_address
            ));
        }
        if case.automatically_applied && case.suggested_name.is_none() {
            return Err(format!(
                "benchmark case '{}' cannot be automatically applied without a suggestion",
                case.entry_address
            ));
        }
    }

    let proposed_names = suite
        .cases
        .iter()
        .filter(|case| case.suggested_name.is_some())
        .count();
    let correct_proposals = suite
        .cases
        .iter()
        .filter(|case| proposal_is_correct(case))
        .count();
    let automatically_applied = suite
        .cases
        .iter()
        .filter(|case| case.automatically_applied)
        .count();
    let correct_automatic_names = suite
        .cases
        .iter()
        .filter(|case| case.automatically_applied && proposal_is_correct(case))
        .count();
    let total_functions = suite.cases.len();
    let semantically_reviewed = suite
        .cases
        .iter()
        .filter(|case| case.semantic_review.is_some())
        .count();
    let semantically_useful = suite
        .cases
        .iter()
        .filter(|case| case.semantic_review == Some(SemanticReview::Useful))
        .count();

    Ok(NamingBenchmarkReport {
        suite_name: suite.name.clone(),
        total_functions,
        proposed_names,
        abstentions: total_functions.saturating_sub(proposed_names),
        correct_proposals,
        incorrect_proposals: proposed_names.saturating_sub(correct_proposals),
        automatically_applied,
        correct_automatic_names,
        unsafe_automatic_names: automatically_applied.saturating_sub(correct_automatic_names),
        proposal_coverage_per_mille: ratio_per_mille(proposed_names, total_functions),
        proposal_precision_per_mille: ratio_per_mille(correct_proposals, proposed_names),
        automatic_precision_per_mille: ratio_per_mille(
            correct_automatic_names,
            automatically_applied,
        ),
        semantically_reviewed,
        semantically_useful,
        semantically_incorrect: semantically_reviewed.saturating_sub(semantically_useful),
        semantic_precision_per_mille: (semantically_reviewed > 0)
            .then(|| ratio_per_mille(semantically_useful, semantically_reviewed)),
        elapsed_ms: suite.cases.iter().map(|case| case.elapsed_ms).sum(),
        model_calls: suite.cases.iter().map(|case| case.model_calls).sum(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(
        expected: &str,
        suggested: Option<&str>,
        automatically_applied: bool,
    ) -> NamingBenchmarkCase {
        NamingBenchmarkCase {
            entry_address: "0x1".to_owned(),
            expected_names: vec![expected.to_owned()],
            suggested_name: suggested.map(str::to_owned),
            confidence: 80,
            automatically_applied,
            elapsed_ms: 10,
            model_calls: 1,
            semantic_review: None,
        }
    }

    #[test]
    fn report_keeps_coverage_precision_and_unsafe_names_separate() {
        let suite = NamingBenchmarkSuite {
            name: "fixture".to_owned(),
            cases: vec![
                case("print_flag", Some("printFlag"), true),
                case("open_config", Some("close_config"), true),
                case("validate_key", None, false),
            ],
        };
        let report = evaluate_suite(&suite).expect("valid suite");
        assert_eq!(report.total_functions, 3);
        assert_eq!(report.proposed_names, 2);
        assert_eq!(report.correct_proposals, 1);
        assert_eq!(report.unsafe_automatic_names, 1);
        assert_eq!(report.proposal_coverage_per_mille, 666);
        assert_eq!(report.proposal_precision_per_mille, 500);
        assert_eq!(report.automatic_precision_per_mille, 500);
        assert_eq!(report.elapsed_ms, 30);
        assert_eq!(report.model_calls, 3);
    }

    #[test]
    fn explicit_aliases_are_accepted_but_no_semantics_are_guessed() {
        let mut benchmark_case = case("authenticate", Some("validate_credentials"), false);
        benchmark_case
            .expected_names
            .push("validate_credentials".to_owned());
        assert!(proposal_is_correct(&benchmark_case));
    }

    #[test]
    fn malformed_automatic_result_is_rejected() {
        let suite = NamingBenchmarkSuite {
            name: "invalid".to_owned(),
            cases: vec![case("main", None, true)],
        };
        assert!(evaluate_suite(&suite).is_err());
    }

    #[test]
    fn human_semantic_review_is_reported_without_weakening_exact_matching() {
        let mut paraphrase = case("authenticate", Some("validate_credentials"), false);
        paraphrase.semantic_review = Some(SemanticReview::Useful);
        let suite = NamingBenchmarkSuite {
            name: "semantic-review".to_owned(),
            cases: vec![paraphrase],
        };
        let report = evaluate_suite(&suite).expect("valid suite");
        assert_eq!(report.correct_proposals, 0);
        assert_eq!(report.semantically_useful, 1);
        assert_eq!(report.semantic_precision_per_mille, Some(1_000));
    }
}
