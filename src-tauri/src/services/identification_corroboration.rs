// Repetition-based corroboration for BSim matches that fail the
// significance threshold on their own.
//
// Real data (serpentine.exe, a plain MSVC binary with no dynamic
// dependency besides KERNEL32.DLL) showed BSim matching common CRT
// startup glue code at similarity ~1.0, rejected purely because the
// significance score BSim assigns to small, generic functions falls
// under the safety threshold. A match repeated at several distinct
// addresses in the *same* binary is itself corroborating evidence, since
// the significance floor scores every address independently and cannot
// see that pattern.
//
// The real data also showed something the design did not originally
// account for: at a given address, several genuinely different CRT
// helpers (e.g. "NtCurrentTeb", "__local_stdio_printf_options",
// "__scrt_initialize_mta") can tie at the exact same similarity and
// significance -- BSim's fingerprint cannot tell them apart at all, the
// same way 39 different C++ exception classes tied on FunctionID (their
// copy constructors are byte-identical). Counting every name present in
// such a tie as "repeated" would silently corroborate one arbitrary name
// out of several equally likely ones. So only a *single, unambiguous*
// winner at a given address -- one with a real margin over its
// runner-up -- ever counts toward another address's repetition.

use std::collections::HashMap;

use crate::models::ghidra_identification::FunctionIdentification;

const NEAR_PERFECT_SIMILARITY: f64 = 0.999;

// Mirrors automaticBsimMinimumMargin in +page.svelte: a candidate that
// would not individually clear the existing ambiguity margin is not a
// "clean winner" here either, so it never contributes to repetition.
const CLEAN_WINNER_MINIMUM_MARGIN: f64 = 0.05;

/// A repetition count of at least this many distinct addresses is treated
/// as corroboration strong enough to rescue a match BSim's own
/// significance score alone would reject as too small/generic to trust.
pub const MINIMUM_CORROBORATING_REPETITIONS: usize = 3;

/// For each BSim candidate name, counts how many distinct function
/// addresses in this binary have it as an unambiguous (non-tied),
/// near-perfect-similarity match. A name only ever contributes from an
/// address where it clearly wins that address on its own -- never from
/// an address where it merely appears inside an unresolved tie.
pub fn count_bsim_repetitions(
    identifications: &[FunctionIdentification],
) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    for identification in identifications {
        let mut best_similarity_by_name: HashMap<&str, f64> = HashMap::new();
        for candidate in &identification.bsim_candidates {
            let best = best_similarity_by_name
                .entry(candidate.name.as_str())
                .or_insert(candidate.similarity);
            if candidate.similarity > *best {
                *best = candidate.similarity;
            }
        }

        let mut ranked: Vec<(&str, f64)> = best_similarity_by_name.into_iter().collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1));

        let Some(&(top_name, top_similarity)) = ranked.first() else {
            continue;
        };
        if top_similarity < NEAR_PERFECT_SIMILARITY {
            continue;
        }

        let is_clean_winner = match ranked.get(1) {
            Some(&(_, runner_up_similarity)) => {
                top_similarity - runner_up_similarity >= CLEAN_WINNER_MINIMUM_MARGIN
            }
            None => true,
        };
        if is_clean_winner {
            *counts.entry(top_name.to_owned()).or_insert(0) += 1;
        }
    }

    counts
}

/// Whether a candidate name recurs often enough across the binary to
/// corroborate a match that fell short of the significance threshold.
pub fn is_corroborated_by_repetition(name: &str, repetitions: &HashMap<String, usize>) -> bool {
    repetitions.get(name).copied().unwrap_or(0) >= MINIMUM_CORROBORATING_REPETITIONS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_identification::BsimIdentificationCandidate;

    fn identification_with_bsim(
        entry_address: &str,
        candidates: Vec<(&str, &str, f64, f64)>,
    ) -> FunctionIdentification {
        FunctionIdentification {
            entry_address: entry_address.to_owned(),
            candidates: Vec::new(),
            bsim_candidates: candidates
                .into_iter()
                .map(
                    |(name, executable, similarity, significance)| BsimIdentificationCandidate {
                        name: name.to_owned(),
                        executable: executable.to_owned(),
                        corpus: "Pack essentiel Reverse Assistant".to_owned(),
                        similarity,
                        significance,
                    },
                )
                .collect(),
            bsim_scanned: true,
            bsim_message: None,
        }
    }

    #[test]
    fn an_unambiguous_name_repeated_at_several_distinct_addresses_is_corroborated() {
        let identifications = vec![
            identification_with_bsim(
                "0x1",
                vec![("__real_unique_helper", "sqlite3.dll", 1.0, 8.3)],
            ),
            identification_with_bsim(
                "0x2",
                vec![("__real_unique_helper", "sqlite3.dll", 1.0, 8.3)],
            ),
            identification_with_bsim(
                "0x3",
                vec![("__real_unique_helper", "sqlite3.dll", 1.0, 8.3)],
            ),
        ];

        let repetitions = count_bsim_repetitions(&identifications);

        assert_eq!(repetitions.get("__real_unique_helper"), Some(&3));
        assert!(is_corroborated_by_repetition(
            "__real_unique_helper",
            &repetitions
        ));
    }

    #[test]
    fn a_name_seen_at_only_one_or_two_addresses_is_not_corroborated() {
        let identifications = vec![
            identification_with_bsim(
                "0x140001bfc",
                vec![("__scrt_initialize_crt", "sqlite3.dll", 1.0, 9.8)],
            ),
            identification_with_bsim(
                "0x140001ec0",
                vec![("__scrt_initialize_crt", "sqlite3.dll", 1.0, 9.8)],
            ),
        ];

        let repetitions = count_bsim_repetitions(&identifications);

        assert_eq!(repetitions.get("__scrt_initialize_crt"), Some(&2));
        assert!(!is_corroborated_by_repetition(
            "__scrt_initialize_crt",
            &repetitions
        ));
    }

    #[test]
    fn a_tied_address_never_corroborates_any_of_the_tied_names() {
        // Real shape observed on serpentine.exe (address 0x1400016b0):
        // five genuinely different CRT helpers tie at the exact same
        // similarity and significance. None of them may count as a
        // "repetition" from this address -- picking any one of the five
        // would be an arbitrary, unverified guess among equally likely
        // names, exactly like the 39-way FunctionID tie on exception
        // copy constructors.
        let tied_address = identification_with_bsim(
            "0x1400016b0",
            vec![
                ("NtCurrentTeb", "sqlite3.dll", 0.9999999999999998, 8.275),
                (
                    "__local_stdio_printf_options",
                    "sqlite3.dll",
                    0.9999999999999998,
                    8.275,
                ),
                (
                    "__local_stdio_scanf_options",
                    "sqlite3.dll",
                    0.9999999999999998,
                    8.275,
                ),
                (
                    "__scrt_get_dyn_tls_init_callback",
                    "sqlite3.dll",
                    0.9999999999999998,
                    8.275,
                ),
                (
                    "__scrt_initialize_mta",
                    "sqlite3.dll",
                    0.9999999999999998,
                    8.275,
                ),
            ],
        );
        // Even repeated at 3 identically-tied addresses, still no rescue.
        let identifications = vec![tied_address.clone(), tied_address.clone(), tied_address];

        let repetitions = count_bsim_repetitions(&identifications);

        assert!(repetitions.is_empty());
        assert!(!is_corroborated_by_repetition("NtCurrentTeb", &repetitions));
    }

    #[test]
    fn a_clean_winner_still_counts_even_when_a_weaker_runner_up_is_present() {
        let identifications = vec![
            identification_with_bsim(
                "0x1",
                vec![
                    ("__real_unique_helper", "sqlite3.dll", 1.0, 8.3),
                    ("some_other_name", "sqlite3.dll", 0.6, 30.0),
                ],
            ),
            identification_with_bsim(
                "0x2",
                vec![("__real_unique_helper", "sqlite3.dll", 1.0, 8.3)],
            ),
            identification_with_bsim(
                "0x3",
                vec![("__real_unique_helper", "sqlite3.dll", 1.0, 8.3)],
            ),
        ];

        let repetitions = count_bsim_repetitions(&identifications);

        assert_eq!(repetitions.get("__real_unique_helper"), Some(&3));
    }

    #[test]
    fn multiple_candidates_at_the_same_address_each_count_once_per_address() {
        // A single function can carry several distinct near-perfect BSim
        // candidates (one per matching corpus executable) for the *same*
        // real name. That is not a tie between different names, so it
        // must still count -- but only once for this one address.
        let identifications = vec![identification_with_bsim(
            "0x140001090",
            vec![
                ("__scrt_initialize_type_info", "sqlite3.dll", 1.0, 9.8),
                ("__scrt_initialize_type_info", "zlib1.dll", 1.0, 9.8),
            ],
        )];

        let repetitions = count_bsim_repetitions(&identifications);

        assert_eq!(repetitions.get("__scrt_initialize_type_info"), Some(&1));
    }

    #[test]
    fn low_similarity_candidates_do_not_count_toward_repetition() {
        let identifications = vec![
            identification_with_bsim("0x1", vec![("some_name", "sqlite3.dll", 0.75, 20.0)]),
            identification_with_bsim("0x2", vec![("some_name", "sqlite3.dll", 0.75, 20.0)]),
            identification_with_bsim("0x3", vec![("some_name", "sqlite3.dll", 0.75, 20.0)]),
        ];

        let repetitions = count_bsim_repetitions(&identifications);

        assert!(!repetitions.contains_key("some_name"));
    }

    #[test]
    fn an_empty_identification_list_has_no_repetitions() {
        let repetitions = count_bsim_repetitions(&[]);

        assert!(repetitions.is_empty());
        assert!(!is_corroborated_by_repetition("anything", &repetitions));
    }
}
