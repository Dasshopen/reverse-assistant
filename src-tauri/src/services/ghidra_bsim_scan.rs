use std::fs;
use std::process::Command;

use tauri::AppHandle;

use crate::models::ghidra_identification::FunctionIdentification;
use crate::models::ghidra_installation::{configure_java_environment, GhidraInstallation};
use crate::models::ghidra_session::AnalysisSession;
use crate::services::bsim_corpus::{active_corpora, database_url};
use crate::services::ghidra_headless::{tail, HEADLESS_MAX_HEAP};

const SCRIPT_NAME: &str = "QueryBsimFunctionsJson.java";
const STDERR_TAIL_BYTES: usize = 4_000;

pub fn scan_unnamed_functions(
    app: &AppHandle,
    installation: &GhidraInstallation,
    session: &AnalysisSession,
) -> Result<Vec<FunctionIdentification>, String> {
    let corpora = active_corpora(app)?;
    if corpora.is_empty() {
        return Err(
            "aucun corpus BSim actif n'est disponible; vérifie le pack BSim dans Paramètres"
                .to_owned(),
        );
    }

    let destination = session.project_dir.join("bsim-identifications.json");
    let scripts_dir = installation.extensions_dir.join("ghidra_scripts");
    let mut command = Command::new(
        installation
            .install_dir
            .join("support")
            .join("analyzeHeadless.bat"),
    );
    command
        .arg(&session.project_dir)
        .arg(&session.project_name)
        .arg("-process")
        .arg(&session.program_path_in_project)
        .arg("-noanalysis")
        .arg("-readOnly")
        .arg("-scriptPath")
        .arg(scripts_dir)
        .arg("-postScript")
        .arg(SCRIPT_NAME)
        .arg(&destination)
        .env("GHIDRA_HEADLESS_MAXMEM", HEADLESS_MAX_HEAP);

    for corpus in corpora {
        command
            .arg("--bsim-corpus")
            .arg(corpus.id)
            .arg(corpus.name)
            .arg(database_url(&corpus.path)?);
    }
    configure_java_environment(&mut command, installation);

    let output = command
        .output()
        .map_err(|error| format!("failed to launch the background BSim scan: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "background BSim scan failed (exit code {:?}): {}",
            output.status.code(),
            tail(&output.stderr, STDERR_TAIL_BYTES)
        ));
    }
    if !destination.is_file() {
        return Err(format!(
            "background BSim scan produced no result file at '{}'",
            destination.display()
        ));
    }

    let json = fs::read_to_string(&destination).map_err(|error| {
        format!(
            "failed to read background BSim results '{}': {error}",
            destination.display()
        )
    })?;
    let mut results: Vec<FunctionIdentification> = serde_json::from_str(&json)
        .map_err(|error| format!("invalid background BSim result JSON: {error}"))?;
    normalize_entry_addresses(&mut results);
    Ok(results)
}

fn canonical_entry_address(address: &str) -> String {
    let trimmed = address.trim();
    let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    else {
        return trimmed.to_owned();
    };
    u64::from_str_radix(hex, 16)
        .map(|value| format!("0x{value:x}"))
        .unwrap_or_else(|_| trimmed.to_owned())
}

fn normalize_entry_addresses(results: &mut [FunctionIdentification]) {
    for result in results {
        result.entry_address = canonical_entry_address(&result.entry_address);
    }
}

pub fn merge_results(
    mut function_id: Vec<FunctionIdentification>,
    mut bsim: Vec<FunctionIdentification>,
) -> Vec<FunctionIdentification> {
    normalize_entry_addresses(&mut function_id);
    normalize_entry_addresses(&mut bsim);
    for bsim_result in bsim {
        if let Some(existing) = function_id
            .iter_mut()
            .find(|item| item.entry_address == bsim_result.entry_address)
        {
            existing.bsim_candidates = bsim_result.bsim_candidates;
            existing.bsim_scanned = bsim_result.bsim_scanned;
            existing.bsim_message = bsim_result.bsim_message;
        } else {
            function_id.push(bsim_result);
        }
    }
    function_id.sort_by(|left, right| left.entry_address.cmp(&right.entry_address));
    function_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_identification::{BsimIdentificationCandidate, FidCandidate};

    fn identification(address: &str, fid_name: Option<&str>) -> FunctionIdentification {
        FunctionIdentification {
            entry_address: address.to_owned(),
            candidates: fid_name
                .map(|name| FidCandidate {
                    name: name.to_owned(),
                    library_family: "Visual Studio".to_owned(),
                    library_version: "2019".to_owned(),
                    library_variant: "Release".to_owned(),
                    overall_score: 20.0,
                    match_mode: "SPECIFIC".to_owned(),
                })
                .into_iter()
                .collect(),
            bsim_candidates: Vec::new(),
            bsim_scanned: false,
            bsim_message: None,
        }
    }

    #[test]
    fn merge_keeps_function_id_and_adds_bsim_evidence() {
        let function_id = vec![identification("0x20", Some("memcpy"))];
        let mut bsim = identification("0x20", None);
        bsim.bsim_scanned = true;
        bsim.bsim_candidates.push(BsimIdentificationCandidate {
            name: "memcpy".to_owned(),
            executable: "msvcrt.dll".to_owned(),
            corpus: "runtime".to_owned(),
            similarity: 1.0,
            significance: 18.0,
        });

        let merged = merge_results(function_id, vec![bsim]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].candidates[0].name, "memcpy");
        assert!(merged[0].bsim_scanned);
        assert_eq!(merged[0].bsim_candidates[0].corpus, "runtime");
    }

    #[test]
    fn merge_adds_bsim_only_functions_and_sorts_by_address() {
        let merged = merge_results(
            vec![identification("0x20", Some("memcpy"))],
            vec![identification("0x10", None)],
        );

        assert_eq!(
            merged
                .iter()
                .map(|item| item.entry_address.as_str())
                .collect::<Vec<_>>(),
            vec!["0x10", "0x20"]
        );
    }

    #[test]
    fn merge_treats_zero_padded_and_canonical_addresses_as_the_same_function() {
        let function_id = vec![identification("0x1014c", Some("StrCatS"))];
        let mut bsim = identification("0x0001014c", None);
        bsim.bsim_scanned = true;
        bsim.bsim_candidates.push(BsimIdentificationCandidate {
            name: "StrCatS".to_owned(),
            executable: "Shell.efi".to_owned(),
            corpus: "edk2".to_owned(),
            similarity: 0.923,
            significance: 104.2,
        });

        let merged = merge_results(function_id, vec![bsim]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].entry_address, "0x1014c");
        assert_eq!(merged[0].bsim_candidates[0].name, "StrCatS");
    }
}
