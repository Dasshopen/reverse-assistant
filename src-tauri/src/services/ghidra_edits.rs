use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::models::ghidra_installation::{configure_java_environment, GhidraInstallation};
use crate::models::ghidra_session::AnalysisSession;
use crate::services::ghidra_headless::{tail, HEADLESS_MAX_HEAP};
use crate::services::ghidra_import::{import_ghidra_export, ImportedGhidraExport};

const APPLY_RENAMES_SCRIPT_NAME: &str = "ApplyFunctionRenamesJson.java";
const STDERR_TAIL_BYTES: usize = 4000;
const MAX_RENAMES: usize = 500;
const MAX_NAME_LENGTH: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionRename {
    pub entry_address: String,
    pub new_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedFunctionRename {
    pub entry_address: String,
    pub old_name: String,
    pub new_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyRenamesResult {
    pub applied: Vec<AppliedFunctionRename>,
    pub imported: ImportedGhidraExport,
}

#[derive(Debug, Serialize)]
struct RenameRequest<'a> {
    schema_version: u32,
    renames: &'a [FunctionRename],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameResultJson {
    schema_version: u32,
    applied: Vec<AppliedFunctionRename>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyRenamesInvocation {
    pub program: PathBuf,
    pub args: Vec<String>,
}

pub fn build_apply_renames_args(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    request_path: &Path,
    result_path: &Path,
    refreshed_export_path: &Path,
) -> ApplyRenamesInvocation {
    let program = installation
        .install_dir
        .join("support")
        .join("analyzeHeadless.bat");
    let scripts_dir = installation.extensions_dir.join("ghidra_scripts");
    let args = vec![
        session.project_dir.to_string_lossy().into_owned(),
        session.project_name.clone(),
        "-process".to_owned(),
        session.program_path_in_project.clone(),
        "-noanalysis".to_owned(),
        "-scriptPath".to_owned(),
        scripts_dir.to_string_lossy().into_owned(),
        "-postScript".to_owned(),
        APPLY_RENAMES_SCRIPT_NAME.to_owned(),
        request_path.to_string_lossy().into_owned(),
        result_path.to_string_lossy().into_owned(),
        refreshed_export_path.to_string_lossy().into_owned(),
    ];

    ApplyRenamesInvocation { program, args }
}

fn validate_and_normalize_renames(
    renames: &[FunctionRename],
) -> Result<Vec<FunctionRename>, String> {
    if renames.is_empty() || renames.len() > MAX_RENAMES {
        return Err("renames must contain between 1 and 500 entries".to_owned());
    }

    let mut addresses = HashSet::new();
    let mut requested_names = HashSet::new();
    let mut normalized = Vec::with_capacity(renames.len());
    for rename in renames {
        if !crate::models::ghidra_export::is_valid_address(&rename.entry_address) {
            return Err(format!(
                "invalid function entry address: {}",
                rename.entry_address
            ));
        }
        if !addresses.insert(rename.entry_address.as_str()) {
            return Err(format!(
                "duplicate function rename: {}",
                rename.entry_address
            ));
        }
        let new_name = rename.new_name.trim();
        if new_name.is_empty()
            || new_name.chars().count() > MAX_NAME_LENGTH
            || new_name.chars().any(char::is_control)
        {
            return Err(format!(
                "invalid new function name at {}",
                rename.entry_address
            ));
        }
        if !requested_names.insert(new_name) {
            return Err(format!(
                "duplicate target function name in rename batch: {new_name}"
            ));
        }
        normalized.push(FunctionRename {
            entry_address: rename.entry_address.clone(),
            new_name: new_name.to_owned(),
        });
    }
    Ok(normalized)
}

fn parse_result(json: &str, expected_count: usize) -> Result<Vec<AppliedFunctionRename>, String> {
    let result: RenameResultJson = serde_json::from_str(json)
        .map_err(|error| format!("invalid function rename result from Ghidra: {error}"))?;
    if result.schema_version != 1 {
        return Err(format!(
            "unsupported function rename result schema: {}",
            result.schema_version
        ));
    }
    if result.applied.len() != expected_count {
        return Err(format!(
            "Ghidra reported {} applied renames but {} were requested",
            result.applied.len(),
            expected_count
        ));
    }
    Ok(result.applied)
}

pub fn run_apply_renames(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    renames: &[FunctionRename],
) -> Result<ApplyRenamesResult, String> {
    let renames = validate_and_normalize_renames(renames)?;
    let request_path = session
        .project_dir
        .join(".reverse-assistant-renames-request.json");
    let result_path = session
        .project_dir
        .join(".reverse-assistant-renames-result.json");
    let refreshed_export_path = session
        .project_dir
        .join(".reverse-assistant-renamed-export.json");

    let _ = fs::remove_file(&result_path);
    let _ = fs::remove_file(&refreshed_export_path);
    let request_json = serde_json::to_string_pretty(&RenameRequest {
        schema_version: 1,
        renames: &renames,
    })
    .map_err(|error| format!("failed to serialize function rename request: {error}"))?;
    fs::write(&request_path, request_json).map_err(|error| {
        format!(
            "failed to write function rename request '{}': {error}",
            request_path.display()
        )
    })?;

    let operation = (|| {
        let invocation = build_apply_renames_args(
            installation,
            session,
            &request_path,
            &result_path,
            &refreshed_export_path,
        );
        let mut command = Command::new(&invocation.program);
        command
            .args(&invocation.args)
            .env("GHIDRA_HEADLESS_MAXMEM", HEADLESS_MAX_HEAP);
        configure_java_environment(&mut command, installation);
        let output = command.output().map_err(|error| {
            format!(
                "failed to launch Ghidra function rename process '{}': {error}",
                invocation.program.display()
            )
        })?;

        if !output.status.success() || !result_path.is_file() || !refreshed_export_path.is_file() {
            return Err(format!(
                "Ghidra function rename failed (exit code {:?}): {}",
                output.status.code(),
                tail(&output.stderr, STDERR_TAIL_BYTES)
            ));
        }

        let result_json = fs::read_to_string(&result_path).map_err(|error| {
            format!(
                "failed to read function rename result '{}': {error}",
                result_path.display()
            )
        })?;
        let applied = parse_result(&result_json, renames.len())?;
        let imported = import_ghidra_export(&refreshed_export_path)?;

        // Cached pseudocode contains the previous function names. This path
        // is safe to remove only because callers first verify the session is
        // inside the app-managed Ghidra root.
        let decompile_cache = session.project_dir.join("decompile-cache");
        if decompile_cache.is_dir() {
            if let Err(error) = fs::remove_dir_all(&decompile_cache) {
                eprintln!(
                    "failed to clear stale decompile cache '{}': {error}",
                    decompile_cache.display()
                );
            }
        }

        Ok(ApplyRenamesResult { applied, imported })
    })();

    let _ = fs::remove_file(&request_path);
    let _ = fs::remove_file(&result_path);
    let _ = fs::remove_file(&refreshed_export_path);
    operation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installation() -> GhidraInstallation {
        GhidraInstallation {
            install_dir: PathBuf::from("C:/Tools/Ghidra"),
            version_label: "ghidra_12.1.2_PUBLIC".to_owned(),
            extensions_dir: PathBuf::from("C:/Users/test/Extensions/ReverseAssistantExporter"),
            java_home: None,
        }
    }

    fn session() -> AnalysisSession {
        AnalysisSession {
            project_dir: PathBuf::from("C:/AppData/ghidra-analysis/run-1"),
            project_name: "sample".to_owned(),
            program_path_in_project: "sample.exe".to_owned(),
        }
    }

    #[test]
    fn invocation_writes_a_live_project_and_never_uses_read_only() {
        let invocation = build_apply_renames_args(
            &installation(),
            &session(),
            Path::new("C:/tmp/request.json"),
            Path::new("C:/tmp/result.json"),
            Path::new("C:/tmp/export.json"),
        );
        assert!(invocation.args.contains(&"-noanalysis".to_owned()));
        assert!(!invocation.args.contains(&"-readOnly".to_owned()));
        assert!(invocation
            .args
            .contains(&APPLY_RENAMES_SCRIPT_NAME.to_owned()));
    }

    #[test]
    fn validation_trims_names_and_rejects_duplicates() {
        let normalized = validate_and_normalize_renames(&[FunctionRename {
            entry_address: "0x401000".to_owned(),
            new_name: "  authenticate_user  ".to_owned(),
        }])
        .expect("a valid rename should pass");
        assert_eq!(normalized[0].new_name, "authenticate_user");

        let duplicate = FunctionRename {
            entry_address: "0x401000".to_owned(),
            new_name: "one".to_owned(),
        };
        assert!(validate_and_normalize_renames(&[duplicate.clone(), duplicate]).is_err());

        let duplicate_target_name = [
            FunctionRename {
                entry_address: "0x401000".to_owned(),
                new_name: "same_name".to_owned(),
            },
            FunctionRename {
                entry_address: "0x402000".to_owned(),
                new_name: "same_name".to_owned(),
            },
        ];
        let error = validate_and_normalize_renames(&duplicate_target_name)
            .expect_err("a batch must not assign one target name twice");
        assert!(error.contains("duplicate target function name"));
    }

    #[test]
    fn result_count_must_match_the_atomic_request() {
        let error = parse_result(r#"{"schema_version":1,"applied":[]}"#, 1)
            .expect_err("a partial result must not be accepted");
        assert!(error.contains("0 applied renames but 1 were requested"));
    }
}
