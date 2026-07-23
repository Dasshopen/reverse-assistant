use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::models::ghidra_export::{is_valid_address, FunctionParameter};
use crate::models::ghidra_installation::GhidraInstallation;
use crate::models::ghidra_session::AnalysisSession;
use crate::services::bsim_corpus::{database_url, locate_available_corpus};
use crate::services::ghidra_headless::{tail, HEADLESS_MAX_HEAP};
use crate::services::ghidra_installation::{load_persisted_install_dir, validate_installation};

const DECOMPILE_SCRIPT_NAME: &str = "DecompileFunctionJson.java";
const STDERR_TAIL_BYTES: usize = 4000;
// Bump this value whenever the Java result semantics change. Keeping the
// version in the file name makes persistent cached results safe across app
// upgrades without having to delete a user's analyzed Ghidra project.
const DECOMPILE_CACHE_VERSION: &str = "native-prototype-bsim-v2";

#[derive(Debug, Clone, PartialEq)]
pub struct DecompileFunctionInvocation {
    pub program: PathBuf,
    pub args: Vec<String>,
}

pub fn build_decompile_function_args(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    entry_address: &str,
    destination_json: &Path,
    bsim_database_url: Option<&str>,
) -> DecompileFunctionInvocation {
    let program = installation
        .install_dir
        .join("support")
        .join("analyzeHeadless.bat");

    let scripts_dir = installation.extensions_dir.join("ghidra_scripts");

    let mut args = vec![
        session.project_dir.to_string_lossy().into_owned(),
        session.project_name.clone(),
        "-process".to_owned(),
        session.program_path_in_project.clone(),
        "-noanalysis".to_owned(),
        "-readOnly".to_owned(),
        "-scriptPath".to_owned(),
        scripts_dir.to_string_lossy().into_owned(),
        "-postScript".to_owned(),
        DECOMPILE_SCRIPT_NAME.to_owned(),
        entry_address.to_owned(),
        destination_json.to_string_lossy().into_owned(),
    ];

    if let Some(url) = bsim_database_url {
        args.push(url.to_owned());
    }

    DecompileFunctionInvocation { program, args }
}

#[derive(Debug, Clone, Serialize)]
pub struct DecompiledFunctionDetails {
    pub decompiled_code: Option<String>,
    pub return_type: String,
    pub parameters: Vec<FunctionParameter>,
    pub calling_convention: String,
    pub bsim: BsimQueryResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BsimQueryResult {
    pub status: String,
    pub matches: Vec<BsimCandidate>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BsimCandidate {
    pub name: String,
    pub executable: String,
    pub similarity: f64,
    pub significance: f64,
}

#[derive(Deserialize)]
struct DecompileResultJson {
    decompiled_code: Option<String>,
    return_type: String,
    parameters: Vec<FunctionParameter>,
    calling_convention: String,
    bsim: BsimQueryResult,
}

impl From<DecompileResultJson> for DecompiledFunctionDetails {
    fn from(parsed: DecompileResultJson) -> Self {
        Self {
            decompiled_code: parsed.decompiled_code,
            return_type: parsed.return_type,
            parameters: parsed.parameters,
            calling_convention: parsed.calling_convention,
            bsim: parsed.bsim,
        }
    }
}

fn parse_decompile_result(json: &str) -> Result<DecompiledFunctionDetails, String> {
    serde_json::from_str::<DecompileResultJson>(json)
        .map(DecompiledFunctionDetails::from)
        .map_err(|error| format!("invalid decompile result JSON from Ghidra: {error}"))
}

fn should_reuse_cached_result(
    cached: &DecompiledFunctionDetails,
    bsim_database_available: bool,
) -> bool {
    !bsim_database_available || cached.bsim.status == "available"
}

fn decompile_cache_path(cache_dir: &Path, entry_address: &str) -> PathBuf {
    cache_dir.join(format!(
        "{}-{DECOMPILE_CACHE_VERSION}.json",
        &entry_address[2..]
    ))
}

fn validate_entry_address(entry_address: &str) -> Result<(), String> {
    if !is_valid_address(entry_address) {
        return Err(
            "entry_address must be a lowercase hexadecimal string beginning with 0x".to_owned(),
        );
    }

    Ok(())
}

pub fn run_decompile_function(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    entry_address: &str,
    bsim_database_path: Option<&Path>,
) -> Result<DecompiledFunctionDetails, String> {
    validate_entry_address(entry_address)?;

    let cache_dir = session.project_dir.join("decompile-cache");

    fs::create_dir_all(&cache_dir).map_err(|error| {
        format!(
            "failed to create the decompile working directory '{}': {error}",
            cache_dir.display()
        )
    })?;

    let destination_json = decompile_cache_path(&cache_dir, entry_address);

    // A Ghidra analysis session is immutable during on-demand decompilation
    // (-readOnly and -noanalysis), so a result for this project/address can be
    // reused safely. This avoids paying the JVM startup cost again after the
    // first click or after restarting the Tauri application.
    if let Ok(json) = fs::read_to_string(&destination_json) {
        if let Ok(cached) = parse_decompile_result(&json) {
            // A missing corpus or a transient BSim failure must not become a
            // permanent cached result. Retry once a corpus is available;
            // successful matches (including an empty match list) stay cached.
            if should_reuse_cached_result(&cached, bsim_database_path.is_some()) {
                return Ok(cached);
            }
        }

        // Ignore an incomplete/corrupt cache entry and regenerate it below.
        let _ = fs::remove_file(&destination_json);
    }

    let bsim_database_url = bsim_database_path.map(database_url).transpose()?;
    let invocation = build_decompile_function_args(
        installation,
        session,
        entry_address,
        &destination_json,
        bsim_database_url.as_deref(),
    );

    let output = Command::new(&invocation.program)
        .args(&invocation.args)
        .env("GHIDRA_HEADLESS_MAXMEM", HEADLESS_MAX_HEAP)
        .output()
        .map_err(|error| {
            format!(
                "failed to launch Ghidra headless analyzer '{}': {error}",
                invocation.program.display()
            )
        })?;

    if !output.status.success() {
        return Err(format!(
            "Ghidra on-demand decompilation failed (exit code {:?}): {}",
            output.status.code(),
            tail(&output.stderr, STDERR_TAIL_BYTES)
        ));
    }

    if !destination_json.is_file() {
        return Err(format!(
            "Ghidra on-demand decompilation completed but produced no result file at '{}'",
            destination_json.display()
        ));
    }

    let json = fs::read_to_string(&destination_json).map_err(|error| {
        format!(
            "failed to read the decompile result '{}': {error}",
            destination_json.display()
        )
    })?;

    parse_decompile_result(&json)
}

pub fn decompile_function(
    app: &AppHandle,
    session: &AnalysisSession,
    entry_address: &str,
) -> Result<DecompiledFunctionDetails, String> {
    let install_dir = load_persisted_install_dir(app)?.ok_or_else(|| {
        "No Ghidra installation is configured. Configure one before decompiling a function."
            .to_owned()
    })?;

    let installation = validate_installation(app, &install_dir)?;

    let bsim_database = locate_available_corpus(app).ok().flatten();

    run_decompile_function(
        &installation,
        session,
        entry_address,
        bsim_database.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_is_stable_and_versioned() {
        assert_eq!(
            decompile_cache_path(Path::new("cache"), "0x140001170"),
            PathBuf::from("cache/140001170-native-prototype-bsim-v2.json")
        );
    }

    #[test]
    fn parses_native_prototype_details() {
        let details = parse_decompile_result(
            r#"{
                "decompiled_code": "int example(int param_1) { return param_1; }",
                "return_type": "int",
                "parameters": [{ "name": "param_1", "data_type": "int" }],
                "calling_convention": "__cdecl",
                "bsim": {
                    "status": "available",
                    "matches": [{
                        "name": "example",
                        "executable": "sqlite3.dll",
                        "similarity": 0.91,
                        "significance": 42.0
                    }],
                    "message": null
                }
            }"#,
        )
        .expect("a valid native prototype result should parse");

        assert_eq!(details.return_type, "int");
        assert_eq!(details.calling_convention, "__cdecl");
        assert_eq!(details.parameters.len(), 1);
        assert_eq!(details.parameters[0].name, "param_1");
        assert_eq!(details.parameters[0].data_type, "int");
        assert_eq!(details.bsim.matches[0].name, "example");
    }

    #[test]
    fn cached_result_does_not_launch_ghidra() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock should be after the Unix epoch")
            .as_nanos();
        let project_dir = std::env::temp_dir().join(format!(
            "reverse-assistant-decompile-cache-test-{unique_suffix}"
        ));
        let cache_dir = project_dir.join("decompile-cache");
        fs::create_dir_all(&cache_dir).expect("the test cache directory should be created");

        let entry_address = "0x140001170";
        fs::write(
            decompile_cache_path(&cache_dir, entry_address),
            r#"{
                "decompiled_code": "int cached(void) { return 1; }",
                "return_type": "int",
                "parameters": [],
                "calling_convention": "__cdecl",
                "bsim": {
                    "status": "unavailable",
                    "matches": [],
                    "message": "The BSim seed corpus is not installed."
                }
            }"#,
        )
        .expect("the cached result should be written");

        let installation = GhidraInstallation {
            install_dir: PathBuf::from("Z:/this-ghidra-installation-does-not-exist"),
            version_label: "ghidra_12.1.2_PUBLIC".to_owned(),
            extensions_dir: PathBuf::from("Z:/this-extension-does-not-exist"),
        };
        let session = AnalysisSession {
            project_dir: project_dir.clone(),
            project_name: "cached-test".to_owned(),
            program_path_in_project: "cached-test.exe".to_owned(),
        };

        let result = run_decompile_function(&installation, &session, entry_address, None)
            .expect("a valid cached result should bypass the missing Ghidra executable");

        assert_eq!(result.return_type, "int");
        assert_eq!(result.calling_convention, "__cdecl");

        fs::remove_dir_all(&project_dir).expect("the isolated test directory should be removed");
    }

    #[test]
    fn cached_unavailable_result_is_not_reused_when_a_corpus_appears() {
        let parsed = parse_decompile_result(
            r#"{
                "decompiled_code": null,
                "return_type": "undefined",
                "parameters": [],
                "calling_convention": "unknown",
                "bsim": {
                    "status": "unavailable",
                    "matches": [],
                    "message": "The BSim seed corpus is not installed."
                }
            }"#,
        )
        .expect("the unavailable result should parse");

        assert!(should_reuse_cached_result(&parsed, false));
        assert!(!should_reuse_cached_result(&parsed, true));
    }
}
