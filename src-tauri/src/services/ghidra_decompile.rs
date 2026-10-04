use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::models::ghidra_export::{is_valid_address, FunctionParameter};
use crate::models::ghidra_installation::{configure_java_environment, GhidraInstallation};
use crate::models::ghidra_session::AnalysisSession;
use crate::services::bsim_corpus::{active_corpora, database_url, ActiveBsimCorpus};
use crate::services::ghidra_headless::{tail, HEADLESS_MAX_HEAP};
use crate::services::ghidra_installation::{load_persisted_install_dir, validate_installation};

const DECOMPILE_SCRIPT_NAME: &str = "DecompileFunctionJson.java";
const BATCH_DECOMPILE_SCRIPT_NAME: &str = "DecompileFunctionsJson.java";
const MAX_BATCH_FUNCTIONS: usize = 500;
const STDERR_TAIL_BYTES: usize = 4000;
// Bump this value whenever the Java result semantics change. Keeping the
// version in the file name makes persistent cached results safe across app
// upgrades without having to delete a user's analyzed Ghidra project.
const DECOMPILE_CACHE_VERSION: &str = "native-prototype-bsim-packs-v3";

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
    bsim_corpora: &[(String, String, String)],
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

    for (id, name, url) in bsim_corpora {
        args.extend([
            "--bsim-corpus".to_owned(),
            id.clone(),
            name.clone(),
            url.clone(),
        ]);
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedFunctionContext {
    pub entry_address: String,
    pub decompiled_code: Option<String>,
    pub return_type: String,
    pub parameters: Vec<FunctionParameter>,
    pub calling_convention: String,
    #[serde(default)]
    pub error: Option<String>,
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
    #[serde(default = "legacy_corpus_name")]
    pub corpus: String,
    pub similarity: f64,
    pub significance: f64,
}

fn legacy_corpus_name() -> String {
    "Corpus BSim historique".to_owned()
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

pub(crate) fn parse_decompile_result(json: &str) -> Result<DecompiledFunctionDetails, String> {
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

fn corpus_cache_key(corpora: &[ActiveBsimCorpus]) -> String {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    for corpus in corpora {
        hasher.update(corpus.id.as_bytes());
        hasher.update(corpus.path.to_string_lossy().as_bytes());
        if let Ok(metadata) = fs::metadata(&corpus.path) {
            hasher.update(metadata.len().to_le_bytes());
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                    hasher.update(duration.as_secs().to_le_bytes());
                }
            }
        }
    }
    let digest = hasher.finalize();
    digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decompile_cache_path(cache_dir: &Path, entry_address: &str, corpus_key: &str) -> PathBuf {
    cache_dir.join(format!(
        "{}-{DECOMPILE_CACHE_VERSION}-{corpus_key}.json",
        &entry_address[2..],
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
    bsim_corpora: &[ActiveBsimCorpus],
) -> Result<DecompiledFunctionDetails, String> {
    validate_entry_address(entry_address)?;

    let cache_dir = session.project_dir.join("decompile-cache");

    fs::create_dir_all(&cache_dir).map_err(|error| {
        format!(
            "failed to create the decompile working directory '{}': {error}",
            cache_dir.display()
        )
    })?;

    let corpus_key = corpus_cache_key(bsim_corpora);
    let destination_json = decompile_cache_path(&cache_dir, entry_address, &corpus_key);

    // A Ghidra analysis session is immutable during on-demand decompilation
    // (-readOnly and -noanalysis), so a result for this project/address can be
    // reused safely. This avoids paying the JVM startup cost again after the
    // first click or after restarting the Tauri application.
    if let Ok(json) = fs::read_to_string(&destination_json) {
        if let Ok(cached) = parse_decompile_result(&json) {
            // A missing corpus or a transient BSim failure must not become a
            // permanent cached result. Retry once a corpus is available;
            // successful matches (including an empty match list) stay cached.
            if should_reuse_cached_result(&cached, !bsim_corpora.is_empty()) {
                return Ok(cached);
            }
        }

        // Ignore an incomplete/corrupt cache entry and regenerate it below.
        let _ = fs::remove_file(&destination_json);
    }

    let bsim_arguments = bsim_corpora
        .iter()
        .map(|corpus| {
            Ok((
                corpus.id.clone(),
                corpus.name.clone(),
                database_url(&corpus.path)?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let invocation = build_decompile_function_args(
        installation,
        session,
        entry_address,
        &destination_json,
        &bsim_arguments,
    );

    let mut command = Command::new(&invocation.program);
    command
        .args(&invocation.args)
        .env("GHIDRA_HEADLESS_MAXMEM", HEADLESS_MAX_HEAP);
    configure_java_environment(&mut command, installation);
    let output = command.output().map_err(|error| {
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

    let bsim_corpora = active_corpora(app).unwrap_or_default();

    run_decompile_function(&installation, session, entry_address, &bsim_corpora)
}

pub fn prepare_function_contexts(
    app: &AppHandle,
    session: &AnalysisSession,
    entry_addresses: &[String],
) -> Result<Vec<PreparedFunctionContext>, String> {
    if entry_addresses.is_empty() || entry_addresses.len() > MAX_BATCH_FUNCTIONS {
        return Err(format!(
            "the AI context batch must contain between 1 and {MAX_BATCH_FUNCTIONS} functions"
        ));
    }
    for address in entry_addresses {
        validate_entry_address(address)?;
    }

    let install_dir = load_persisted_install_dir(app)?
        .ok_or_else(|| "No Ghidra installation is configured.".to_owned())?;
    let installation = validate_installation(app, &install_dir)?;
    let work_dir = session.project_dir.join("ai-context");
    fs::create_dir_all(&work_dir).map_err(|error| {
        format!(
            "failed to create AI context directory '{}': {error}",
            work_dir.display()
        )
    })?;
    let request_path = work_dir.join("addresses.json");
    let destination = work_dir.join("decompiled-functions.json");
    fs::write(
        &request_path,
        serde_json::to_vec(entry_addresses)
            .map_err(|error| format!("failed to serialize AI context request: {error}"))?,
    )
    .map_err(|error| format!("failed to write AI context request: {error}"))?;
    if destination.is_file() {
        fs::remove_file(&destination)
            .map_err(|error| format!("failed to clear stale AI context result: {error}"))?;
    }

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
        .arg(BATCH_DECOMPILE_SCRIPT_NAME)
        .arg(&request_path)
        .arg(&destination)
        .env("GHIDRA_HEADLESS_MAXMEM", HEADLESS_MAX_HEAP);
    configure_java_environment(&mut command, &installation);
    let output = command
        .output()
        .map_err(|error| format!("failed to launch Ghidra batch decompilation: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Ghidra batch decompilation failed (exit code {:?}): {}",
            output.status.code(),
            tail(&output.stderr, STDERR_TAIL_BYTES)
        ));
    }
    let json = fs::read_to_string(&destination).map_err(|error| {
        format!(
            "failed to read AI context result '{}': {error}",
            destination.display()
        )
    })?;
    serde_json::from_str(&json)
        .map_err(|error| format!("invalid AI context JSON from Ghidra: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_is_stable_and_versioned() {
        assert_eq!(
            decompile_cache_path(Path::new("cache"), "0x140001170", "abc123"),
            PathBuf::from("cache/140001170-native-prototype-bsim-packs-v3-abc123.json")
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
            decompile_cache_path(&cache_dir, entry_address, &corpus_cache_key(&[])),
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
            java_home: None,
        };
        let session = AnalysisSession {
            project_dir: project_dir.clone(),
            project_name: "cached-test".to_owned(),
            program_path_in_project: "cached-test.exe".to_owned(),
        };

        let result = run_decompile_function(&installation, &session, entry_address, &[])
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
