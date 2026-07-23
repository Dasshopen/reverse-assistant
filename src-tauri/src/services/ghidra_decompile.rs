use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::models::ghidra_export::{is_valid_address, FunctionParameter};
use crate::models::ghidra_installation::GhidraInstallation;
use crate::models::ghidra_session::AnalysisSession;
use crate::services::ghidra_headless::{tail, HEADLESS_MAX_HEAP};
use crate::services::ghidra_installation::{load_persisted_install_dir, validate_installation};

const DECOMPILE_SCRIPT_NAME: &str = "DecompileFunctionJson.java";
const STDERR_TAIL_BYTES: usize = 4000;

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
) -> DecompileFunctionInvocation {
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
        "-readOnly".to_owned(),
        "-scriptPath".to_owned(),
        scripts_dir.to_string_lossy().into_owned(),
        "-postScript".to_owned(),
        DECOMPILE_SCRIPT_NAME.to_owned(),
        entry_address.to_owned(),
        destination_json.to_string_lossy().into_owned(),
    ];

    DecompileFunctionInvocation { program, args }
}

#[derive(Debug, Clone, Serialize)]
pub struct DecompiledFunctionDetails {
    pub decompiled_code: Option<String>,
    pub return_type: String,
    pub parameters: Vec<FunctionParameter>,
    pub calling_convention: String,
}

#[derive(Deserialize)]
struct DecompileResultJson {
    decompiled_code: Option<String>,
    return_type: String,
    parameters: Vec<FunctionParameter>,
    calling_convention: String,
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
) -> Result<DecompiledFunctionDetails, String> {
    validate_entry_address(entry_address)?;

    let cache_dir = session.project_dir.join("decompile-cache");

    fs::create_dir_all(&cache_dir).map_err(|error| {
        format!(
            "failed to create the decompile working directory '{}': {error}",
            cache_dir.display()
        )
    })?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            format!("system clock error while preparing a decompile request: {error}")
        })?
        .as_nanos();

    let destination_json = cache_dir.join(format!("{nanos}.json"));

    let invocation =
        build_decompile_function_args(installation, session, entry_address, &destination_json);

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

    let _ = fs::remove_file(&destination_json);

    let parsed: DecompileResultJson = serde_json::from_str(&json)
        .map_err(|error| format!("invalid decompile result JSON from Ghidra: {error}"))?;

    Ok(DecompiledFunctionDetails {
        decompiled_code: parsed.decompiled_code,
        return_type: parsed.return_type,
        parameters: parsed.parameters,
        calling_convention: parsed.calling_convention,
    })
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

    run_decompile_function(&installation, session, entry_address)
}
