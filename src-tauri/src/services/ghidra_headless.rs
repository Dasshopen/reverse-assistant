use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Manager};

use crate::models::ghidra_identification::{parse_identifications, FunctionIdentification};
use crate::models::ghidra_installation::configure_java_environment;
use crate::models::ghidra_installation::GhidraInstallation;
use crate::models::ghidra_session::AnalysisSession;
use crate::services::ghidra_import::{import_ghidra_export, ImportedGhidraExport};
use crate::services::ghidra_installation::{load_persisted_install_dir, validate_installation};

const HEADLESS_SCRIPT_NAME: &str = "ExportReverseAssistantJson.java";
const IDENTIFY_FUNCTIONS_SCRIPT_NAME: &str = "IdentifyFunctionsJson.java";
const DISABLE_SLOW_ANALYZERS_SCRIPT_NAME: &str = "DisableSlowAnalyzers.java";
const STDERR_TAIL_BYTES: usize = 4000;

// analyzeHeadless.bat defaults to a 2G JVM heap (MAXMEM_DEFAULT in the script),
// unlike the interactive GUI launcher which sets no default cap. Large or
// heavily optimized binaries can hit significant GC pressure under 2G.
pub(crate) const HEADLESS_MAX_HEAP: &str = "8G";

#[derive(Debug, Clone, PartialEq)]
pub struct HeadlessAnalysisInvocation {
    pub program: PathBuf,
    pub args: Vec<String>,
}

pub fn build_headless_analysis_args(
    installation: &GhidraInstallation,
    project_dir: &Path,
    project_name: &str,
    binary_path: &Path,
    destination_json: &Path,
    identifications_json: &Path,
) -> HeadlessAnalysisInvocation {
    let program = installation
        .install_dir
        .join("support")
        .join("analyzeHeadless.bat");

    let scripts_dir = installation.extensions_dir.join("ghidra_scripts");

    let args = vec![
        project_dir.to_string_lossy().into_owned(),
        project_name.to_owned(),
        "-scriptPath".to_owned(),
        scripts_dir.to_string_lossy().into_owned(),
        "-preScript".to_owned(),
        DISABLE_SLOW_ANALYZERS_SCRIPT_NAME.to_owned(),
        "-import".to_owned(),
        binary_path.to_string_lossy().into_owned(),
        "-postScript".to_owned(),
        HEADLESS_SCRIPT_NAME.to_owned(),
        destination_json.to_string_lossy().into_owned(),
        "-postScript".to_owned(),
        IDENTIFY_FUNCTIONS_SCRIPT_NAME.to_owned(),
        identifications_json.to_string_lossy().into_owned(),
    ];

    HeadlessAnalysisInvocation { program, args }
}

fn sanitize_project_name(binary_path: &Path) -> String {
    let stem = binary_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("binary");

    let sanitized: String = stem
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.is_empty() {
        "binary".to_owned()
    } else {
        sanitized
    }
}

// Name of the app-data subdirectory holding every Ghidra project this app
// has ever created for an analysis run. services::project_storage relies
// on this being the single, authoritative root for "a directory this app
// manages" when it verifies a project's Ghidra directory before deleting
// it -- keep the two in sync via `ghidra_analysis_root_dir` rather than
// duplicating the directory name.
const GHIDRA_ANALYSIS_DIR_NAME: &str = "ghidra-analysis";

pub fn ghidra_analysis_root_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|dir| dir.join(GHIDRA_ANALYSIS_DIR_NAME))
        .map_err(|error| format!("unable to resolve the application data directory: {error}"))
}

pub fn prepare_run_directory(
    app: &AppHandle,
    binary_path: &Path,
) -> Result<(PathBuf, String), String> {
    let project_name = sanitize_project_name(binary_path);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock error while preparing an analysis run: {error}"))?
        .as_nanos();

    let run_id = format!("{project_name}-{nanos}");

    let run_dir = ghidra_analysis_root_dir(app)?.join(&run_id);

    fs::create_dir_all(&run_dir).map_err(|error| {
        format!(
            "failed to create the analysis working directory '{}': {error}",
            run_dir.display()
        )
    })?;

    Ok((run_dir, project_name))
}

pub(crate) fn tail(bytes: &[u8], max_bytes: usize) -> String {
    let start = bytes.len().saturating_sub(max_bytes);

    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

// analyzeHeadless's -process expects the bare file name of the previously
// imported program (confirmed by manual testing: a leading slash makes
// -process fail with "invalid filename specified").
fn program_path_in_project(binary_path: &Path) -> Result<String, String> {
    binary_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "unable to determine the file name of the analyzed binary: {}",
                binary_path.display()
            )
        })
}

pub fn run_headless_analysis(
    installation: &GhidraInstallation,
    app: &AppHandle,
    binary_path: &Path,
) -> Result<(PathBuf, PathBuf, AnalysisSession), String> {
    let (run_dir, project_name) = prepare_run_directory(app, binary_path)?;

    let destination_json = run_dir.join("export.json");
    let identifications_json = run_dir.join("identifications.json");

    let invocation = build_headless_analysis_args(
        installation,
        &run_dir,
        &project_name,
        binary_path,
        &destination_json,
        &identifications_json,
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
            "Ghidra headless analysis failed (exit code {:?}): {}",
            output.status.code(),
            tail(&output.stderr, STDERR_TAIL_BYTES)
        ));
    }

    if !destination_json.is_file() {
        return Err(format!(
            "Ghidra headless analysis completed but produced no export file at '{}'",
            destination_json.display()
        ));
    }

    if !identifications_json.is_file() {
        return Err(format!(
            "Ghidra headless analysis completed but produced no FunctionID identification file at '{}'",
            identifications_json.display()
        ));
    }

    let session = AnalysisSession {
        project_dir: run_dir,
        project_name,
        program_path_in_project: program_path_in_project(binary_path)?,
    };

    Ok((destination_json, identifications_json, session))
}

pub fn analyze_binary(
    app: &AppHandle,
    binary_path: &Path,
) -> Result<
    (
        ImportedGhidraExport,
        Vec<FunctionIdentification>,
        AnalysisSession,
    ),
    String,
> {
    let install_dir = load_persisted_install_dir(app)?.ok_or_else(|| {
        "No Ghidra installation is configured. Configure one before analyzing a binary.".to_owned()
    })?;

    let installation = validate_installation(app, &install_dir)?;

    if !binary_path.is_file() {
        return Err(format!(
            "the selected binary does not exist: {}",
            binary_path.display()
        ));
    }

    let (json_path, identifications_json_path, session) =
        run_headless_analysis(&installation, app, binary_path)?;

    let imported = import_ghidra_export(&json_path)?;

    let identifications_json = fs::read_to_string(&identifications_json_path).map_err(|error| {
        format!(
            "failed to read FunctionID identification results '{}': {error}",
            identifications_json_path.display()
        )
    })?;

    let identifications = parse_identifications(&identifications_json)?;

    Ok((imported, identifications, session))
}
