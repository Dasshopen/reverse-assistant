use std::fs;
use std::io::{Read, Write};
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::models::ghidra_export::GhidraExport;
use crate::models::ghidra_identification::{parse_identifications, FunctionIdentification};
use crate::models::ghidra_session::AnalysisSession;
use crate::models::project::ProjectMetadata;
use crate::services::ghidra_headless::ghidra_analysis_root_dir;
use crate::services::naming_arbitration::StoredArbitrationOutcome;
use crate::services::naming_generation::{StoredGenerationDiagnostic, StoredGenerationOutcome};

const PROJECTS_DIR_NAME: &str = "projects";
const PROJECT_METADATA_FILE_NAME: &str = "project.json";
const PROJECT_EXPORT_FILE_NAME: &str = "export.json";
const PROJECT_DATA_ARCHIVE_FILE_NAME: &str = "analysis.zip";
const PROJECT_IDENTIFICATIONS_FILE_NAME: &str = "identifications.json";
const PROJECT_ARBITRATION_FILE_NAME: &str = "arbitration-results.json";
const PROJECT_GENERATION_FILE_NAME: &str = "generation-results.json";
const PROJECT_GENERATION_DIAGNOSTICS_FILE_NAME: &str = "generation-diagnostics.json";

// `metadata.session` is the permanent reference to a project's original
// Ghidra analysis; `session_available` is always computed fresh (never
// cached/persisted) by checking whether that Ghidra project is actually
// on disk right now. Keeping these separate is what makes the snapshot
// degradation reversible: a project whose Ghidra files are temporarily
// unavailable (an external drive unplugged, a directory moved and moved
// back, ...) becomes "live" again on a later open with no special
// recovery step, because the reference itself was never destroyed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProjectSummary {
    #[serde(flatten)]
    pub metadata: ProjectMetadata,
    pub session_available: bool,
}

fn summarize(metadata: ProjectMetadata) -> ProjectSummary {
    let session_available = metadata
        .session
        .as_ref()
        .is_some_and(ghidra_project_files_exist);

    ProjectSummary {
        metadata,
        session_available,
    }
}

fn real_projects_root_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|dir| dir.join(PROJECTS_DIR_NAME))
        .map_err(|error| format!("unable to resolve the application data directory: {error}"))
}

pub fn save_project(
    app: &AppHandle,
    name: &str,
    export: &GhidraExport,
    session: Option<AnalysisSession>,
) -> Result<ProjectMetadata, String> {
    save_project_at(&real_projects_root_dir(app)?, name, export, session)
}

pub fn save_project_with_identifications(
    app: &AppHandle,
    name: &str,
    export: &GhidraExport,
    session: Option<AnalysisSession>,
    identifications: &[FunctionIdentification],
) -> Result<ProjectMetadata, String> {
    save_project_at_with_identifications(
        &real_projects_root_dir(app)?,
        name,
        export,
        session,
        Some(identifications),
    )
}

pub fn list_projects(app: &AppHandle) -> Result<Vec<ProjectSummary>, String> {
    list_projects_at(&real_projects_root_dir(app)?)
}

pub fn load_project(app: &AppHandle, id: &str) -> Result<(GhidraExport, ProjectSummary), String> {
    load_project_at(&real_projects_root_dir(app)?, id)
}

pub fn load_project_with_identifications(
    app: &AppHandle,
    id: &str,
) -> Result<
    (
        GhidraExport,
        Option<Vec<FunctionIdentification>>,
        ProjectSummary,
    ),
    String,
> {
    load_project_at_with_identifications(&real_projects_root_dir(app)?, id)
}

pub fn delete_project(app: &AppHandle, id: &str) -> Result<(), String> {
    delete_project_at(
        &real_projects_root_dir(app)?,
        id,
        &ghidra_analysis_root_dir(app)?,
    )
}

pub fn rename_project(
    app: &AppHandle,
    id: &str,
    new_name: &str,
) -> Result<ProjectMetadata, String> {
    rename_project_at(&real_projects_root_dir(app)?, id, new_name)
}

pub fn replace_project_export(
    app: &AppHandle,
    id: &str,
    export: &GhidraExport,
) -> Result<(), String> {
    replace_project_export_at(&real_projects_root_dir(app)?, id, export)
}

pub fn replace_project_identifications(
    app: &AppHandle,
    id: &str,
    identifications: &[FunctionIdentification],
) -> Result<(), String> {
    replace_project_identifications_at(&real_projects_root_dir(app)?, id, identifications)
}

fn replace_project_identifications_at(
    root: &Path,
    id: &str,
    identifications: &[FunctionIdentification],
) -> Result<(), String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);
    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }
    let (export_json, _) = read_project_payload(&dir)?;
    let export: GhidraExport = serde_json::from_str(&export_json)
        .map_err(|error| format!("invalid saved project export: {error}"))?;
    export.validate()?;
    let arbitration = read_stored_arbitration(&dir)?;
    let generation = read_stored_generation(&dir)?;
    let diagnostics = read_stored_generation_diagnostics(&dir)?;
    write_project_archive(
        &dir,
        &export,
        Some(identifications),
        arbitration.as_deref(),
        generation.as_deref(),
        diagnostics.as_deref(),
    )
}

pub fn replace_project_arbitration(
    app: &AppHandle,
    id: &str,
    results: &[StoredArbitrationOutcome],
) -> Result<(), String> {
    replace_project_arbitration_at(&real_projects_root_dir(app)?, id, results)
}

fn replace_project_arbitration_at(
    root: &Path,
    id: &str,
    results: &[StoredArbitrationOutcome],
) -> Result<(), String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);
    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }
    let (export_json, archived_identifications) = read_project_payload(&dir)?;
    let export: GhidraExport = serde_json::from_str(&export_json)
        .map_err(|error| format!("invalid saved project export: {error}"))?;
    export.validate()?;
    let identifications = if archived_identifications.is_some() {
        archived_identifications
    } else {
        read_stored_identifications(&dir, None)?
    };
    let generation = read_stored_generation(&dir)?;
    let diagnostics = read_stored_generation_diagnostics(&dir)?;
    write_project_archive(
        &dir,
        &export,
        identifications.as_deref(),
        Some(results),
        generation.as_deref(),
        diagnostics.as_deref(),
    )
}

pub fn load_project_arbitration(
    app: &AppHandle,
    id: &str,
) -> Result<Vec<StoredArbitrationOutcome>, String> {
    load_project_arbitration_at(&real_projects_root_dir(app)?, id)
}

fn load_project_arbitration_at(
    root: &Path,
    id: &str,
) -> Result<Vec<StoredArbitrationOutcome>, String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);
    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }
    Ok(read_stored_arbitration(&dir)?.unwrap_or_default())
}

fn read_stored_arbitration(dir: &Path) -> Result<Option<Vec<StoredArbitrationOutcome>>, String> {
    let archive_path = dir.join(PROJECT_DATA_ARCHIVE_FILE_NAME);
    if !archive_path.is_file() {
        return Ok(None);
    }
    let file = fs::File::open(&archive_path).map_err(|error| {
        format!(
            "failed to open project archive '{}': {error}",
            archive_path.display()
        )
    })?;
    let mut archive = ZipArchive::new(file).map_err(|error| {
        format!(
            "invalid project archive '{}': {error}",
            archive_path.display()
        )
    })?;
    let result = match archive.by_name(PROJECT_ARBITRATION_FILE_NAME) {
        Ok(mut entry) => {
            let mut json = String::new();
            entry
                .read_to_string(&mut json)
                .map_err(|error| format!("failed to inflate arbitration results: {error}"))?;
            let results: Vec<StoredArbitrationOutcome> = serde_json::from_str(&json)
                .map_err(|error| format!("invalid stored arbitration results: {error}"))?;
            Ok(Some(results))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(error) => Err(format!("failed to read arbitration results: {error}")),
    };
    result
}

pub fn replace_project_generation(
    app: &AppHandle,
    id: &str,
    results: &[StoredGenerationOutcome],
) -> Result<(), String> {
    replace_project_generation_at(&real_projects_root_dir(app)?, id, results)
}

fn replace_project_generation_at(
    root: &Path,
    id: &str,
    results: &[StoredGenerationOutcome],
) -> Result<(), String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);
    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }
    let (export_json, archived_identifications) = read_project_payload(&dir)?;
    let export: GhidraExport = serde_json::from_str(&export_json)
        .map_err(|error| format!("invalid saved project export: {error}"))?;
    export.validate()?;
    let identifications = if archived_identifications.is_some() {
        archived_identifications
    } else {
        read_stored_identifications(&dir, None)?
    };
    let arbitration = read_stored_arbitration(&dir)?;
    let diagnostics = read_stored_generation_diagnostics(&dir)?;
    write_project_archive(
        &dir,
        &export,
        identifications.as_deref(),
        arbitration.as_deref(),
        Some(results),
        diagnostics.as_deref(),
    )
}

pub fn replace_project_generation_diagnostics(
    app: &AppHandle,
    id: &str,
    diagnostics: &[StoredGenerationDiagnostic],
) -> Result<(), String> {
    replace_project_generation_diagnostics_at(&real_projects_root_dir(app)?, id, diagnostics)
}

fn replace_project_generation_diagnostics_at(
    root: &Path,
    id: &str,
    diagnostics: &[StoredGenerationDiagnostic],
) -> Result<(), String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);
    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }
    let (export_json, archived_identifications) = read_project_payload(&dir)?;
    let export: GhidraExport = serde_json::from_str(&export_json)
        .map_err(|error| format!("invalid saved project export: {error}"))?;
    export.validate()?;
    let identifications = if archived_identifications.is_some() {
        archived_identifications
    } else {
        read_stored_identifications(&dir, None)?
    };
    let arbitration = read_stored_arbitration(&dir)?;
    let generation = read_stored_generation(&dir)?;
    write_project_archive(
        &dir,
        &export,
        identifications.as_deref(),
        arbitration.as_deref(),
        generation.as_deref(),
        Some(diagnostics),
    )
}

pub fn load_project_generation_diagnostics(
    app: &AppHandle,
    id: &str,
) -> Result<Vec<StoredGenerationDiagnostic>, String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(&real_projects_root_dir(app)?, id);
    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }
    Ok(read_stored_generation_diagnostics(&dir)?.unwrap_or_default())
}

fn read_stored_generation_diagnostics(
    dir: &Path,
) -> Result<Option<Vec<StoredGenerationDiagnostic>>, String> {
    let archive_path = dir.join(PROJECT_DATA_ARCHIVE_FILE_NAME);
    if !archive_path.is_file() {
        return Ok(None);
    }
    let file = fs::File::open(&archive_path).map_err(|error| {
        format!(
            "failed to open project archive '{}': {error}",
            archive_path.display()
        )
    })?;
    let mut archive = ZipArchive::new(file).map_err(|error| {
        format!(
            "invalid project archive '{}': {error}",
            archive_path.display()
        )
    })?;
    let result = match archive.by_name(PROJECT_GENERATION_DIAGNOSTICS_FILE_NAME) {
        Ok(mut entry) => {
            let mut json = String::new();
            entry
                .read_to_string(&mut json)
                .map_err(|error| format!("failed to inflate generation diagnostics: {error}"))?;
            let diagnostics: Vec<StoredGenerationDiagnostic> = serde_json::from_str(&json)
                .map_err(|error| format!("invalid stored generation diagnostics: {error}"))?;
            Ok(Some(compact_generation_diagnostics(diagnostics)))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(error) => Err(format!("failed to read generation diagnostics: {error}")),
    };
    result
}

fn generation_diagnostic_family(stage: &str) -> &str {
    if stage == "network" {
        "network"
    } else if stage.starts_with("contextual_") {
        "contextual"
    } else if stage.starts_with("initial_") || stage == "initial_generation" {
        "initial"
    } else {
        stage
    }
}

fn compact_generation_diagnostics(
    diagnostics: Vec<StoredGenerationDiagnostic>,
) -> Vec<StoredGenerationDiagnostic> {
    let mut compacted: Vec<StoredGenerationDiagnostic> = Vec::new();
    for diagnostic in diagnostics {
        let family = generation_diagnostic_family(&diagnostic.stage);
        let duplicate = compacted.iter_mut().rev().find(|existing| {
            existing.entry_address == diagnostic.entry_address
                && generation_diagnostic_family(&existing.stage) == family
                && existing
                    .created_at_unix_seconds
                    .abs_diff(diagnostic.created_at_unix_seconds)
                    <= 60
        });
        if let Some(existing) = duplicate {
            let diagnostic_has_raw = diagnostic.raw_response.is_some();
            if diagnostic_has_raw || existing.raw_response.is_none() {
                existing.validation_error = diagnostic.validation_error;
            }
            if diagnostic_has_raw {
                existing.raw_response = diagnostic.raw_response;
                existing.stage = diagnostic.stage;
            }
            existing.attempt = existing.attempt.max(diagnostic.attempt);
            existing.created_at_unix_seconds = existing
                .created_at_unix_seconds
                .max(diagnostic.created_at_unix_seconds);
        } else {
            compacted.push(diagnostic);
        }
    }
    compacted
}

pub fn load_project_generation(
    app: &AppHandle,
    id: &str,
) -> Result<Vec<StoredGenerationOutcome>, String> {
    load_project_generation_at(&real_projects_root_dir(app)?, id)
}

fn load_project_generation_at(
    root: &Path,
    id: &str,
) -> Result<Vec<StoredGenerationOutcome>, String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);
    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }
    Ok(read_stored_generation(&dir)?.unwrap_or_default())
}

fn read_stored_generation(dir: &Path) -> Result<Option<Vec<StoredGenerationOutcome>>, String> {
    let archive_path = dir.join(PROJECT_DATA_ARCHIVE_FILE_NAME);
    if !archive_path.is_file() {
        return Ok(None);
    }
    let file = fs::File::open(&archive_path).map_err(|error| {
        format!(
            "failed to open project archive '{}': {error}",
            archive_path.display()
        )
    })?;
    let mut archive = ZipArchive::new(file).map_err(|error| {
        format!(
            "invalid project archive '{}': {error}",
            archive_path.display()
        )
    })?;
    let result = match archive.by_name(PROJECT_GENERATION_FILE_NAME) {
        Ok(mut entry) => {
            let mut json = String::new();
            entry
                .read_to_string(&mut json)
                .map_err(|error| format!("failed to inflate generation results: {error}"))?;
            let results: Vec<StoredGenerationOutcome> = serde_json::from_str(&json)
                .map_err(|error| format!("invalid stored generation results: {error}"))?;
            Ok(Some(results))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(error) => Err(format!("failed to read generation results: {error}")),
    };
    result
}

fn replace_project_export_at(root: &Path, id: &str, export: &GhidraExport) -> Result<(), String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);
    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }
    export.validate()?;
    let identifications = read_stored_identifications(&dir, None)?;
    let arbitration = read_stored_arbitration(&dir)?;
    let generation = read_stored_generation(&dir)?;
    let diagnostics = read_stored_generation_diagnostics(&dir)?;
    write_project_archive(
        &dir,
        export,
        identifications.as_deref(),
        arbitration.as_deref(),
        generation.as_deref(),
        diagnostics.as_deref(),
    )
}

pub fn require_managed_session(app: &AppHandle, session: &AnalysisSession) -> Result<(), String> {
    require_managed_ghidra_project_dir(&session.project_dir, &ghidra_analysis_root_dir(app)?)
}

fn sanitize_name_for_id(name: &str) -> String {
    let sanitized: String = name
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
        "project".to_owned()
    } else {
        sanitized
    }
}

fn unix_time(context: &str) -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock error while {context}: {error}"))
}

fn generate_project_id(name: &str) -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock error while creating a project: {error}"))?
        .as_nanos();

    Ok(format!("{}-{nanos}", sanitize_name_for_id(name)))
}

fn project_dir_at(root: &Path, id: &str) -> PathBuf {
    root.join(id)
}

fn require_safe_project_id(id: &str) -> Result<(), String> {
    let mut components = Path::new(id).components();
    let is_single_normal_component =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();

    if id.is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id.contains(':')
        || !is_single_normal_component
    {
        return Err("invalid saved project id".to_owned());
    }

    Ok(())
}

fn save_project_at(
    root: &Path,
    name: &str,
    export: &GhidraExport,
    session: Option<AnalysisSession>,
) -> Result<ProjectMetadata, String> {
    save_project_at_with_identifications(root, name, export, session, None)
}

fn save_project_at_with_identifications(
    root: &Path,
    name: &str,
    export: &GhidraExport,
    session: Option<AnalysisSession>,
    identifications: Option<&[FunctionIdentification]>,
) -> Result<ProjectMetadata, String> {
    let id = generate_project_id(name)?;
    let dir = project_dir_at(root, &id);

    fs::create_dir_all(&dir).map_err(|error| {
        format!(
            "failed to create project directory '{}': {error}",
            dir.display()
        )
    })?;

    let metadata = ProjectMetadata {
        id: id.clone(),
        name: name.to_owned(),
        created_at_unix_seconds: unix_time("creating a project")?,
        session,
        program_name: export.program.name.clone(),
        program_format: export.program.format.clone(),
        program_architecture: export.program.architecture.clone(),
        function_count: export.functions.len(),
    };

    write_metadata(&dir, &metadata)?;
    write_project_archive(&dir, export, identifications, None, None, None)?;

    Ok(metadata)
}

fn write_metadata(dir: &Path, metadata: &ProjectMetadata) -> Result<(), String> {
    let json = serde_json::to_string_pretty(metadata)
        .map_err(|error| format!("failed to serialize project metadata: {error}"))?;

    fs::write(dir.join(PROJECT_METADATA_FILE_NAME), json)
        .map_err(|error| format!("failed to write project metadata: {error}"))
}

// The full analysis is compressed as one local archive. `project.json`
// intentionally stays outside it so listing projects never has to inflate
// a potentially large export. A present-but-empty identifications entry
// means FunctionID ran and found nothing; a missing entry means it never ran.
fn write_project_archive(
    dir: &Path,
    export: &GhidraExport,
    identifications: Option<&[FunctionIdentification]>,
    arbitration: Option<&[StoredArbitrationOutcome]>,
    generation: Option<&[StoredGenerationOutcome]>,
    diagnostics: Option<&[StoredGenerationDiagnostic]>,
) -> Result<(), String> {
    let export_json = serde_json::to_vec(export)
        .map_err(|error| format!("failed to serialize the analysis export: {error}"))?;
    let identifications_json = identifications
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|error| format!("failed to serialize FunctionID results: {error}"))?;
    let arbitration_json = arbitration
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|error| format!("failed to serialize arbitration results: {error}"))?;
    let generation_json = generation
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|error| format!("failed to serialize generation results: {error}"))?;
    let diagnostics_json = diagnostics
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|error| format!("failed to serialize generation diagnostics: {error}"))?;

    let archive_path = dir.join(PROJECT_DATA_ARCHIVE_FILE_NAME);
    let temporary_path = dir.join(format!("{PROJECT_DATA_ARCHIVE_FILE_NAME}.tmp"));
    let file = fs::File::create(&temporary_path).map_err(|error| {
        format!(
            "failed to create project archive '{}': {error}",
            temporary_path.display()
        )
    })?;
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut archive = ZipWriter::new(file);
    archive
        .start_file(PROJECT_EXPORT_FILE_NAME, options)
        .map_err(|error| format!("failed to start the export archive entry: {error}"))?;
    archive
        .write_all(&export_json)
        .map_err(|error| format!("failed to compress the analysis export: {error}"))?;
    if let Some(json) = identifications_json {
        archive
            .start_file(PROJECT_IDENTIFICATIONS_FILE_NAME, options)
            .map_err(|error| format!("failed to start the FunctionID archive entry: {error}"))?;
        archive
            .write_all(&json)
            .map_err(|error| format!("failed to compress FunctionID results: {error}"))?;
    }
    if let Some(json) = arbitration_json {
        archive
            .start_file(PROJECT_ARBITRATION_FILE_NAME, options)
            .map_err(|error| format!("failed to start the arbitration archive entry: {error}"))?;
        archive
            .write_all(&json)
            .map_err(|error| format!("failed to compress arbitration results: {error}"))?;
    }
    if let Some(json) = generation_json {
        archive
            .start_file(PROJECT_GENERATION_FILE_NAME, options)
            .map_err(|error| format!("failed to start the generation archive entry: {error}"))?;
        archive
            .write_all(&json)
            .map_err(|error| format!("failed to compress generation results: {error}"))?;
    }
    if let Some(json) = diagnostics_json {
        archive
            .start_file(PROJECT_GENERATION_DIAGNOSTICS_FILE_NAME, options)
            .map_err(|error| {
                format!("failed to start the generation diagnostics entry: {error}")
            })?;
        archive
            .write_all(&json)
            .map_err(|error| format!("failed to compress generation diagnostics: {error}"))?;
    }
    archive
        .finish()
        .map_err(|error| format!("failed to finish the project archive: {error}"))?;

    if archive_path.is_file() {
        fs::remove_file(&archive_path).map_err(|error| {
            format!(
                "failed to replace project archive '{}': {error}",
                archive_path.display()
            )
        })?;
    }
    fs::rename(&temporary_path, &archive_path).map_err(|error| {
        format!(
            "failed to install project archive '{}': {error}",
            archive_path.display()
        )
    })?;
    Ok(())
}

fn read_metadata(dir: &Path) -> Result<ProjectMetadata, String> {
    let path = dir.join(PROJECT_METADATA_FILE_NAME);
    let json = fs::read_to_string(&path).map_err(|error| {
        format!(
            "failed to read project metadata '{}': {error}",
            path.display()
        )
    })?;

    serde_json::from_str(&json)
        .map_err(|error| format!("invalid project metadata '{}': {error}", path.display()))
}

fn list_projects_at(root: &Path) -> Result<Vec<ProjectSummary>, String> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(root).map_err(|error| {
        format!(
            "failed to read projects directory '{}': {error}",
            root.display()
        )
    })?;

    let mut projects = Vec::new();

    for entry in entries {
        let entry =
            entry.map_err(|error| format!("failed to read a projects directory entry: {error}"))?;
        let path = entry.path();

        if !path.is_dir() || !path.join(PROJECT_METADATA_FILE_NAME).is_file() {
            continue;
        }

        projects.push(summarize(read_metadata(&path)?));
    }

    // Newest first: the most likely project a user wants to reopen.
    projects.sort_by_key(|project| std::cmp::Reverse(project.metadata.created_at_unix_seconds));

    Ok(projects)
}

fn load_project_at(root: &Path, id: &str) -> Result<(GhidraExport, ProjectSummary), String> {
    let (export, _, summary) = load_project_at_with_identifications(root, id)?;
    Ok((export, summary))
}

fn load_project_at_with_identifications(
    root: &Path,
    id: &str,
) -> Result<
    (
        GhidraExport,
        Option<Vec<FunctionIdentification>>,
        ProjectSummary,
    ),
    String,
> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);

    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }

    // Availability is re-tested on every open, never cached: `metadata`
    // itself is never mutated or rewritten here, so a project whose
    // Ghidra files are temporarily missing keeps its reference and can
    // become "live" again automatically the moment those files reappear.
    let summary = summarize(read_metadata(&dir)?);

    let (json, archived_identifications) = read_project_payload(&dir)?;

    // Deliberately not `GhidraExport::parse_and_validate`: that entry point
    // is for real Ghidra-produced files and dispatches on `schema_version`
    // through the historical, strict Raw* wire types. This file was
    // written by `write_export` from the canonical shape itself (a
    // superset of the wire contract -- e.g. a function's derived
    // `strings`), so it's deserialized directly as that shape. `validate()`
    // still runs as a defense-in-depth check against a hand-edited or
    // corrupted cache file.
    let export: GhidraExport = serde_json::from_str(&json)
        .map_err(|error| format!("invalid saved project export: {error}"))?;
    export.validate()?;

    let identifications = if archived_identifications.is_some() {
        archived_identifications
    } else {
        read_stored_identifications(&dir, summary.metadata.session.as_ref())?
    };

    Ok((export, identifications, summary))
}

fn read_project_payload(
    dir: &Path,
) -> Result<(String, Option<Vec<FunctionIdentification>>), String> {
    let archive_path = dir.join(PROJECT_DATA_ARCHIVE_FILE_NAME);
    if archive_path.is_file() {
        let file = fs::File::open(&archive_path).map_err(|error| {
            format!(
                "failed to open project archive '{}': {error}",
                archive_path.display()
            )
        })?;
        let mut archive = ZipArchive::new(file).map_err(|error| {
            format!(
                "invalid project archive '{}': {error}",
                archive_path.display()
            )
        })?;
        let mut export_json = String::new();
        archive
            .by_name(PROJECT_EXPORT_FILE_NAME)
            .map_err(|error| format!("project archive has no export entry: {error}"))?
            .read_to_string(&mut export_json)
            .map_err(|error| format!("failed to inflate the project export: {error}"))?;

        let identifications = match archive.by_name(PROJECT_IDENTIFICATIONS_FILE_NAME) {
            Ok(mut entry) => {
                let mut json = String::new();
                entry
                    .read_to_string(&mut json)
                    .map_err(|error| format!("failed to inflate FunctionID results: {error}"))?;
                Some(parse_identifications(&json)?)
            }
            Err(zip::result::ZipError::FileNotFound) => None,
            Err(error) => return Err(format!("failed to read FunctionID results: {error}")),
        };
        return Ok((export_json, identifications));
    }

    // Backward compatibility: projects created before compact archives used
    // a plain canonical export file. They remain fully readable.
    let export_path = dir.join(PROJECT_EXPORT_FILE_NAME);
    let json = fs::read_to_string(&export_path).map_err(|error| {
        format!(
            "failed to read project export '{}': {error}",
            export_path.display()
        )
    })?;
    Ok((json, None))
}

fn read_stored_identifications(
    dir: &Path,
    session: Option<&AnalysisSession>,
) -> Result<Option<Vec<FunctionIdentification>>, String> {
    let local_path = dir.join(PROJECT_IDENTIFICATIONS_FILE_NAME);
    let fallback_path =
        session.map(|value| value.project_dir.join(PROJECT_IDENTIFICATIONS_FILE_NAME));
    let path = if local_path.is_file() {
        Some(local_path)
    } else {
        fallback_path.filter(|candidate| candidate.is_file())
    };
    let Some(path) = path else { return Ok(None) };
    let json = fs::read_to_string(&path).map_err(|error| {
        format!(
            "failed to read FunctionID results '{}': {error}",
            path.display()
        )
    })?;
    parse_identifications(&json).map(Some)
}

fn ghidra_project_files_exist(session: &AnalysisSession) -> bool {
    session
        .project_dir
        .join(format!("{}.gpr", session.project_name))
        .is_file()
}

fn delete_project_at(root: &Path, id: &str, managed_ghidra_root: &Path) -> Result<(), String> {
    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);

    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }

    let metadata = read_metadata(&dir)?;

    // The Ghidra project belongs to this saved project, not to some
    // unrelated temp-file lifecycle -- deleting the project must not leave
    // it orphaned on disk forever. But `session.project_dir` came from a
    // JSON file on disk, not a value this call constructed itself -- if
    // `project.json` were ever corrupted or hand-edited, blindly
    // `remove_dir_all`-ing whatever path it names would be an arbitrary
    // filesystem deletion. Refuse the whole operation (delete nothing,
    // project included) unless the path canonically resolves to somewhere
    // inside the app's own managed Ghidra analysis root.
    if let Some(session) = &metadata.session {
        if session.project_dir.is_dir() {
            require_managed_ghidra_project_dir(&session.project_dir, managed_ghidra_root)?;

            fs::remove_dir_all(&session.project_dir).map_err(|error| {
                format!(
                    "failed to remove Ghidra project directory '{}': {error}",
                    session.project_dir.display()
                )
            })?;
        }
    }

    fs::remove_dir_all(&dir).map_err(|error| {
        format!(
            "failed to remove project directory '{}': {error}",
            dir.display()
        )
    })
}

// Canonicalizes both paths (resolving symlinks and `.`/`..` components) so
// containment can't be defeated by a symlink or a relative-path trick, then
// requires the target to be a genuine descendant of the managed root --
// never the root itself (a project's Ghidra directory is always one
// specific run's subdirectory, never the whole shared root).
fn require_managed_ghidra_project_dir(
    project_dir: &Path,
    managed_ghidra_root: &Path,
) -> Result<(), String> {
    let canonical_target = fs::canonicalize(project_dir).map_err(|error| {
        format!(
            "failed to resolve Ghidra project directory '{}': {error}",
            project_dir.display()
        )
    })?;

    let canonical_root = fs::canonicalize(managed_ghidra_root).map_err(|error| {
        format!(
            "failed to resolve the managed Ghidra analysis directory '{}': {error}",
            managed_ghidra_root.display()
        )
    })?;

    if canonical_target == canonical_root || !canonical_target.starts_with(&canonical_root) {
        return Err(format!(
            "refusing to delete '{}': it is not a Ghidra project directory managed by this application",
            project_dir.display()
        ));
    }

    Ok(())
}

fn rename_project_at(root: &Path, id: &str, new_name: &str) -> Result<ProjectMetadata, String> {
    if new_name.trim().is_empty() {
        return Err("project name must not be empty".to_owned());
    }

    require_safe_project_id(id)?;
    let dir = project_dir_at(root, id);

    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }

    let mut metadata = read_metadata(&dir)?;
    metadata.name = new_name.to_owned();
    write_metadata(&dir, &metadata)?;

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_export::{Endianness, ProgramMetadata};
    use crate::models::ghidra_identification::FidCandidate;

    fn isolated_root(test_name: &str) -> PathBuf {
        let unique_suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock should be after the Unix epoch")
            .as_nanos();

        std::env::temp_dir().join(format!(
            "reverse-assistant-project-storage-test-{test_name}-{unique_suffix}"
        ))
    }

    fn sample_export(program_name: &str) -> GhidraExport {
        GhidraExport {
            schema_version: 2,
            program: ProgramMetadata {
                name: program_name.to_owned(),
                sha256: "0".repeat(64),
                format: "PE".to_owned(),
                architecture: "x86_64".to_owned(),
                endianness: Endianness::Little,
                image_base: "0x140000000".to_owned(),
                external_entry_points: Vec::new(),
                required_libraries: Vec::new(),
            },
            functions: Vec::new(),
            strings: Vec::new(),
            types: Vec::new(),
        }
    }

    fn sample_session(project_dir: &Path) -> AnalysisSession {
        AnalysisSession {
            project_dir: project_dir.to_path_buf(),
            project_name: "sample".to_owned(),
            program_path_in_project: "sample.exe".to_owned(),
        }
    }

    // A stand-in for `app_data_dir/ghidra-analysis` -- every real
    // `session.project_dir` lives inside this in production.
    fn isolated_managed_ghidra_root(test_name: &str) -> PathBuf {
        isolated_root(&format!("{test_name}-managed-ghidra-root"))
    }

    #[test]
    fn project_ids_must_be_one_safe_path_component() {
        assert!(require_safe_project_id("sample-123456").is_ok());

        for unsafe_id in [
            "",
            ".",
            "..",
            "../outside",
            "..\\outside",
            "nested/project",
            "nested\\project",
            "C:\\Windows",
        ] {
            assert_eq!(
                require_safe_project_id(unsafe_id),
                Err("invalid saved project id".to_owned()),
                "'{unsafe_id}' must not escape or add nesting below the projects root"
            );
        }
    }

    // The synthetic fixtures above exercise the storage logic itself; this
    // uses a real, complex headless export (external entry points, thunks,
    // detected types with fields/usages, ...) to confirm the canonical
    // model's Serialize output is genuinely re-readable by
    // GhidraExport::parse_and_validate on the other side of a real disk
    // round-trip, not just structurally equal in memory.
    #[test]
    fn a_real_complex_export_round_trips_through_disk_unchanged() {
        const REAL_ELF_EXPORT_JSON: &str =
            include_str!("../../tests/fixtures/real-fauxware-export-v2.json");

        let root = isolated_root("real-export-round-trip");
        let export = GhidraExport::parse_and_validate(REAL_ELF_EXPORT_JSON)
            .expect("the real fixture should parse");

        let saved = save_project_at(&root, "fauxware", &export, None)
            .expect("saving a real export should succeed");
        assert_eq!(saved.function_count, export.functions.len());
        let raw_size = serde_json::to_vec(&export)
            .expect("the real export should serialize")
            .len() as u64;
        let archive_size =
            fs::metadata(project_dir_at(&root, &saved.id).join(PROJECT_DATA_ARCHIVE_FILE_NAME))
                .expect("the compact project archive should exist")
                .len();
        assert!(archive_size < raw_size, "the real export should compress");

        let (loaded_export, _) =
            load_project_at(&root, &saved.id).expect("loading the real export should succeed");
        assert_eq!(loaded_export, export);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn save_then_load_round_trips_a_snapshot_project() {
        let root = isolated_root("save-load-snapshot");
        let export = sample_export("sample.exe");

        let saved = save_project_at(&root, "My Analysis", &export, None)
            .expect("saving a project should succeed");
        assert_eq!(saved.name, "My Analysis");
        assert_eq!(saved.program_name, "sample.exe");
        assert_eq!(saved.session, None);

        let (loaded_export, loaded_summary) =
            load_project_at(&root, &saved.id).expect("loading the saved project should succeed");
        assert_eq!(loaded_export, export);
        assert_eq!(loaded_summary.metadata, saved);
        // A project that never had a session (a manual import) is simply
        // never "available" -- there's nothing to become available.
        assert!(!loaded_summary.session_available);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn compact_archive_round_trips_function_id_results_without_a_plain_export_copy() {
        let root = isolated_root("function-id-round-trip");
        let export = sample_export("identified.exe");
        let identifications = vec![FunctionIdentification {
            entry_address: "0x140001000".to_owned(),
            candidates: vec![FidCandidate {
                name: "memcpy".to_owned(),
                library_family: "visual studio".to_owned(),
                library_version: "2019".to_owned(),
                library_variant: "x64".to_owned(),
                overall_score: 42.5,
                match_mode: "FULL".to_owned(),
            }],
            bsim_candidates: Vec::new(),
            bsim_scanned: false,
            bsim_message: None,
        }];

        let saved = save_project_at_with_identifications(
            &root,
            "Identified",
            &export,
            None,
            Some(&identifications),
        )
        .expect("saving identified project should succeed");
        let project_dir = project_dir_at(&root, &saved.id);
        assert!(project_dir.join(PROJECT_DATA_ARCHIVE_FILE_NAME).is_file());
        assert!(!project_dir.join(PROJECT_EXPORT_FILE_NAME).exists());

        let (loaded_export, loaded_identifications, _) =
            load_project_at_with_identifications(&root, &saved.id)
                .expect("compact project should load");
        assert_eq!(loaded_export, export);
        assert_eq!(loaded_identifications, Some(identifications));

        fs::remove_dir_all(root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn an_empty_function_id_result_remains_distinct_from_function_id_not_run() {
        let root = isolated_root("empty-function-id");
        let export = sample_export("no-match.exe");
        let saved =
            save_project_at_with_identifications(&root, "No match", &export, None, Some(&[]))
                .expect("saving empty FunctionID result should succeed");

        let (_, loaded_identifications, _) = load_project_at_with_identifications(&root, &saved.id)
            .expect("empty FunctionID result should load");
        assert_eq!(loaded_identifications, Some(Vec::new()));

        fs::remove_dir_all(root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn legacy_plain_export_projects_remain_readable() {
        let root = isolated_root("legacy-plain-export");
        let export = sample_export("legacy.exe");
        let saved =
            save_project_at(&root, "Legacy", &export, None).expect("initial project should save");
        let project_dir = project_dir_at(&root, &saved.id);
        fs::remove_file(project_dir.join(PROJECT_DATA_ARCHIVE_FILE_NAME))
            .expect("test should remove the new archive");
        fs::write(
            project_dir.join(PROJECT_EXPORT_FILE_NAME),
            serde_json::to_vec(&export).expect("legacy export should serialize"),
        )
        .expect("legacy export should be written");

        let (loaded, identifications, _) = load_project_at_with_identifications(&root, &saved.id)
            .expect("legacy project should remain readable");
        assert_eq!(loaded, export);
        assert_eq!(identifications, None);

        fs::remove_dir_all(root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn replacing_a_project_export_is_durable() {
        let root = isolated_root("replace-export");
        let original = sample_export("before.exe");
        let saved = save_project_at(&root, "Editable", &original, None)
            .expect("the original project should save");

        let updated = sample_export("after.exe");
        replace_project_export_at(&root, &saved.id, &updated)
            .expect("the updated export should replace the snapshot");
        let (loaded, _) =
            load_project_at(&root, &saved.id).expect("the updated snapshot should remain readable");
        assert_eq!(loaded, updated);

        fs::remove_dir_all(root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn a_live_session_is_available_when_its_ghidra_project_still_exists() {
        let root = isolated_root("live-session-survives");
        let ghidra_project_dir = isolated_root("live-session-survives-ghidra-project");
        fs::create_dir_all(&ghidra_project_dir).expect("the fake Ghidra project dir should exist");
        fs::write(ghidra_project_dir.join("sample.gpr"), b"fake-gpr")
            .expect("the fake .gpr file should be written");

        let export = sample_export("sample.exe");
        let session = sample_session(&ghidra_project_dir);

        let saved = save_project_at(&root, "Live Analysis", &export, Some(session.clone()))
            .expect("saving a live project should succeed");
        assert_eq!(saved.session, Some(session.clone()));

        let (_, summary) =
            load_project_at(&root, &saved.id).expect("loading the live project should succeed");
        assert_eq!(summary.metadata.session, Some(session));
        assert!(summary.session_available);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
        fs::remove_dir_all(&ghidra_project_dir)
            .expect("the isolated fake Ghidra project directory should be removed");
    }

    // The core of the reversibility requirement: a live project whose
    // Ghidra files are temporarily missing must not lose its session
    // reference. `metadata.session` (the permanent reference) and
    // `session_available` (freshly re-tested on every load) are asserted
    // separately here on purpose.
    #[test]
    fn a_missing_ghidra_project_is_reported_unavailable_without_losing_the_session_reference() {
        let root = isolated_root("live-session-unavailable");
        // Deliberately never created -- simulates the Ghidra project having
        // been moved, deleted, or being on an unplugged external drive.
        let missing_ghidra_project_dir = isolated_root("live-session-unavailable-missing");

        let export = sample_export("sample.exe");
        let session = sample_session(&missing_ghidra_project_dir);

        let saved = save_project_at(&root, "Live Analysis", &export, Some(session.clone()))
            .expect("saving a live project should succeed");

        let (_, summary) = load_project_at(&root, &saved.id)
            .expect("loading should still succeed, just reported as unavailable");
        assert_eq!(summary.metadata.session, Some(session.clone()));
        assert!(!summary.session_available);

        // Nothing was rewritten to disk -- re-reading the persisted
        // metadata directly must still show the original, undisturbed
        // reference, not a nulled-out one.
        let metadata_on_disk = read_metadata(&project_dir_at(&root, &saved.id))
            .expect("reading the persisted metadata directly should succeed");
        assert_eq!(metadata_on_disk.session, Some(session));

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    // Proves the degradation is genuinely reversible, not just
    // non-destructive: once the Ghidra project reappears, a later load
    // reports it live again with no special recovery action needed.
    #[test]
    fn a_project_becomes_live_again_once_its_ghidra_project_reappears() {
        let root = isolated_root("live-session-recovers");
        let ghidra_project_dir = isolated_root("live-session-recovers-ghidra-project");
        // Deliberately not created until after the first load.

        let export = sample_export("sample.exe");
        let session = sample_session(&ghidra_project_dir);

        let saved = save_project_at(&root, "Live Analysis", &export, Some(session.clone()))
            .expect("saving should succeed");

        let (_, first_load) =
            load_project_at(&root, &saved.id).expect("the first load should succeed");
        assert!(!first_load.session_available);

        // The Ghidra project reappears (e.g. an external drive was
        // reconnected, or the directory was moved back into place).
        fs::create_dir_all(&ghidra_project_dir).expect("the fake Ghidra project dir should exist");
        fs::write(ghidra_project_dir.join("sample.gpr"), b"fake-gpr")
            .expect("the fake .gpr file should be written");

        let (_, second_load) =
            load_project_at(&root, &saved.id).expect("the second load should succeed");
        assert!(second_load.session_available);
        assert_eq!(second_load.metadata.session, Some(session));

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
        fs::remove_dir_all(&ghidra_project_dir)
            .expect("the isolated fake Ghidra project directory should be removed");
    }

    #[test]
    fn list_projects_reports_current_session_availability_per_project() {
        let root = isolated_root("list-reports-availability");
        let ghidra_project_dir = isolated_root("list-reports-availability-ghidra-project");
        fs::create_dir_all(&ghidra_project_dir).expect("the fake Ghidra project dir should exist");
        fs::write(ghidra_project_dir.join("sample.gpr"), b"fake-gpr")
            .expect("the fake .gpr file should be written");

        let live_export = sample_export("live.exe");
        let live = save_project_at(
            &root,
            "Live",
            &live_export,
            Some(sample_session(&ghidra_project_dir)),
        )
        .expect("saving the live project should succeed");

        let missing_ghidra_project_dir = isolated_root("list-reports-availability-missing");
        let unavailable_export = sample_export("unavailable.exe");
        let unavailable = save_project_at(
            &root,
            "Unavailable",
            &unavailable_export,
            Some(sample_session(&missing_ghidra_project_dir)),
        )
        .expect("saving the unavailable project should succeed");

        let snapshot_export = sample_export("snapshot.exe");
        let snapshot = save_project_at(&root, "Snapshot", &snapshot_export, None)
            .expect("saving the snapshot project should succeed");

        let projects = list_projects_at(&root).expect("listing should succeed");
        let find = |id: &str| {
            projects
                .iter()
                .find(|project| project.metadata.id == id)
                .expect("the project should be present in the listing")
        };

        assert!(find(&live.id).session_available);
        assert!(!find(&unavailable.id).session_available);
        assert!(!find(&snapshot.id).session_available);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
        fs::remove_dir_all(&ghidra_project_dir)
            .expect("the isolated fake Ghidra project directory should be removed");
    }

    #[test]
    fn list_projects_sorts_newest_first_and_ignores_unrelated_entries() {
        let root = isolated_root("list-sorts-newest-first");
        fs::create_dir_all(&root).expect("the isolated root should be created");

        // An unrelated directory with no project.json must be ignored, not
        // cause an error.
        fs::create_dir_all(root.join("not-a-project"))
            .expect("the unrelated directory should be created");

        let export = sample_export("first.exe");
        let first = save_project_at(&root, "First", &export, None).expect("first save");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let second_export = sample_export("second.exe");
        let second = save_project_at(&root, "Second", &second_export, None).expect("second save");

        let projects = list_projects_at(&root).expect("listing should succeed");

        assert_eq!(projects.len(), 2);
        // Newest first. If both saves landed in the same second, accept
        // either relative order rather than assert a flaky one.
        if projects[0].metadata.created_at_unix_seconds
            != projects[1].metadata.created_at_unix_seconds
        {
            assert_eq!(projects[0].metadata.id, second.id);
            assert_eq!(projects[1].metadata.id, first.id);
        }

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn list_projects_on_a_missing_root_is_an_empty_list_not_an_error() {
        let root = isolated_root("list-missing-root");

        let projects = list_projects_at(&root).expect("a missing root should list as empty");

        assert!(projects.is_empty());
    }

    #[test]
    fn delete_project_removes_its_directory_and_its_properly_contained_ghidra_project() {
        let root = isolated_root("delete-removes-both");
        let managed_ghidra_root = isolated_managed_ghidra_root("delete-removes-both");
        // Mirrors real usage: `session.project_dir` is always a
        // subdirectory of the managed root, never the root itself.
        let ghidra_project_dir = managed_ghidra_root.join("run-1");
        fs::create_dir_all(&ghidra_project_dir).expect("the fake Ghidra project dir should exist");

        let export = sample_export("sample.exe");
        let session = sample_session(&ghidra_project_dir);
        let saved = save_project_at(&root, "To Delete", &export, Some(session))
            .expect("saving should succeed");

        delete_project_at(&root, &saved.id, &managed_ghidra_root).expect("deleting should succeed");

        assert!(!project_dir_at(&root, &saved.id).is_dir());
        assert!(!ghidra_project_dir.is_dir());

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
        let _ = fs::remove_dir_all(&managed_ghidra_root);
    }

    #[test]
    fn delete_project_of_a_snapshot_only_removes_its_own_directory() {
        let root = isolated_root("delete-snapshot-only");
        let managed_ghidra_root = isolated_managed_ghidra_root("delete-snapshot-only");
        let export = sample_export("sample.exe");
        let saved =
            save_project_at(&root, "Snapshot", &export, None).expect("saving should succeed");

        delete_project_at(&root, &saved.id, &managed_ghidra_root).expect("deleting should succeed");

        assert!(!project_dir_at(&root, &saved.id).is_dir());

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn delete_project_of_a_live_project_whose_ghidra_directory_is_already_gone_succeeds() {
        let root = isolated_root("delete-live-already-gone");
        let managed_ghidra_root = isolated_managed_ghidra_root("delete-live-already-gone");
        fs::create_dir_all(&managed_ghidra_root).expect("the managed root should be created");

        // A "live" project (has a session reference) whose Ghidra project
        // directory was deleted by some other means after the fact -- e.g.
        // the user manually cleared the Ghidra analysis folder, or an
        // earlier `delete_project` run already removed it. This must not be
        // treated like the "unsafe external path" cases: `is_dir()` is false,
        // so the containment check and the Ghidra-directory removal are
        // both skipped entirely, and only the project's own local record is
        // removed.
        let ghidra_project_dir = managed_ghidra_root.join("run-already-gone");
        assert!(
            !ghidra_project_dir.exists(),
            "the Ghidra project directory must not exist for this test"
        );

        let export = sample_export("sample.exe");
        let session = sample_session(&ghidra_project_dir);
        let saved = save_project_at(&root, "Live But Orphaned", &export, Some(session))
            .expect("saving should succeed");

        delete_project_at(&root, &saved.id, &managed_ghidra_root).expect(
            "deleting a live project whose Ghidra directory is already gone should succeed",
        );

        assert!(!project_dir_at(&root, &saved.id).is_dir());

        fs::remove_dir_all(&root).expect("cleanup: root");
        fs::remove_dir_all(&managed_ghidra_root).expect("cleanup: managed root");
    }

    #[test]
    fn deleting_an_unknown_project_id_is_an_error() {
        let root = isolated_root("delete-unknown");
        let managed_ghidra_root = isolated_managed_ghidra_root("delete-unknown");
        fs::create_dir_all(&root).expect("the isolated root should be created");

        let error = delete_project_at(&root, "does-not-exist", &managed_ghidra_root)
            .expect_err("deleting an unknown id should fail");
        assert!(error.contains("does-not-exist"));

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn delete_project_refuses_to_remove_a_ghidra_project_outside_the_managed_root() {
        let root = isolated_root("delete-refuses-external");
        let managed_ghidra_root = isolated_managed_ghidra_root("delete-refuses-external");
        fs::create_dir_all(&managed_ghidra_root).expect("the managed root should be created");

        // Deliberately *not* under managed_ghidra_root -- simulates a
        // corrupted or hand-edited project.json pointing somewhere the
        // application never created.
        let external_dir = isolated_root("delete-refuses-external-victim");
        fs::create_dir_all(&external_dir).expect("the external directory should be created");
        fs::write(external_dir.join("do-not-delete-me.txt"), b"important")
            .expect("a marker file should be written");

        let export = sample_export("sample.exe");
        let session = sample_session(&external_dir);
        let saved = save_project_at(&root, "Suspicious", &export, Some(session))
            .expect("saving should succeed");

        let error = delete_project_at(&root, &saved.id, &managed_ghidra_root).expect_err(
            "deleting a project whose Ghidra directory sits outside the managed root should be refused",
        );
        assert!(error.contains("not a Ghidra project directory managed by this application"));

        // The whole operation is refused: neither the external directory
        // nor the project's own directory was touched.
        assert!(external_dir.join("do-not-delete-me.txt").is_file());
        assert!(project_dir_at(&root, &saved.id).is_dir());

        fs::remove_dir_all(&root).expect("cleanup: root");
        fs::remove_dir_all(&managed_ghidra_root).expect("cleanup: managed root");
        fs::remove_dir_all(&external_dir).expect("cleanup: external dir");
    }

    #[test]
    fn delete_project_refuses_a_dot_dot_path_that_escapes_the_managed_root() {
        let root = isolated_root("delete-refuses-traversal");
        let managed_ghidra_root = isolated_managed_ghidra_root("delete-refuses-traversal");
        fs::create_dir_all(&managed_ghidra_root).expect("the managed root should be created");

        let escape_target = isolated_root("delete-refuses-traversal-escape-target");
        fs::create_dir_all(&escape_target).expect("the escape target should be created");

        // Syntactically looks like it might be under the managed root, but
        // `..` walks straight back out of it once canonicalized -- a naive
        // string-prefix check on the raw path would be fooled by this.
        let traversal_path = managed_ghidra_root
            .join("..")
            .join(escape_target.file_name().expect("a file name"));
        assert!(
            traversal_path.is_dir(),
            "the traversal path should resolve to the real escape target directory"
        );

        let export = sample_export("sample.exe");
        let session = sample_session(&traversal_path);
        let saved = save_project_at(&root, "Traversal", &export, Some(session))
            .expect("saving should succeed");

        let error = delete_project_at(&root, &saved.id, &managed_ghidra_root).expect_err(
            "a `..`-escaping path must be refused, not naively accepted by a raw prefix check",
        );
        assert!(error.contains("not a Ghidra project directory managed by this application"));
        assert!(escape_target.is_dir());

        fs::remove_dir_all(&root).expect("cleanup: root");
        fs::remove_dir_all(&managed_ghidra_root).expect("cleanup: managed root");
        fs::remove_dir_all(&escape_target).expect("cleanup: escape target");
    }

    #[test]
    fn delete_project_refuses_the_managed_root_itself_as_a_project_directory() {
        let root = isolated_root("delete-refuses-root-itself");
        let managed_ghidra_root = isolated_managed_ghidra_root("delete-refuses-root-itself");
        fs::create_dir_all(&managed_ghidra_root).expect("the managed root should be created");

        let export = sample_export("sample.exe");
        // Pathological: `project_dir` IS the managed root, not one
        // specific run's subdirectory of it.
        let session = sample_session(&managed_ghidra_root);
        let saved = save_project_at(&root, "Root Itself", &export, Some(session))
            .expect("saving should succeed");

        let error = delete_project_at(&root, &saved.id, &managed_ghidra_root).expect_err(
            "the managed root itself must never be treated as a deletable project directory",
        );
        assert!(error.contains("not a Ghidra project directory managed by this application"));
        assert!(managed_ghidra_root.is_dir());

        fs::remove_dir_all(&root).expect("cleanup: root");
        fs::remove_dir_all(&managed_ghidra_root).expect("cleanup: managed root");
    }

    #[test]
    fn rename_project_updates_only_the_name() {
        let root = isolated_root("rename-updates-name");
        let export = sample_export("sample.exe");
        let saved =
            save_project_at(&root, "Old Name", &export, None).expect("saving should succeed");

        let renamed =
            rename_project_at(&root, &saved.id, "New Name").expect("renaming should succeed");

        assert_eq!(renamed.name, "New Name");
        assert_eq!(renamed.id, saved.id);
        assert_eq!(renamed.program_name, saved.program_name);

        let (_, reloaded) = load_project_at(&root, &saved.id).expect("reloading should succeed");
        assert_eq!(reloaded.metadata.name, "New Name");

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn rename_project_rejects_a_blank_name() {
        let root = isolated_root("rename-rejects-blank");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Original", &export, None).expect("saving");

        let error = rename_project_at(&root, &saved.id, "   ")
            .expect_err("a blank name should be rejected");
        assert!(error.contains("must not be empty"));

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    fn sample_arbitration(
        entry_address: &str,
        chosen_name: Option<&str>,
    ) -> StoredArbitrationOutcome {
        StoredArbitrationOutcome {
            entry_address: entry_address.to_owned(),
            chosen_name: chosen_name.map(str::to_owned),
            reasoning: "le contexte appelant/appele confirme ce choix".to_owned(),
            provider_label: "Ollama (local)".to_owned(),
            confidence: 90,
            evidence: vec!["appelant cohérent".to_owned()],
            context_complete: true,
            agent_version: crate::services::naming_arbitration::NAMING_PIPELINE_VERSION,
            semantic_fallback: None,
        }
    }

    #[test]
    fn a_freshly_saved_project_has_no_arbitration_results_yet() {
        let root = isolated_root("arbitration-none-yet");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Fresh", &export, None).expect("saving should succeed");

        let results = load_project_arbitration_at(&root, &saved.id)
            .expect("loading arbitration on a project that never had any should succeed");
        assert!(results.is_empty());

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn arbitration_results_round_trip_through_the_project_archive() {
        let root = isolated_root("arbitration-round-trip");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Arbitrated", &export, None).expect("saving");

        let mut fallback = sample_arbitration("0x140001090", None);
        fallback.semantic_fallback = Some(
            crate::services::naming_arbitration::SemanticFallbackOutcome {
                suggested_name: Some("memmove".to_owned()),
                reasoning: "copie arrière en cas de chevauchement".to_owned(),
                provider_label: "Ollama (local)".to_owned(),
                confidence: 91,
                evidence: vec!["comparaison des plages mémoire".to_owned()],
                manual_review_required: true,
            },
        );
        let results = vec![
            sample_arbitration("0x1400016b0", Some("NtCurrentTeb")),
            fallback,
        ];
        replace_project_arbitration_at(&root, &saved.id, &results)
            .expect("storing arbitration results should succeed");

        let loaded = load_project_arbitration_at(&root, &saved.id)
            .expect("loading the stored arbitration results should succeed");
        assert_eq!(loaded, results);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn a_later_arbitration_result_for_the_same_address_replaces_the_earlier_one() {
        let root = isolated_root("arbitration-replace-address");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Arbitrated", &export, None).expect("saving");

        replace_project_arbitration_at(&root, &saved.id, &[sample_arbitration("0x1", None)])
            .expect("storing the first arbitration result should succeed");
        replace_project_arbitration_at(
            &root,
            &saved.id,
            &[sample_arbitration("0x1", Some("resolved_name"))],
        )
        .expect("storing the updated arbitration result should succeed");

        let loaded = load_project_arbitration_at(&root, &saved.id).expect("loading should succeed");
        assert_eq!(
            loaded,
            vec![sample_arbitration("0x1", Some("resolved_name"))]
        );

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn replacing_the_export_preserves_existing_arbitration_results() {
        let root = isolated_root("arbitration-survives-export-replace");
        let original = sample_export("before.exe");
        let saved = save_project_at(&root, "Editable", &original, None).expect("saving");

        let results = vec![sample_arbitration("0x1", Some("resolved_name"))];
        replace_project_arbitration_at(&root, &saved.id, &results)
            .expect("storing arbitration results should succeed");

        let updated = sample_export("after.exe");
        replace_project_export_at(&root, &saved.id, &updated)
            .expect("replacing the export should succeed");

        let loaded = load_project_arbitration_at(&root, &saved.id)
            .expect("arbitration results should survive an export replace");
        assert_eq!(loaded, results);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn replacing_function_id_results_preserves_existing_arbitration_results() {
        let root = isolated_root("arbitration-survives-identifications-replace");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Editable", &export, None).expect("saving");

        let results = vec![sample_arbitration("0x1", Some("resolved_name"))];
        replace_project_arbitration_at(&root, &saved.id, &results)
            .expect("storing arbitration results should succeed");

        let identifications = vec![FunctionIdentification {
            entry_address: "0x1400016b0".to_owned(),
            candidates: vec![FidCandidate {
                name: "memcpy".to_owned(),
                library_family: "visual studio".to_owned(),
                library_version: "2019".to_owned(),
                library_variant: "x64".to_owned(),
                overall_score: 42.5,
                match_mode: "FULL".to_owned(),
            }],
            bsim_candidates: Vec::new(),
            bsim_scanned: false,
            bsim_message: None,
        }];
        replace_project_identifications_at(&root, &saved.id, &identifications)
            .expect("replacing identifications should succeed");

        let loaded = load_project_arbitration_at(&root, &saved.id)
            .expect("arbitration results should survive a FunctionID replace");
        assert_eq!(loaded, results);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    fn sample_generation(
        entry_address: &str,
        suggested_name: Option<&str>,
    ) -> StoredGenerationOutcome {
        StoredGenerationOutcome {
            entry_address: entry_address.to_owned(),
            suggested_name: suggested_name.map(str::to_owned),
            reasoning: "appelle CreateFileA avec un mode lecture".to_owned(),
            provider_label: "Ollama (local)".to_owned(),
            confidence: 75,
            evidence: vec!["appel CreateFileA".to_owned()],
            context_complete: true,
            agent_version: crate::services::naming_generation::NAMING_GENERATION_VERSION,
            analysis_pass: 1,
            verification_tier: crate::services::naming_generation::NameVerificationTier::default(),
            verifier_verdict: None,
            calibration_breakdowns: Vec::new(),
        }
    }

    fn sample_generation_diagnostic(entry_address: &str) -> StoredGenerationDiagnostic {
        StoredGenerationDiagnostic {
            entry_address: entry_address.to_owned(),
            stage: "contextual_repair".to_owned(),
            attempt: 2,
            validation_error: "the model repeated a rejected generic name".to_owned(),
            raw_response: Some("{\"suggested_name\":\"FUN_140001f20\"}".to_owned()),
            agent_version: crate::services::naming_generation::NAMING_GENERATION_VERSION,
            created_at_unix_seconds: 1_785_300_000,
        }
    }

    #[test]
    fn generation_diagnostics_round_trip_and_survive_result_updates() {
        let root = isolated_root("generation-diagnostics-round-trip");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Diagnosed", &export, None).expect("saving");
        let diagnostics = vec![sample_generation_diagnostic("0x140001f20")];

        replace_project_generation_diagnostics_at(&root, &saved.id, &diagnostics)
            .expect("storing diagnostics should succeed");
        replace_project_generation_at(
            &root,
            &saved.id,
            &[sample_generation("0x140009a10", Some("open_config_file"))],
        )
        .expect("updating results should preserve diagnostics");

        let dir = project_dir_at(&root, &saved.id);
        assert_eq!(
            read_stored_generation_diagnostics(&dir).expect("loading should succeed"),
            Some(diagnostics)
        );

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn backend_and_frontend_diagnostics_for_one_failure_are_compacted() {
        let mut raw = sample_generation_diagnostic("0x140001f20");
        raw.stage = "contextual_repair".to_owned();
        raw.created_at_unix_seconds = 100;
        let mut displayed = sample_generation_diagnostic("0x140001f20");
        displayed.stage = "contextual_refinement".to_owned();
        displayed.raw_response = None;
        displayed.created_at_unix_seconds = 101;

        let compacted = compact_generation_diagnostics(vec![raw.clone(), displayed]);

        assert_eq!(compacted.len(), 1);
        assert_eq!(compacted[0].stage, "contextual_repair");
        assert_eq!(compacted[0].raw_response, raw.raw_response);
        assert_eq!(compacted[0].created_at_unix_seconds, 101);
    }

    #[test]
    fn a_freshly_saved_project_has_no_generation_results_yet() {
        let root = isolated_root("generation-none-yet");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Fresh", &export, None).expect("saving should succeed");

        let results = load_project_generation_at(&root, &saved.id)
            .expect("loading generation on a project that never had any should succeed");
        assert!(results.is_empty());

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn generation_results_round_trip_through_the_project_archive() {
        let root = isolated_root("generation-round-trip");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Generated", &export, None).expect("saving");

        let results = vec![
            sample_generation("0x140009a10", Some("open_config_file")),
            sample_generation("0x140009a40", None),
        ];
        replace_project_generation_at(&root, &saved.id, &results)
            .expect("storing generation results should succeed");

        let loaded = load_project_generation_at(&root, &saved.id)
            .expect("loading the stored generation results should succeed");
        assert_eq!(loaded, results);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn the_verification_tier_survives_a_project_save_and_reopen() {
        use crate::services::naming_generation::{
            CalibrationBreakdown, EvidenceCategory, EvidenceStrength, NameVerificationTier,
            VerificationVerdict,
        };

        // sample_generation() always uses the default tier, which would not
        // catch a round trip that silently resets the field back to that
        // same default -- use a non-default value so a real loss is visible.
        let root = isolated_root("generation-tier-round-trip");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Generated", &export, None).expect("saving");

        let mut strong = sample_generation("0x140009a10", Some("open_config_file"));
        strong.verification_tier = NameVerificationTier::Strong;
        strong.calibration_breakdowns = vec![CalibrationBreakdown {
            provider_label: Some("Ollama (local)".to_owned()),
            formula: "legacy_min_v1".to_owned(),
            raw_agent_confidence: 60,
            verifier_confidence: Some(92),
            evidence_score: 75,
            final_score: 60,
            strongest_evidence: Some(EvidenceStrength::KnownApi),
            name_tokens: vec!["file".to_owned(), "open".to_owned()],
            covered_tokens: vec!["file".to_owned(), "open".to_owned()],
            unsupported_tokens: Vec::new(),
            independent_source_groups: 1,
            primary_categories: vec![EvidenceCategory::FileIo],
            secondary_categories: Vec::new(),
            secondary_only: false,
            deterministic_contradictions: Vec::new(),
            verifier_verdict: Some(VerificationVerdict::Supported),
            verifier_disagreement: false,
            verification_tier: NameVerificationTier::Supported,
        }];
        let mut partial = sample_generation("0x140009a40", Some("guess_name"));
        partial.verification_tier = NameVerificationTier::Partial;
        replace_project_generation_at(&root, &saved.id, &[strong.clone(), partial.clone()])
            .expect("storing generation results should succeed");

        let loaded = load_project_generation_at(&root, &saved.id)
            .expect("reopening the project should succeed");
        let reloaded_strong = loaded
            .iter()
            .find(|item| item.entry_address == "0x140009a10")
            .expect("the strong-tier result must still be present");
        let reloaded_partial = loaded
            .iter()
            .find(|item| item.entry_address == "0x140009a40")
            .expect("the partial-tier result must still be present");
        assert_eq!(
            reloaded_strong.verification_tier,
            NameVerificationTier::Strong
        );
        assert_eq!(
            reloaded_partial.verification_tier,
            NameVerificationTier::Partial
        );
        assert_eq!(
            reloaded_strong.calibration_breakdowns,
            strong.calibration_breakdowns
        );

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn a_later_generation_result_for_the_same_address_replaces_the_earlier_one() {
        let root = isolated_root("generation-replace-address");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Generated", &export, None).expect("saving");

        replace_project_generation_at(&root, &saved.id, &[sample_generation("0x1", None)])
            .expect("storing the first generation result should succeed");
        replace_project_generation_at(
            &root,
            &saved.id,
            &[sample_generation("0x1", Some("resolved_name"))],
        )
        .expect("storing the updated generation result should succeed");

        let loaded = load_project_generation_at(&root, &saved.id).expect("loading should succeed");
        assert_eq!(
            loaded,
            vec![sample_generation("0x1", Some("resolved_name"))]
        );

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn replacing_the_export_preserves_existing_generation_results() {
        let root = isolated_root("generation-survives-export-replace");
        let original = sample_export("before.exe");
        let saved = save_project_at(&root, "Editable", &original, None).expect("saving");

        let results = vec![sample_generation("0x1", Some("resolved_name"))];
        replace_project_generation_at(&root, &saved.id, &results)
            .expect("storing generation results should succeed");

        let updated = sample_export("after.exe");
        replace_project_export_at(&root, &saved.id, &updated)
            .expect("replacing the export should succeed");

        let loaded = load_project_generation_at(&root, &saved.id)
            .expect("generation results should survive an export replace");
        assert_eq!(loaded, results);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn replacing_function_id_results_preserves_existing_generation_results() {
        let root = isolated_root("generation-survives-identifications-replace");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Editable", &export, None).expect("saving");

        let results = vec![sample_generation("0x1", Some("resolved_name"))];
        replace_project_generation_at(&root, &saved.id, &results)
            .expect("storing generation results should succeed");

        let identifications = vec![FunctionIdentification {
            entry_address: "0x1400016b0".to_owned(),
            candidates: Vec::new(),
            bsim_candidates: Vec::new(),
            bsim_scanned: false,
            bsim_message: None,
        }];
        replace_project_identifications_at(&root, &saved.id, &identifications)
            .expect("replacing identifications should succeed");

        let loaded = load_project_generation_at(&root, &saved.id)
            .expect("generation results should survive a FunctionID replace");
        assert_eq!(loaded, results);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn replacing_arbitration_results_preserves_existing_generation_results_and_vice_versa() {
        let root = isolated_root("generation-and-arbitration-coexist");
        let export = sample_export("sample.exe");
        let saved = save_project_at(&root, "Editable", &export, None).expect("saving");

        let generation = vec![sample_generation("0x1", Some("resolved_name"))];
        replace_project_generation_at(&root, &saved.id, &generation)
            .expect("storing generation results should succeed");

        let arbitration = vec![sample_arbitration("0x2", Some("resolved_name"))];
        replace_project_arbitration_at(&root, &saved.id, &arbitration)
            .expect("storing arbitration results should succeed");

        assert_eq!(
            load_project_generation_at(&root, &saved.id)
                .expect("generation results should survive an arbitration replace"),
            generation
        );
        assert_eq!(
            load_project_arbitration_at(&root, &saved.id)
                .expect("arbitration results should still be readable"),
            arbitration
        );

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }
}
