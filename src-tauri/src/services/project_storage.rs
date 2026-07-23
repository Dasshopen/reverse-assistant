use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Manager};

use crate::models::ghidra_export::GhidraExport;
use crate::models::ghidra_session::AnalysisSession;
use crate::models::project::ProjectMetadata;

const PROJECTS_DIR_NAME: &str = "projects";
const PROJECT_METADATA_FILE_NAME: &str = "project.json";
const PROJECT_EXPORT_FILE_NAME: &str = "export.json";

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

pub fn list_projects(app: &AppHandle) -> Result<Vec<ProjectMetadata>, String> {
    list_projects_at(&real_projects_root_dir(app)?)
}

pub fn load_project(app: &AppHandle, id: &str) -> Result<(GhidraExport, ProjectMetadata), String> {
    load_project_at(&real_projects_root_dir(app)?, id)
}

pub fn delete_project(app: &AppHandle, id: &str) -> Result<(), String> {
    delete_project_at(&real_projects_root_dir(app)?, id)
}

pub fn rename_project(
    app: &AppHandle,
    id: &str,
    new_name: &str,
) -> Result<ProjectMetadata, String> {
    rename_project_at(&real_projects_root_dir(app)?, id, new_name)
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

fn save_project_at(
    root: &Path,
    name: &str,
    export: &GhidraExport,
    session: Option<AnalysisSession>,
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
    write_export(&dir, export)?;

    Ok(metadata)
}

fn write_metadata(dir: &Path, metadata: &ProjectMetadata) -> Result<(), String> {
    let json = serde_json::to_string_pretty(metadata)
        .map_err(|error| format!("failed to serialize project metadata: {error}"))?;

    fs::write(dir.join(PROJECT_METADATA_FILE_NAME), json)
        .map_err(|error| format!("failed to write project metadata: {error}"))
}

// The canonical `GhidraExport` only derives `Serialize` (see
// models::ghidra_export) -- exactly what's needed here, since this writes
// the same shape already sent to Svelte straight to disk.
fn write_export(dir: &Path, export: &GhidraExport) -> Result<(), String> {
    let json = serde_json::to_string(export)
        .map_err(|error| format!("failed to serialize the analysis export: {error}"))?;

    fs::write(dir.join(PROJECT_EXPORT_FILE_NAME), json)
        .map_err(|error| format!("failed to write the analysis export: {error}"))
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

fn list_projects_at(root: &Path) -> Result<Vec<ProjectMetadata>, String> {
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

        projects.push(read_metadata(&path)?);
    }

    // Newest first: the most likely project a user wants to reopen.
    projects.sort_by_key(|project| std::cmp::Reverse(project.created_at_unix_seconds));

    Ok(projects)
}

fn load_project_at(root: &Path, id: &str) -> Result<(GhidraExport, ProjectMetadata), String> {
    let dir = project_dir_at(root, id);

    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }

    let mut metadata = read_metadata(&dir)?;

    // A "live" project's extra usefulness (continued on-demand
    // decompilation) depends on its original Ghidra project files still
    // being on disk. If they were moved or deleted since saving, downgrade
    // to a snapshot rather than restoring a session that would just fail
    // the next decompile attempt -- and persist that downgrade so future
    // loads don't need to re-discover it every time.
    if let Some(session) = &metadata.session {
        if !ghidra_project_files_exist(session) {
            metadata.session = None;
            write_metadata(&dir, &metadata)?;
        }
    }

    let export_path = dir.join(PROJECT_EXPORT_FILE_NAME);
    let json = fs::read_to_string(&export_path).map_err(|error| {
        format!(
            "failed to read project export '{}': {error}",
            export_path.display()
        )
    })?;

    // Deliberately not `GhidraExport::parse_and_validate`: that entry point
    // is for real Ghidra-produced files and dispatches on `schema_version`
    // through the historical, strict Raw* wire types. This file was
    // written by `write_export` from the canonical shape itself (a
    // superset of the wire contract -- e.g. a function's derived
    // `strings`), so it's deserialized directly as that shape. `validate()`
    // still runs as a defense-in-depth check against a hand-edited or
    // corrupted cache file.
    let export: GhidraExport = serde_json::from_str(&json).map_err(|error| {
        format!(
            "invalid project export '{}': {error}",
            export_path.display()
        )
    })?;
    export.validate()?;

    Ok((export, metadata))
}

fn ghidra_project_files_exist(session: &AnalysisSession) -> bool {
    session
        .project_dir
        .join(format!("{}.gpr", session.project_name))
        .is_file()
}

fn delete_project_at(root: &Path, id: &str) -> Result<(), String> {
    let dir = project_dir_at(root, id);

    if !dir.is_dir() {
        return Err(format!("no saved project exists with id '{id}'"));
    }

    let metadata = read_metadata(&dir)?;

    // The Ghidra project belongs to this saved project, not to some
    // unrelated temp-file lifecycle -- deleting the project must not leave
    // it orphaned on disk forever.
    if let Some(session) = &metadata.session {
        if session.project_dir.is_dir() {
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

fn rename_project_at(root: &Path, id: &str, new_name: &str) -> Result<ProjectMetadata, String> {
    if new_name.trim().is_empty() {
        return Err("project name must not be empty".to_owned());
    }

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

        let (loaded_export, loaded_metadata) =
            load_project_at(&root, &saved.id).expect("loading the saved project should succeed");
        assert_eq!(loaded_export, export);
        assert_eq!(loaded_metadata, saved);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn a_live_session_survives_reload_when_its_ghidra_project_still_exists() {
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

        let (_, loaded_metadata) =
            load_project_at(&root, &saved.id).expect("loading the live project should succeed");
        assert_eq!(loaded_metadata.session, Some(session));

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
        fs::remove_dir_all(&ghidra_project_dir)
            .expect("the isolated fake Ghidra project directory should be removed");
    }

    #[test]
    fn a_live_session_downgrades_to_a_snapshot_when_its_ghidra_project_is_gone() {
        let root = isolated_root("live-session-downgrades");
        // Deliberately never created -- simulates the Ghidra project having
        // been moved or deleted since the project was saved.
        let missing_ghidra_project_dir = isolated_root("live-session-downgrades-missing");

        let export = sample_export("sample.exe");
        let session = sample_session(&missing_ghidra_project_dir);

        let saved = save_project_at(&root, "Live Analysis", &export, Some(session))
            .expect("saving a live project should succeed");
        assert!(saved.session.is_some());

        let (_, loaded_metadata) = load_project_at(&root, &saved.id)
            .expect("loading should still succeed, just as a snapshot");
        assert_eq!(loaded_metadata.session, None);

        // The downgrade must be persisted -- loading again should not need
        // to "rediscover" the missing Ghidra project every time.
        let (_, reloaded_metadata) =
            load_project_at(&root, &saved.id).expect("loading a second time should succeed");
        assert_eq!(reloaded_metadata.session, None);

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
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
        if projects[0].created_at_unix_seconds != projects[1].created_at_unix_seconds {
            assert_eq!(projects[0].id, second.id);
            assert_eq!(projects[1].id, first.id);
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
    fn delete_project_removes_its_directory_and_its_ghidra_project() {
        let root = isolated_root("delete-removes-both");
        let ghidra_project_dir = isolated_root("delete-removes-both-ghidra-project");
        fs::create_dir_all(&ghidra_project_dir).expect("the fake Ghidra project dir should exist");

        let export = sample_export("sample.exe");
        let session = sample_session(&ghidra_project_dir);
        let saved = save_project_at(&root, "To Delete", &export, Some(session))
            .expect("saving should succeed");

        delete_project_at(&root, &saved.id).expect("deleting should succeed");

        assert!(!project_dir_at(&root, &saved.id).is_dir());
        assert!(!ghidra_project_dir.is_dir());

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn delete_project_of_a_snapshot_only_removes_its_own_directory() {
        let root = isolated_root("delete-snapshot-only");
        let export = sample_export("sample.exe");
        let saved =
            save_project_at(&root, "Snapshot", &export, None).expect("saving should succeed");

        delete_project_at(&root, &saved.id).expect("deleting should succeed");

        assert!(!project_dir_at(&root, &saved.id).is_dir());

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
    }

    #[test]
    fn deleting_an_unknown_project_id_is_an_error() {
        let root = isolated_root("delete-unknown");
        fs::create_dir_all(&root).expect("the isolated root should be created");

        let error = delete_project_at(&root, "does-not-exist")
            .expect_err("deleting an unknown id should fail");
        assert!(error.contains("does-not-exist"));

        fs::remove_dir_all(&root).expect("the isolated test directory should be removed");
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
        assert_eq!(reloaded.name, "New Name");

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
}
