// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use tauri::AppHandle;

use models::ghidra_export::GhidraExport;
use models::ghidra_identification::FunctionIdentification;
use models::ghidra_installation::GhidraInstallation;
use models::ghidra_session::AnalysisSession;
use models::project::ProjectMetadata;
use services::call_graph::{self, CallGraphDirection, CallGraphNeighborhood};
use services::comparison::{self, ProjectComparison};
use services::ghidra_decompile::{self, DecompiledFunctionDetails};
use services::ghidra_headless;
use services::ghidra_import::{import_ghidra_export, GhidraImportSummary, ImportedGhidraExport};
use services::ghidra_installation::{self, GhidraInstallationStatus};
use services::global_strings::{self, GlobalStringView};
use services::imports_exports::{self, ImportView};
use services::program_overview::{self, ProgramOverview};
use services::project_storage::{self, ProjectSummary};

#[derive(Debug, Clone, Serialize)]
struct AutomaticAnalysisResult {
    imported: ImportedGhidraExport,
    identifications: Vec<FunctionIdentification>,
}

#[derive(Debug, Clone, Serialize)]
struct LoadedProject {
    export: GhidraExport,
    project: ProjectSummary,
}

// Best-effort: a failure to persist a project as a local project must not
// fail the analysis/import the user is actively waiting on -- the data is
// still fully usable for the rest of this session either way, it just
// won't be reloadable in a future one.
fn auto_save_project(app: &AppHandle, export: &GhidraExport, session: Option<AnalysisSession>) {
    if let Err(error) = project_storage::save_project(app, &export.program.name, export, session) {
        eprintln!("failed to save this analysis as a local project: {error}");
    }
}

pub mod models;
pub mod services;

#[derive(Default)]
struct DecompileCoordinator(Mutex<()>);

impl DecompileCoordinator {
    fn run_exclusive<T>(&self, operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _guard = self
            .0
            .lock()
            .map_err(|_| "the Ghidra decompilation queue lock was poisoned".to_owned())?;

        operation()
    }
}

#[tauri::command]
fn get_backend_status() -> String {
    String::from("Reverse Assistant Rust backend ready")
}

#[tauri::command]
fn import_ghidra_export_summary(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    path: String,
) -> Result<GhidraImportSummary, String> {
    let imported = import_ghidra_export(Path::new(&path))?;
    store_export(&export_state, imported.export.clone())?;
    // A manual JSON import has no live Ghidra project behind it -- it can
    // only ever be a snapshot project.
    auto_save_project(&app, &imported.export, None);

    Ok(imported.summary)
}

#[tauri::command]
fn import_ghidra_export_details(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    path: String,
) -> Result<ImportedGhidraExport, String> {
    let imported = import_ghidra_export(Path::new(&path))?;
    store_export(&export_state, imported.export.clone())?;
    auto_save_project(&app, &imported.export, None);

    Ok(imported)
}

fn store_export(
    export_state: &tauri::State<'_, Mutex<Option<GhidraExport>>>,
    export: GhidraExport,
) -> Result<(), String> {
    *export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())? = Some(export);

    Ok(())
}

#[tauri::command]
fn configure_ghidra_installation(
    app: AppHandle,
    install_dir: String,
) -> Result<GhidraInstallation, String> {
    ghidra_installation::configure_and_persist(&app, Path::new(&install_dir))
}

#[tauri::command]
fn get_ghidra_installation_status(app: AppHandle) -> Result<GhidraInstallationStatus, String> {
    ghidra_installation::current_installation_status(&app)
}

#[tauri::command(async)]
fn analyze_binary_with_ghidra(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    binary_path: String,
) -> Result<AutomaticAnalysisResult, String> {
    let (imported, identifications, session) =
        ghidra_headless::analyze_binary(&app, Path::new(&binary_path))?;

    *session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())? = Some(session.clone());

    store_export(&export_state, imported.export.clone())?;
    auto_save_project(&app, &imported.export, Some(session));

    Ok(AutomaticAnalysisResult {
        imported,
        identifications,
    })
}

#[tauri::command]
fn get_call_graph(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    entry_address: String,
    direction: CallGraphDirection,
    max_depth: u32,
) -> Result<CallGraphNeighborhood, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its call graph."
            .to_owned()
    })?;

    call_graph::compute_neighborhood(export, &entry_address, direction, max_depth)
}

#[tauri::command]
fn get_global_strings(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<GlobalStringView>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its strings."
            .to_owned()
    })?;

    Ok(global_strings::build_global_strings_view(export))
}

#[tauri::command]
fn get_imports(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<ImportView>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its imports."
            .to_owned()
    })?;

    Ok(imports_exports::list_imports(export))
}

#[tauri::command]
fn get_external_entry_points(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<models::ghidra_export::ExternalEntryPoint>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its external entry points."
            .to_owned()
    })?;

    Ok(export.program.external_entry_points.clone())
}

#[tauri::command]
fn get_detected_types(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<models::ghidra_export::DetectedType>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its detected types."
            .to_owned()
    })?;

    Ok(export.types.clone())
}

#[tauri::command]
fn get_program_overview(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<ProgramOverview, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its overview."
            .to_owned()
    })?;

    Ok(program_overview::compute_overview(export))
}

#[tauri::command]
fn list_projects(app: AppHandle) -> Result<Vec<ProjectSummary>, String> {
    project_storage::list_projects(&app)
}

#[tauri::command]
fn open_project(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    id: String,
) -> Result<LoadedProject, String> {
    let (export, project) = project_storage::load_project(&app, &id)?;

    // Availability is re-tested fresh by `load_project` on every call, so
    // this never restores a session for Ghidra project files that aren't
    // actually there right now -- and never permanently forgets the
    // reference either, since `project.metadata.session` itself is left
    // untouched on disk.
    let session_to_restore = if project.session_available {
        project.metadata.session.clone()
    } else {
        None
    };

    *session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())? = session_to_restore;

    store_export(&export_state, export.clone())?;

    Ok(LoadedProject { export, project })
}

#[tauri::command]
fn delete_project(app: AppHandle, id: String) -> Result<(), String> {
    project_storage::delete_project(&app, &id)
}

#[tauri::command]
fn rename_project(app: AppHandle, id: String, new_name: String) -> Result<ProjectMetadata, String> {
    project_storage::rename_project(&app, &id, &new_name)
}

#[tauri::command]
fn compare_projects(
    app: AppHandle,
    project_a_id: String,
    project_b_id: String,
) -> Result<ProjectComparison, String> {
    if project_a_id == project_b_id {
        return Err("Select two different saved projects to compare.".to_owned());
    }

    // Comparison is deliberately read-only: loading either side here must
    // not replace the analysis currently open in the explorer.
    let (project_a, _) = project_storage::load_project(&app, &project_a_id)?;
    let (project_b, _) = project_storage::load_project(&app, &project_b_id)?;

    Ok(comparison::compare_projects(&project_a, &project_b))
}

#[tauri::command(async)]
fn decompile_function(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    decompile_coordinator: tauri::State<'_, DecompileCoordinator>,
    entry_address: String,
) -> Result<DecompiledFunctionDetails, String> {
    let session = session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| {
            "No Ghidra analysis session is active. Analyze a binary before requesting decompiled code.".to_owned()
        })?;

    // Ghidra takes an exclusive project lock even when analyzeHeadless opens
    // the program with -readOnly. Serialize requests so rapid function
    // selections wait their turn instead of failing with LockException.
    let details = decompile_coordinator
        .run_exclusive(|| ghidra_decompile::decompile_function(&app, &session, &entry_address))?;

    // Bulk export never populates `decompiled_code` (decompilation is
    // on-demand by design), so without this write-through the stored
    // export's copy would stay frozen at "nothing decompiled yet" forever
    // -- silently making `decompiled_function_count` in the overview
    // permanently wrong instead of tracking real progress.
    if let Some(decompiled_code) = &details.decompiled_code {
        let mut export = export_state
            .lock()
            .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

        if let Some(export) = export.as_mut() {
            if let Some(function) = export
                .functions
                .iter_mut()
                .find(|function| function.entry_address == entry_address)
            {
                function.decompiled_code = Some(decompiled_code.clone());
            }
        }
    }

    Ok(details)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(None::<AnalysisSession>))
        .manage(Mutex::new(None::<GhidraExport>))
        .manage(DecompileCoordinator::default())
        .invoke_handler(tauri::generate_handler![
            get_backend_status,
            import_ghidra_export_summary,
            import_ghidra_export_details,
            configure_ghidra_installation,
            get_ghidra_installation_status,
            analyze_binary_with_ghidra,
            decompile_function,
            get_call_graph,
            get_global_strings,
            get_imports,
            get_external_entry_points,
            get_detected_types,
            get_program_overview,
            list_projects,
            open_project,
            delete_project,
            rename_project,
            compare_projects
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    use super::DecompileCoordinator;

    #[test]
    fn decompile_coordinator_serializes_operations() {
        let coordinator = Arc::new(DecompileCoordinator::default());
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let (second_started_tx, second_started_rx) = mpsc::channel();

        let first_coordinator = Arc::clone(&coordinator);
        let first = thread::spawn(move || {
            first_coordinator.run_exclusive(|| {
                first_started_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
                Ok(())
            })
        });

        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the first operation should acquire the queue");

        let second_coordinator = Arc::clone(&coordinator);
        let second = thread::spawn(move || {
            second_coordinator.run_exclusive(|| {
                second_started_tx.send(()).unwrap();
                Ok(())
            })
        });

        assert!(
            second_started_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "the second operation must wait while the first owns the queue"
        );

        release_first_tx.send(()).unwrap();
        second_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the second operation should start after the first releases the queue");

        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    }
}
