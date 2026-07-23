// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use tauri::AppHandle;

use models::ghidra_identification::FunctionIdentification;
use models::ghidra_installation::GhidraInstallation;
use models::ghidra_session::AnalysisSession;
use services::ghidra_decompile::{self, DecompiledFunctionDetails};
use services::ghidra_headless;
use services::ghidra_import::{import_ghidra_export, GhidraImportSummary, ImportedGhidraExport};
use services::ghidra_installation::{self, GhidraInstallationStatus};

#[derive(Debug, Clone, Serialize)]
struct AutomaticAnalysisResult {
    imported: ImportedGhidraExport,
    identifications: Vec<FunctionIdentification>,
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
fn import_ghidra_export_summary(path: String) -> Result<GhidraImportSummary, String> {
    let imported = import_ghidra_export(Path::new(&path))?;

    Ok(imported.summary)
}

#[tauri::command]
fn import_ghidra_export_details(path: String) -> Result<ImportedGhidraExport, String> {
    import_ghidra_export(Path::new(&path))
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
    binary_path: String,
) -> Result<AutomaticAnalysisResult, String> {
    let (imported, identifications, session) =
        ghidra_headless::analyze_binary(&app, Path::new(&binary_path))?;

    *session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())? = Some(session);

    Ok(AutomaticAnalysisResult {
        imported,
        identifications,
    })
}

#[tauri::command(async)]
fn decompile_function(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
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
    decompile_coordinator
        .run_exclusive(|| ghidra_decompile::decompile_function(&app, &session, &entry_address))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(None::<AnalysisSession>))
        .manage(DecompileCoordinator::default())
        .invoke_handler(tauri::generate_handler![
            get_backend_status,
            import_ghidra_export_summary,
            import_ghidra_export_details,
            configure_ghidra_installation,
            get_ghidra_installation_status,
            analyze_binary_with_ghidra,
            decompile_function
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
