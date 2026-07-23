// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use std::path::Path;
use std::sync::Mutex;

use tauri::AppHandle;

use models::ghidra_installation::GhidraInstallation;
use models::ghidra_session::AnalysisSession;
use services::ghidra_decompile::{self, DecompiledFunctionDetails};
use services::ghidra_headless;
use services::ghidra_import::{import_ghidra_export, GhidraImportSummary, ImportedGhidraExport};
use services::ghidra_installation::{self, GhidraInstallationStatus};

pub mod models;
pub mod services;

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
) -> Result<ImportedGhidraExport, String> {
    let (imported, session) = ghidra_headless::analyze_binary(&app, Path::new(&binary_path))?;

    *session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())? = Some(session);

    Ok(imported)
}

#[tauri::command(async)]
fn decompile_function(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    entry_address: String,
) -> Result<DecompiledFunctionDetails, String> {
    let session = session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| {
            "No Ghidra analysis session is active. Analyze a binary before requesting decompiled code.".to_owned()
        })?;

    ghidra_decompile::decompile_function(&app, &session, &entry_address)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(None::<AnalysisSession>))
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
