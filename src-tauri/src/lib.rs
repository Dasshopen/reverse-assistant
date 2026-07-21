// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use std::path::Path;

use services::ghidra_import::{import_ghidra_export, GhidraImportSummary, ImportedGhidraExport};

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            get_backend_status,
            import_ghidra_export_summary,
            import_ghidra_export_details
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
