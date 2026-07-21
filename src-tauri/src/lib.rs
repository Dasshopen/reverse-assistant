// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use std::path::Path;

use services::ghidra_import::{import_ghidra_export, GhidraImportSummary};

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_backend_status,
            import_ghidra_export_summary
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
