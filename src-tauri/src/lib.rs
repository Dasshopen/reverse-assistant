// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
pub mod models;

#[tauri::command]
fn get_backend_status() -> String {
    String::from("Reverse Assistant Rust backend ready")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_backend_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
