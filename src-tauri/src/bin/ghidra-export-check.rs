// Read-only diagnostic for the Java exporter / Rust importer boundary.
use std::path::PathBuf;

use reverse_assistant_lib::services::ghidra_import::import_ghidra_export;

fn main() -> Result<(), String> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| "usage: ghidra-export-check <export.json>".to_owned())?;
    let imported = import_ghidra_export(&path)?;
    println!(
        "PASS {}: {} functions ({} decompiled), {} global strings",
        imported.export.program.name,
        imported.summary.function_count,
        imported.summary.decompiled_function_count,
        imported.export.strings.len(),
    );
    Ok(())
}
