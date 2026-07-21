use serde::Serialize;
use std::{fs, path::Path};

use crate::models::ghidra_export::GhidraExport;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GhidraImportSummary {
    pub function_count: usize,
    pub external_function_count: usize,
    pub decompiled_function_count: usize,
    pub call_count: usize,
    pub string_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportedGhidraExport {
    pub export: GhidraExport,
    pub summary: GhidraImportSummary,
}

pub fn import_ghidra_export(path: &Path) -> Result<ImportedGhidraExport, String> {
    let json = fs::read_to_string(path)
        .map_err(|error| format!("failed to read Ghidra export '{}': {error}", path.display()))?;

    let export = GhidraExport::parse_and_validate(&json)?;

    let summary = GhidraImportSummary {
        function_count: export.functions.len(),

        external_function_count: export
            .functions
            .iter()
            .filter(|function| function.is_external)
            .count(),

        decompiled_function_count: export
            .functions
            .iter()
            .filter(|function| function.decompiled_code.is_some())
            .count(),

        call_count: export
            .functions
            .iter()
            .map(|function| function.calls.len())
            .sum(),

        string_count: export
            .functions
            .iter()
            .map(|function| function.strings.len())
            .sum(),
    };

    Ok(ImportedGhidraExport { export, summary })
}
