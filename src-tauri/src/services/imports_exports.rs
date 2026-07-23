use serde::Serialize;

use crate::models::ghidra_export::GhidraExport;
use crate::services::call_graph::build_caller_index;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportView {
    pub entry_address: String,
    pub name: String,
    // Real DLL name for PE; always `None` for ELF (Ghidra doesn't attribute
    // individual ELF imports to their real .so -- see
    // GhidraExport.program.required_libraries for the whole-program list).
    pub library: Option<String>,
    pub used_by_function_count: usize,
}

// Every import already exists in `functions` (`is_external: true`); the
// only real gap was library attribution, already resolved by Ghidra during
// export. "Used by N functions" reuses the same caller index the call
// graph already builds and tests -- no new cross-referencing logic needed.
pub fn list_imports(export: &GhidraExport) -> Vec<ImportView> {
    let caller_index = build_caller_index(export);

    export
        .functions
        .iter()
        .filter(|function| function.is_external)
        .map(|function| ImportView {
            entry_address: function.entry_address.clone(),
            name: function.name.clone(),
            library: function.library.clone(),
            used_by_function_count: caller_index
                .get(function.entry_address.as_str())
                .map_or(0, Vec::len),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_export::{
        Endianness, FunctionCall, FunctionParameter, ProgramMetadata,
    };

    fn function(
        entry_address: &str,
        name: &str,
        is_external: bool,
        library: Option<&str>,
        calls: &[&str],
    ) -> crate::models::ghidra_export::GhidraFunction {
        crate::models::ghidra_export::GhidraFunction {
            entry_address: entry_address.to_owned(),
            name: name.to_owned(),
            return_type: "void".to_owned(),
            parameters: Vec::<FunctionParameter>::new(),
            is_external,
            is_thunk: false,
            decompiled_code: None,
            calls: calls
                .iter()
                .map(|target| FunctionCall {
                    target_address: Some((*target).to_owned()),
                    target_name: format!("callee-{target}"),
                })
                .collect(),
            strings: Vec::new(),
            library: library.map(str::to_owned),
        }
    }

    fn export(functions: Vec<crate::models::ghidra_export::GhidraFunction>) -> GhidraExport {
        GhidraExport {
            schema_version: 2,
            program: ProgramMetadata {
                name: "fixture.dll".to_owned(),
                sha256: "0".repeat(64),
                format: "PE".to_owned(),
                architecture: "x86_64".to_owned(),
                endianness: Endianness::Little,
                image_base: "0x140000000".to_owned(),
                external_entry_points: Vec::new(),
                required_libraries: Vec::new(),
            },
            functions,
            strings: Vec::new(),
        }
    }

    #[test]
    fn import_with_a_real_library_and_no_callers() {
        let data = export(vec![function(
            "0x1",
            "CreateFileW",
            true,
            Some("KERNEL32.DLL"),
            &[],
        )]);

        let imports = list_imports(&data);

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].library.as_deref(), Some("KERNEL32.DLL"));
        assert_eq!(imports[0].used_by_function_count, 0);
    }

    #[test]
    fn elf_style_import_has_no_library() {
        let data = export(vec![function("0x1", "strcmp", true, None, &[])]);

        let imports = list_imports(&data);

        assert_eq!(imports[0].library, None);
    }

    #[test]
    fn import_called_by_three_functions_is_counted() {
        let data = export(vec![
            function("0x1", "puts", true, Some("KERNEL32.DLL"), &[]),
            function("0x2", "a", false, None, &["0x1"]),
            function("0x3", "b", false, None, &["0x1"]),
            function("0x4", "c", false, None, &["0x1"]),
        ]);

        let imports = list_imports(&data);
        let puts = imports
            .iter()
            .find(|import| import.entry_address == "0x1")
            .unwrap();

        assert_eq!(puts.used_by_function_count, 3);
    }

    #[test]
    fn internal_functions_are_excluded() {
        let data = export(vec![function("0x1", "main", false, None, &[])]);

        assert!(list_imports(&data).is_empty());
    }
}
