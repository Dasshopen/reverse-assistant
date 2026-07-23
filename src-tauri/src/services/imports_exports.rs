use std::collections::{HashMap, HashSet, VecDeque};

use serde::Serialize;

use crate::models::ghidra_export::{GhidraExport, GhidraFunction};
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
// graph already builds and tests, which is itself thunk-aware: a real
// caller often doesn't call the import directly but rather a PLT-style
// thunk that redirects to it, so the count has to walk through those
// thunks rather than stop at the import's direct callers (usually none).
pub fn list_imports(export: &GhidraExport) -> Vec<ImportView> {
    let caller_index = build_caller_index(export);
    let function_index: HashMap<&str, &GhidraFunction> = export
        .functions
        .iter()
        .map(|function| (function.entry_address.as_str(), function))
        .collect();

    export
        .functions
        .iter()
        .filter(|function| function.is_external)
        .map(|function| ImportView {
            entry_address: function.entry_address.clone(),
            name: function.name.clone(),
            library: function.library.clone(),
            used_by_function_count: resolve_using_functions(
                &caller_index,
                &function_index,
                function.entry_address.as_str(),
            )
            .len(),
        })
        .collect()
}

// Starting from `start` (an import's address), walks backwards over the
// (thunk-aware) caller index. A caller that is itself a thunk is never
// counted as a "using" function -- the walk continues past it to find its
// own callers instead, since a thunk chain can be several hops deep (or,
// on ELF, a single PLT stub hop). The first non-thunk caller found along
// each path is the real user. A `visited` set guards against cycles (a
// thunk chain that loops back on itself), which simply yield no users
// along that path rather than looping forever.
fn resolve_using_functions<'a>(
    caller_index: &HashMap<&'a str, Vec<&'a str>>,
    function_index: &HashMap<&'a str, &'a GhidraFunction>,
    start: &'a str,
) -> HashSet<&'a str> {
    let mut users: HashSet<&str> = HashSet::new();
    let mut visited: HashSet<&str> = HashSet::new();
    visited.insert(start);

    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(start);

    while let Some(address) = queue.pop_front() {
        let Some(callers) = caller_index.get(address) else {
            continue;
        };

        for &caller in callers {
            if !visited.insert(caller) {
                continue;
            }

            let is_thunk = function_index
                .get(caller)
                .is_some_and(|function| function.is_thunk);

            if is_thunk {
                queue.push_back(caller);
            } else {
                users.insert(caller);
            }
        }
    }

    users
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
            thunk_target_address: None,
        }
    }

    // A PLT-style thunk: redirects to `target` via `thunk_target_address`
    // rather than a real `calls` entry (mirrors what Ghidra actually
    // exports for a thunk, whose body is a jump, not a call).
    fn thunk(entry_address: &str, name: &str, target: &str) -> GhidraFunction {
        GhidraFunction {
            is_thunk: true,
            thunk_target_address: Some(target.to_owned()),
            ..function(entry_address, name, false, None, &[])
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
            types: Vec::new(),
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

    #[test]
    fn direct_call_with_no_thunk_counts_as_a_user() {
        let data = export(vec![
            function("0x1", "strcmp", true, None, &[]),
            function("0x2", "authenticate", false, None, &["0x1"]),
        ]);

        let imports = list_imports(&data);

        assert_eq!(imports[0].used_by_function_count, 1);
    }

    #[test]
    fn caller_through_a_single_plt_style_thunk_is_counted_and_the_thunk_is_not() {
        // authenticate --calls--> thunk --thunk_target_address--> strcmp
        let data = export(vec![
            function("0x1", "strcmp", true, None, &[]),
            thunk("0x2", "strcmp", "0x1"),
            function("0x3", "authenticate", false, None, &["0x2"]),
        ]);

        let imports = list_imports(&data);

        assert_eq!(imports[0].used_by_function_count, 1);
    }

    #[test]
    fn caller_through_multiple_levels_of_thunks_is_counted() {
        // authenticate --calls--> thunk_b --> thunk_a --> strcmp
        let data = export(vec![
            function("0x1", "strcmp", true, None, &[]),
            thunk("0x2", "strcmp", "0x1"),
            thunk("0x3", "strcmp", "0x2"),
            function("0x4", "authenticate", false, None, &["0x3"]),
        ]);

        let imports = list_imports(&data);

        assert_eq!(imports[0].used_by_function_count, 1);
    }

    #[test]
    fn multiple_distinct_functions_calling_through_different_thunks_are_all_counted() {
        let data = export(vec![
            function("0x1", "strcmp", true, None, &[]),
            thunk("0x2", "strcmp", "0x1"),
            thunk("0x3", "strcmp", "0x1"),
            function("0x4", "authenticate", false, None, &["0x2"]),
            function("0x5", "validate_password", false, None, &["0x3"]),
            function("0x6", "check_login", false, None, &["0x1"]),
        ]);

        let imports = list_imports(&data);

        assert_eq!(imports[0].used_by_function_count, 3);
    }

    #[test]
    fn a_cycle_among_thunks_terminates_and_yields_no_phantom_users() {
        // strcmp <- thunk_a (0x2, targets strcmp) <- thunk_b (0x3, targets
        // thunk_a) <- back to thunk_a via an explicit `calls` edge, closing
        // a real cycle. No non-thunk function ever calls into it, so the
        // walk must terminate rather than loop forever, and report zero
        // users.
        let thunk_a = GhidraFunction {
            calls: vec![FunctionCall {
                target_address: Some("0x3".to_owned()),
                target_name: "callee-0x3".to_owned(),
            }],
            ..thunk("0x2", "strcmp", "0x1")
        };

        let data = export(vec![
            function("0x1", "strcmp", true, None, &[]),
            thunk_a,
            thunk("0x3", "strcmp", "0x2"),
        ]);

        let imports = list_imports(&data);

        assert_eq!(imports[0].used_by_function_count, 0);
    }
}
