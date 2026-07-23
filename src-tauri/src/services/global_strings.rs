use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::models::ghidra_export::{GhidraExport, GhidraFunction};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReferencingFunction {
    pub entry_address: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GlobalStringView {
    pub address: String,
    pub value: String,
    // Real Ghidra reference count -- may exceed `referencing_functions.len()`
    // when the same function references the string more than once.
    pub reference_count: usize,
    pub referencing_functions: Vec<ReferencingFunction>,
}

// Pure aggregation over already-exported data: no Ghidra API access needed
// here (unlike the reference count itself, which only Java/Ghidra can
// compute) -- just resolving each string's distinct referencing functions,
// mirroring call_graph's caller-index pattern.
pub fn build_global_strings_view(export: &GhidraExport) -> Vec<GlobalStringView> {
    let function_index: HashMap<&str, &GhidraFunction> = export
        .functions
        .iter()
        .map(|function| (function.entry_address.as_str(), function))
        .collect();

    export
        .strings
        .iter()
        .map(|global_string| {
            let mut seen_functions = HashSet::new();
            let mut referencing_functions = Vec::new();

            for reference in &global_string.references {
                let Some(function_address) = &reference.function_address else {
                    continue;
                };

                if !seen_functions.insert(function_address.as_str()) {
                    continue;
                }

                if let Some(function) = function_index.get(function_address.as_str()) {
                    referencing_functions.push(ReferencingFunction {
                        entry_address: function.entry_address.clone(),
                        name: function.name.clone(),
                    });
                }
            }

            referencing_functions.sort_by(|a, b| a.entry_address.cmp(&b.entry_address));

            GlobalStringView {
                address: global_string.address.clone(),
                value: global_string.value.clone(),
                reference_count: global_string.references.len(),
                referencing_functions,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_export::{
        Endianness, FunctionCall, FunctionParameter, GlobalString, ProgramMetadata, StringReference,
    };

    fn function(entry_address: &str, name: &str) -> GhidraFunction {
        GhidraFunction {
            entry_address: entry_address.to_owned(),
            name: name.to_owned(),
            return_type: "void".to_owned(),
            parameters: Vec::<FunctionParameter>::new(),
            is_external: false,
            is_thunk: false,
            decompiled_code: None,
            calls: Vec::<FunctionCall>::new(),
            strings: Vec::new(),
            library: None,
            thunk_target_address: None,
        }
    }

    fn reference(instruction_address: &str, function_address: Option<&str>) -> StringReference {
        StringReference {
            instruction_address: instruction_address.to_owned(),
            function_address: function_address.map(str::to_owned),
        }
    }

    fn export(functions: Vec<GhidraFunction>, strings: Vec<GlobalString>) -> GhidraExport {
        GhidraExport {
            schema_version: 2,
            program: ProgramMetadata {
                name: "fixture.exe".to_owned(),
                sha256: "0".repeat(64),
                format: "PE".to_owned(),
                architecture: "x86_64".to_owned(),
                endianness: Endianness::Little,
                image_base: "0x140000000".to_owned(),
                external_entry_points: Vec::new(),
                required_libraries: Vec::new(),
            },
            functions,
            strings,
            types: Vec::new(),
        }
    }

    #[test]
    fn string_referenced_once_by_one_function() {
        let data = export(
            vec![function("0x1", "main")],
            vec![GlobalString {
                address: "0x2000".to_owned(),
                value: "hello".to_owned(),
                references: vec![reference("0x1010", Some("0x1"))],
            }],
        );

        let view = build_global_strings_view(&data);

        assert_eq!(view.len(), 1);
        assert_eq!(view[0].reference_count, 1);
        assert_eq!(view[0].referencing_functions.len(), 1);
        assert_eq!(view[0].referencing_functions[0].name, "main");
    }

    #[test]
    fn same_function_referencing_a_string_three_times_gives_one_distinct_function() {
        let data = export(
            vec![function("0x400664", "authenticate")],
            vec![GlobalString {
                address: "0x4008d0".to_owned(),
                value: "SOSNEAKY".to_owned(),
                references: vec![
                    reference("0x400680", Some("0x400664")),
                    reference("0x4006a0", Some("0x400664")),
                    reference("0x4006c0", Some("0x400664")),
                ],
            }],
        );

        let view = build_global_strings_view(&data);

        assert_eq!(view[0].reference_count, 3);
        assert_eq!(view[0].referencing_functions.len(), 1);
        assert_eq!(view[0].referencing_functions[0].entry_address, "0x400664");
    }

    #[test]
    fn reference_with_no_containing_function_is_counted_but_not_listed() {
        let data = export(
            Vec::new(),
            vec![GlobalString {
                address: "0x2000".to_owned(),
                value: "orphan".to_owned(),
                references: vec![reference("0x1010", None)],
            }],
        );

        let view = build_global_strings_view(&data);

        assert_eq!(view[0].reference_count, 1);
        assert!(view[0].referencing_functions.is_empty());
    }

    #[test]
    fn identical_values_at_different_addresses_stay_distinct() {
        let data = export(
            Vec::new(),
            vec![
                GlobalString {
                    address: "0x2000".to_owned(),
                    value: "duplicate".to_owned(),
                    references: vec![reference("0x1010", None)],
                },
                GlobalString {
                    address: "0x3000".to_owned(),
                    value: "duplicate".to_owned(),
                    references: vec![reference("0x1020", None)],
                },
            ],
        );

        let view = build_global_strings_view(&data);

        assert_eq!(view.len(), 2);
        assert_eq!(view[0].address, "0x2000");
        assert_eq!(view[1].address, "0x3000");
    }

    #[test]
    fn empty_input_produces_no_entries() {
        let data = export(Vec::new(), Vec::new());

        assert!(build_global_strings_view(&data).is_empty());
    }
}
