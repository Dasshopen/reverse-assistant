use serde::Serialize;

use crate::models::ghidra_export::{DetectedTypeKind, ExternalEntryPointKind, GhidraExport};

// A single dashboard-style snapshot of a loaded analysis, computed entirely
// from data already captured by the other features (call graph, strings,
// imports/exports, detected types) -- no new Ghidra collection needed, just
// aggregation over the canonical `GhidraExport` already held in memory.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProgramOverview {
    pub function_count: usize,
    pub internal_function_count: usize,
    pub external_function_count: usize,
    pub thunk_function_count: usize,
    pub decompiled_function_count: usize,
    pub total_call_count: usize,

    pub string_count: usize,
    pub total_string_reference_count: usize,
    pub most_referenced_string: Option<StringReferenceCount>,

    pub required_library_count: usize,
    pub external_entry_point_count: usize,
    pub external_entry_point_function_count: usize,
    pub most_called_function: Option<FunctionCallCount>,

    pub detected_type_count: usize,
    pub struct_count: usize,
    pub union_count: usize,
    pub enum_count: usize,
    pub typedef_count: usize,
    pub opaque_type_count: usize,
    pub anonymous_type_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FunctionCallCount {
    pub entry_address: String,
    pub name: String,
    pub call_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StringReferenceCount {
    pub address: String,
    pub value: String,
    pub reference_count: usize,
}

pub fn compute_overview(export: &GhidraExport) -> ProgramOverview {
    let internal_function_count = export
        .functions
        .iter()
        .filter(|function| !function.is_external)
        .count();
    let external_function_count = export.functions.len() - internal_function_count;
    let thunk_function_count = export
        .functions
        .iter()
        .filter(|function| function.is_thunk)
        .count();
    let decompiled_function_count = export
        .functions
        .iter()
        .filter(|function| function.decompiled_code.is_some())
        .count();
    let total_call_count: usize = export.functions.iter().map(|f| f.calls.len()).sum();

    let most_called_function = export
        .functions
        .iter()
        .filter(|function| !function.calls.is_empty())
        .max_by_key(|function| function.calls.len())
        .map(|function| FunctionCallCount {
            entry_address: function.entry_address.clone(),
            name: function.name.clone(),
            call_count: function.calls.len(),
        });

    let total_string_reference_count: usize =
        export.strings.iter().map(|s| s.references.len()).sum();

    let most_referenced_string = export
        .strings
        .iter()
        .max_by_key(|string| string.references.len())
        .map(|string| StringReferenceCount {
            address: string.address.clone(),
            value: string.value.clone(),
            reference_count: string.references.len(),
        });

    let external_entry_point_function_count = export
        .program
        .external_entry_points
        .iter()
        .filter(|entry_point| entry_point.kind == ExternalEntryPointKind::Function)
        .count();

    let struct_count = count_kind(export, DetectedTypeKind::Struct);
    let union_count = count_kind(export, DetectedTypeKind::Union);
    let enum_count = count_kind(export, DetectedTypeKind::Enum);
    let typedef_count = count_kind(export, DetectedTypeKind::Typedef);
    let opaque_type_count = export.types.iter().filter(|t| t.is_opaque).count();
    let anonymous_type_count = export.types.iter().filter(|t| t.is_anonymous).count();

    ProgramOverview {
        function_count: export.functions.len(),
        internal_function_count,
        external_function_count,
        thunk_function_count,
        decompiled_function_count,
        total_call_count,
        string_count: export.strings.len(),
        total_string_reference_count,
        most_referenced_string,
        required_library_count: export.program.required_libraries.len(),
        external_entry_point_count: export.program.external_entry_points.len(),
        external_entry_point_function_count,
        most_called_function,
        detected_type_count: export.types.len(),
        struct_count,
        union_count,
        enum_count,
        typedef_count,
        opaque_type_count,
        anonymous_type_count,
    }
}

fn count_kind(export: &GhidraExport, kind: DetectedTypeKind) -> usize {
    export
        .types
        .iter()
        .filter(|detected_type| detected_type.kind == kind)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_export::{
        DetectedType, Endianness, ExternalEntryPoint, FunctionCall, FunctionParameter,
        GhidraFunction, GlobalString, ProgramMetadata, StringReference,
    };

    fn function(
        entry_address: &str,
        name: &str,
        is_external: bool,
        is_thunk: bool,
        decompiled: bool,
        calls: usize,
    ) -> GhidraFunction {
        GhidraFunction {
            entry_address: entry_address.to_owned(),
            name: name.to_owned(),
            return_type: "void".to_owned(),
            parameters: Vec::<FunctionParameter>::new(),
            is_external,
            is_thunk,
            decompiled_code: decompiled.then(|| "void f() {}".to_owned()),
            calls: (0..calls)
                .map(|index| FunctionCall {
                    target_address: Some(format!("0x{index:x}")),
                    target_name: format!("callee-{index}"),
                })
                .collect(),
            strings: Vec::new(),
            library: None,
            thunk_target_address: None,
        }
    }

    fn detected_type(
        name: &str,
        kind: DetectedTypeKind,
        is_opaque: bool,
        is_anonymous: bool,
    ) -> DetectedType {
        DetectedType {
            name: name.to_owned(),
            kind,
            category: "/".to_owned(),
            size: None,
            is_opaque,
            is_anonymous,
            fields: Vec::new(),
            enum_values: Vec::new(),
            target_type_name: None,
            usages: Vec::new(),
        }
    }

    fn export(
        functions: Vec<GhidraFunction>,
        strings: Vec<GlobalString>,
        types: Vec<DetectedType>,
        external_entry_points: Vec<ExternalEntryPoint>,
        required_libraries: Vec<String>,
    ) -> GhidraExport {
        GhidraExport {
            schema_version: 2,
            program: ProgramMetadata {
                name: "fixture.exe".to_owned(),
                sha256: "0".repeat(64),
                format: "PE".to_owned(),
                architecture: "x86_64".to_owned(),
                endianness: Endianness::Little,
                image_base: "0x140000000".to_owned(),
                external_entry_points,
                required_libraries,
            },
            functions,
            strings,
            types,
        }
    }

    #[test]
    fn empty_export_produces_zeroed_overview_with_no_maxima() {
        let data = export(Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());

        let overview = compute_overview(&data);

        assert_eq!(overview.function_count, 0);
        assert_eq!(overview.most_called_function, None);
        assert_eq!(overview.most_referenced_string, None);
    }

    #[test]
    fn function_counts_split_internal_external_thunk_and_decompiled() {
        let data = export(
            vec![
                function("0x1", "main", false, false, true, 2),
                function("0x2", "helper", false, false, false, 0),
                function("0x3", "plt_stub", false, true, false, 1),
                function("0x4", "printf", true, false, false, 0),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let overview = compute_overview(&data);

        assert_eq!(overview.function_count, 4);
        assert_eq!(overview.internal_function_count, 3);
        assert_eq!(overview.external_function_count, 1);
        assert_eq!(overview.thunk_function_count, 1);
        assert_eq!(overview.decompiled_function_count, 1);
        assert_eq!(overview.total_call_count, 3);
    }

    #[test]
    fn most_called_function_is_the_true_maximum_and_ties_pick_one_deterministically() {
        let data = export(
            vec![
                function("0x1", "a", false, false, false, 1),
                function("0x2", "b", false, false, false, 5),
                function("0x3", "c", false, false, false, 3),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let overview = compute_overview(&data);

        let most_called = overview
            .most_called_function
            .expect("should have a maximum");
        assert_eq!(most_called.entry_address, "0x2");
        assert_eq!(most_called.call_count, 5);
    }

    #[test]
    fn most_referenced_string_is_the_true_maximum() {
        let reference = |address: &str| StringReference {
            instruction_address: address.to_owned(),
            function_address: None,
        };

        let data = export(
            Vec::new(),
            vec![
                GlobalString {
                    address: "0x1000".to_owned(),
                    value: "low".to_owned(),
                    references: vec![reference("0x1")],
                },
                GlobalString {
                    address: "0x2000".to_owned(),
                    value: "high".to_owned(),
                    references: vec![reference("0x2"), reference("0x3"), reference("0x4")],
                },
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let overview = compute_overview(&data);

        assert_eq!(overview.string_count, 2);
        assert_eq!(overview.total_string_reference_count, 4);
        let most_referenced = overview
            .most_referenced_string
            .expect("should have a maximum");
        assert_eq!(most_referenced.value, "high");
        assert_eq!(most_referenced.reference_count, 3);
    }

    #[test]
    fn detected_types_are_counted_per_kind_and_by_opacity_anonymity() {
        let data = export(
            Vec::new(),
            Vec::new(),
            vec![
                detected_type("Config", DetectedTypeKind::Struct, false, false),
                detected_type("Flags", DetectedTypeKind::Union, false, true),
                detected_type("Mode", DetectedTypeKind::Enum, false, false),
                detected_type("Handle", DetectedTypeKind::Typedef, false, false),
                detected_type("Opaque", DetectedTypeKind::Struct, true, false),
            ],
            Vec::new(),
            Vec::new(),
        );

        let overview = compute_overview(&data);

        assert_eq!(overview.detected_type_count, 5);
        assert_eq!(overview.struct_count, 2);
        assert_eq!(overview.union_count, 1);
        assert_eq!(overview.enum_count, 1);
        assert_eq!(overview.typedef_count, 1);
        assert_eq!(overview.opaque_type_count, 1);
        assert_eq!(overview.anonymous_type_count, 1);
    }

    #[test]
    fn external_entry_points_and_required_libraries_are_counted() {
        let data = export(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![
                ExternalEntryPoint {
                    address: "0x1".to_owned(),
                    name: Some("main".to_owned()),
                    kind: ExternalEntryPointKind::Function,
                },
                ExternalEntryPoint {
                    address: "0x2".to_owned(),
                    name: None,
                    kind: ExternalEntryPointKind::Data,
                },
            ],
            vec!["libc.so.6".to_owned()],
        );

        let overview = compute_overview(&data);

        assert_eq!(overview.external_entry_point_count, 2);
        assert_eq!(overview.external_entry_point_function_count, 1);
        assert_eq!(overview.required_library_count, 1);
    }
}
