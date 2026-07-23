use std::collections::HashMap;

use serde::Serialize;

use crate::models::ghidra_export::{
    DetectedTypeKind, ExternalEntryPointKind, GhidraExport, GhidraFunction,
};
use crate::services::call_graph::{build_caller_index, resolve_calling_functions};

// A single dashboard-style snapshot of a loaded analysis, computed entirely
// from data already captured by the other features (call graph, strings,
// imports/exports, detected types) -- no new Ghidra collection needed, just
// aggregation over the canonical `GhidraExport` already held in memory.
//
// `decompiled_function_count` reflects the loaded export's own snapshot of
// `functions[].decompiled_code`. It is not a stale figure: for an
// automatically-analyzed session, `decompile_function` writes each
// on-demand result back into the stored export (see lib.rs), so this
// number genuinely grows as the user decompiles more functions rather than
// staying frozen at the export-time value (which bulk export never
// populates -- decompilation is on-demand by design).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProgramOverview {
    pub function_count: usize,
    pub internal_function_count: usize,
    pub external_function_count: usize,
    pub thunk_function_count: usize,
    pub decompiled_function_count: usize,
    // Total distinct (caller, callee) call edges across the program --
    // i.e. call *sites*, not distinct calling functions. Deliberately kept
    // apart from `most_used_function` below, which counts something else
    // entirely (see its own doc comment).
    pub call_site_count: usize,

    pub string_count: usize,
    pub total_string_reference_count: usize,
    pub most_referenced_string: Option<StringReferenceCount>,

    pub required_library_count: usize,
    pub external_entry_point_count: usize,
    pub external_entry_point_function_count: usize,
    // The function called by the most *distinct, non-thunk* functions in
    // the program -- reuses the same thunk-aware resolution as an import's
    // `used_by_function_count`, so a PLT/GOT-style redirect is never
    // conflated with a real caller, and a caller reaching this function
    // through several call sites still counts once.
    pub most_used_function: Option<FunctionUsageCount>,

    pub detected_type_count: usize,
    pub struct_count: usize,
    pub union_count: usize,
    pub enum_count: usize,
    pub typedef_count: usize,
    pub opaque_type_count: usize,
    pub anonymous_type_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FunctionUsageCount {
    pub entry_address: String,
    pub name: String,
    pub used_by_function_count: usize,
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
    let call_site_count: usize = export.functions.iter().map(|f| f.calls.len()).sum();

    let caller_index = build_caller_index(export);
    let function_index: HashMap<&str, &GhidraFunction> = export
        .functions
        .iter()
        .map(|function| (function.entry_address.as_str(), function))
        .collect();

    let most_used_function = export
        .functions
        .iter()
        // A thunk is a redirect, not a callee identity worth ranking on its
        // own -- its callers are already, transitively, callers of its
        // real target too, so letting a thunk win here would just be a
        // confusing duplicate of the real function's own count.
        .filter(|function| !function.is_thunk)
        .map(|function| {
            let caller_count = resolve_calling_functions(
                &caller_index,
                &function_index,
                function.entry_address.as_str(),
            )
            .len();

            (function, caller_count)
        })
        .filter(|(_, caller_count)| *caller_count > 0)
        .max_by_key(|(_, caller_count)| *caller_count)
        .map(|(function, caller_count)| FunctionUsageCount {
            entry_address: function.entry_address.clone(),
            name: function.name.clone(),
            used_by_function_count: caller_count,
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
        call_site_count,
        string_count: export.strings.len(),
        total_string_reference_count,
        most_referenced_string,
        required_library_count: export.program.required_libraries.len(),
        external_entry_point_count: export.program.external_entry_points.len(),
        external_entry_point_function_count,
        most_used_function,
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
        calls: &[&str],
    ) -> GhidraFunction {
        GhidraFunction {
            entry_address: entry_address.to_owned(),
            name: name.to_owned(),
            return_type: "void".to_owned(),
            parameters: Vec::<FunctionParameter>::new(),
            is_external,
            is_thunk,
            decompiled_code: decompiled.then(|| "void f() {}".to_owned()),
            calls: calls
                .iter()
                .map(|target| FunctionCall {
                    target_address: Some((*target).to_owned()),
                    target_name: format!("callee-{target}"),
                })
                .collect(),
            strings: Vec::new(),
            library: None,
            thunk_target_address: None,
        }
    }

    // A PLT-style thunk: redirects to `target` via `thunk_target_address`
    // rather than a real `calls` entry, mirroring what Ghidra actually
    // exports for a thunk (see call_graph.rs/imports_exports.rs tests).
    fn thunk(entry_address: &str, name: &str, target: &str) -> GhidraFunction {
        GhidraFunction {
            thunk_target_address: Some(target.to_owned()),
            ..function(entry_address, name, false, true, false, &[])
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
        assert_eq!(overview.most_used_function, None);
        assert_eq!(overview.most_referenced_string, None);
    }

    #[test]
    fn function_counts_split_internal_external_thunk_and_decompiled() {
        let data = export(
            vec![
                function("0x1", "main", false, false, true, &["0x2", "0x4"]),
                function("0x2", "helper", false, false, false, &[]),
                function("0x3", "plt_stub", false, true, false, &["0x4"]),
                function("0x4", "printf", true, false, false, &[]),
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
        assert_eq!(overview.call_site_count, 3);
    }

    #[test]
    fn most_used_function_counts_distinct_real_callers_not_outgoing_calls_or_call_sites() {
        // "target" is called directly once by `a`, twice (two call sites)
        // by `b`, and once more through a thunk by `c` -- a naive
        // "outgoing calls" or "raw call site" count would crown a
        // different function; the true distinct-caller count is 3 (a, b,
        // c), with the thunk itself never counted as a caller.
        let data = export(
            vec![
                function("0x1", "target", false, false, false, &[]),
                function("0x2", "a", false, false, false, &["0x1"]),
                function("0x3", "b", false, false, false, &["0x1", "0x1"]),
                thunk("0x4", "target_thunk", "0x1"),
                function("0x5", "c", false, false, false, &["0x4"]),
                // "decoy" makes far more outgoing calls than anyone makes
                // into "target" (and, crucially, never calls "target" or
                // its thunk itself), but is called by nobody -- it must
                // not be reported as the most-used function.
                function("0x6", "decoy", false, false, false, &["0x2", "0x3", "0x5"]),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let overview = compute_overview(&data);

        let most_used = overview.most_used_function.expect("should have a maximum");
        assert_eq!(most_used.entry_address, "0x1");
        assert_eq!(most_used.name, "target");
        assert_eq!(most_used.used_by_function_count, 3);
    }

    #[test]
    fn a_thunk_is_never_reported_as_the_most_used_function_even_on_a_tie() {
        // Every caller of `real_target` goes exclusively through the
        // thunk, so both resolve to the exact same distinct-caller count
        // (2) -- a genuine tie. `max_by_key` keeps the *last* equally-
        // maximal candidate, and the thunk is placed later in the function
        // list (mirroring how a real PLT thunk's address usually sorts
        // after the plain external stub it redirects to), so without
        // excluding thunks from candidacy the thunk would win the tie.
        // It's a redirect, not a meaningful callee identity, and must
        // never be reported here.
        let data = export(
            vec![
                function("0x1", "real_target", false, false, false, &[]),
                thunk("0x9", "real_target_thunk", "0x1"),
                function("0x2", "a", false, false, false, &["0x9"]),
                function("0x3", "b", false, false, false, &["0x9"]),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let overview = compute_overview(&data);

        let most_used = overview.most_used_function.expect("should have a maximum");
        assert_eq!(most_used.entry_address, "0x1");
        assert_eq!(most_used.name, "real_target");
        assert_eq!(most_used.used_by_function_count, 2);
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
