use reverse_assistant_lib::models::ghidra_export::GhidraExport;
use reverse_assistant_lib::services::program_overview::compute_overview;

const REAL_ELF_EXPORT_JSON: &str = include_str!("fixtures/real-fauxware-export-v2.json");
const REAL_PE_EXPORT_JSON: &str = include_str!("fixtures/real-sqlite3-export-v2.json");

#[test]
fn real_elf_overview_matches_the_known_fauxware_shape() {
    let export = GhidraExport::parse_and_validate(REAL_ELF_EXPORT_JSON)
        .expect("a real headless ELF v2 export should be valid");

    let overview = compute_overview(&export);

    assert_eq!(overview.function_count, 37);
    assert_eq!(overview.internal_function_count, 29);
    assert_eq!(overview.external_function_count, 8);
    assert_eq!(overview.thunk_function_count, 15);
    // Headless export never bulk-decompiles (on-demand only).
    assert_eq!(overview.decompiled_function_count, 0);
    assert_eq!(overview.call_site_count, 25);

    // `read` is directly called by both `authenticate` and `main` --  two
    // distinct real callers. `puts` ties at 2 as well (`accepted` and
    // `main`), but `read`'s entry address sorts after `puts`'s, so it wins
    // the deterministic last-equal-wins tie-break. Crucially, this is a
    // *distinct-caller* count, not the number of outgoing calls `read`
    // itself makes (it makes none -- it's an external import).
    let most_used = overview
        .most_used_function
        .expect("some function should have real distinct callers");
    assert_eq!(most_used.entry_address, "0x3");
    assert_eq!(most_used.name, "read");
    assert_eq!(most_used.used_by_function_count, 2);

    assert_eq!(overview.string_count, 7);
    assert_eq!(overview.total_string_reference_count, 11);

    // The hardcoded backdoor string, already the star of the global-strings
    // fixture -- three real references is exactly why "most referenced"
    // and "distinct referencing functions" are different numbers.
    let most_referenced = overview
        .most_referenced_string
        .expect("SOSNEAKY should be the most-referenced string");
    assert_eq!(most_referenced.value, "SOSNEAKY");
    assert_eq!(most_referenced.reference_count, 3);

    assert_eq!(overview.external_entry_point_count, 16);
    assert_eq!(overview.external_entry_point_function_count, 9);
    assert_eq!(overview.required_library_count, 1);

    assert_eq!(overview.detected_type_count, 18);
    assert_eq!(overview.struct_count, 11);
    assert_eq!(overview.union_count, 0);
    assert_eq!(overview.enum_count, 3);
    assert_eq!(overview.typedef_count, 4);
    assert_eq!(overview.opaque_type_count, 0);
    assert_eq!(overview.anonymous_type_count, 0);
}

#[test]
fn real_pe_overview_reports_no_most_used_function_when_every_kept_function_is_a_leaf() {
    let export = GhidraExport::parse_and_validate(REAL_PE_EXPORT_JSON)
        .expect("a real headless PE v2 export should be valid");

    let overview = compute_overview(&export);

    assert_eq!(overview.function_count, 14);
    assert_eq!(overview.external_function_count, 8);
    assert_eq!(overview.thunk_function_count, 6);

    // Every function kept in this trimmed fixture is a leaf import/thunk
    // stub with an empty `calls` list, and none of them call each other --
    // there is honestly no function with any real caller to report, not a
    // fabricated entry.
    assert_eq!(overview.most_used_function, None);

    assert_eq!(overview.detected_type_count, 6);
    assert_eq!(overview.struct_count, 2);
    assert_eq!(overview.union_count, 2);
    assert_eq!(overview.enum_count, 1);
    assert_eq!(overview.typedef_count, 1);
    // sqlite3_stmt (opaque) and the anonymous PDB union.
    assert_eq!(overview.opaque_type_count, 1);
    assert_eq!(overview.anonymous_type_count, 1);
}
