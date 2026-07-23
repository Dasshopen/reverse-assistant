use reverse_assistant_lib::models::ghidra_export::{
    Endianness, ExternalEntryPointKind, GhidraExport,
};

const V1_EXAMPLE_JSON: &str = include_str!("../../docs/contracts/ghidra-export-v1.example.json");
const V2_EXAMPLE_JSON: &str = include_str!("../../docs/contracts/ghidra-export-v2.example.json");
const REAL_ELF_EXPORT_JSON: &str = include_str!("fixtures/real-fauxware-export-v2.json");
const REAL_PE_EXPORT_JSON: &str = include_str!("fixtures/real-sqlite3-export-v2.json");

fn parsed_v2_example() -> GhidraExport {
    GhidraExport::parse_and_validate(V2_EXAMPLE_JSON).expect("the v2 example JSON should be valid")
}

#[test]
fn valid_ghidra_export_v2_deserializes() {
    let export = parsed_v2_example();

    assert_eq!(export.schema_version, 2);
    assert_eq!(export.program.name, "sample.exe");
    assert_eq!(export.program.endianness, Endianness::Little);
    assert_eq!(export.program.required_libraries, vec!["MSVCRT.DLL"]);
    assert_eq!(export.program.external_entry_points.len(), 1);
    assert_eq!(
        export.program.external_entry_points[0].address,
        "0x140001150"
    );
    assert_eq!(
        export.program.external_entry_points[0].name.as_deref(),
        Some("FUN_140001150")
    );
    assert_eq!(
        export.program.external_entry_points[0].kind,
        ExternalEntryPointKind::Function
    );

    assert_eq!(export.functions.len(), 2);

    let internal = &export.functions[0];
    assert_eq!(internal.entry_address, "0x140001150");
    assert_eq!(internal.library, None);
    assert_eq!(internal.thunk_target_address, None);

    let external = &export.functions[1];
    assert_eq!(external.name, "strcmp");
    assert!(external.is_external);
    assert_eq!(external.library.as_deref(), Some("MSVCRT.DLL"));
    assert_eq!(external.thunk_target_address, None);

    // Function objects carry no wire-format `strings` field in v2 -- the
    // canonical model still exposes one, derived from the global table.
    assert_eq!(internal.strings, vec!["secret"]);

    assert_eq!(export.strings.len(), 1);
    assert_eq!(export.strings[0].address, "0x140003000");
}

#[test]
fn v1_export_still_imports_with_honest_gaps() {
    let export = GhidraExport::parse_and_validate(V1_EXAMPLE_JSON)
        .expect("the v1 example JSON should still be accepted");

    assert_eq!(export.schema_version, 1);
    assert_eq!(export.functions.len(), 1);
    assert_eq!(export.functions[0].strings, vec!["secret"]);

    // v1 never captured string addresses -- the global cross-reference
    // table is legitimately empty, not an error.
    assert!(export.strings.is_empty());

    // v1 never attributed imports to a library or captured required
    // libraries at all.
    assert_eq!(export.functions[0].library, None);
    assert!(export.program.required_libraries.is_empty());

    // v1 never captured thunk targets either.
    assert_eq!(export.functions[0].thunk_target_address, None);

    // v1's bare entry_points addresses become honestly-unknown entries,
    // not guessed names/kinds.
    assert!(!export.program.external_entry_points.is_empty());
    for entry_point in &export.program.external_entry_points {
        assert_eq!(entry_point.name, None);
        assert_eq!(entry_point.kind, ExternalEntryPointKind::Unknown);
    }
}

#[test]
fn real_elf_export_has_no_per_import_library_but_real_required_libraries() {
    let export = GhidraExport::parse_and_validate(REAL_ELF_EXPORT_JSON)
        .expect("a real headless ELF v2 export should be valid");

    assert_eq!(export.program.required_libraries, vec!["libc.so.6"]);

    let strcmp = export
        .functions
        .iter()
        .find(|function| function.name == "strcmp" && function.is_external)
        .expect("strcmp should be present as an external function");

    // ELF imports are never attributed to a specific library, even though
    // the whole program's real dependency (libc.so.6) is known above.
    assert_eq!(strcmp.library, None);

    // strcmp is only reachable through two levels of PLT/GOT thunks: a PLT
    // stub (0x400550) whose real `calls` entry resolves to a GOT-level
    // thunk (0x602020), which itself has no `calls` at all and only
    // carries `thunk_target_address` pointing at the real external
    // function above. Both hops must round-trip through parsing.
    let plt_thunk = export
        .functions
        .iter()
        .find(|function| function.entry_address == "0x400550")
        .expect("the strcmp PLT thunk should be present");
    assert!(plt_thunk.is_thunk);
    assert_eq!(plt_thunk.thunk_target_address.as_deref(), Some("0x602020"));

    let got_thunk = export
        .functions
        .iter()
        .find(|function| function.entry_address == "0x602020")
        .expect("the strcmp GOT-level thunk should be present");
    assert!(got_thunk.is_thunk);
    assert!(got_thunk.calls.is_empty());
    assert_eq!(
        got_thunk.thunk_target_address.as_deref(),
        Some(strcmp.entry_address.as_str())
    );

    // `main` is a real function reachable externally on this ELF
    // executable -- confirms external_entry_points carries real
    // name/kind data, not just addresses.
    let main_entry_point = export
        .program
        .external_entry_points
        .iter()
        .find(|entry_point| entry_point.name.as_deref() == Some("main"))
        .expect("main should appear as an external entry point");
    assert_eq!(main_entry_point.kind, ExternalEntryPointKind::Function);
}

#[test]
fn real_pe_export_attributes_imports_to_the_real_dll_and_lists_clean_exports() {
    let export = GhidraExport::parse_and_validate(REAL_PE_EXPORT_JSON)
        .expect("a real headless PE v2 export should be valid");

    assert!(export
        .program
        .required_libraries
        .iter()
        .any(|library| library == "KERNEL32.DLL"));

    let kernel32_import = export
        .functions
        .iter()
        .find(|function| function.is_external && function.name == "FlushFileBuffers")
        .expect("FlushFileBuffers should be present as an external function");
    assert_eq!(kernel32_import.library.as_deref(), Some("KERNEL32.DLL"));

    let sqlite3_open = export
        .program
        .external_entry_points
        .iter()
        .find(|entry_point| entry_point.name.as_deref() == Some("sqlite3_open"))
        .expect("sqlite3_open should be a real export of this DLL");
    assert_eq!(sqlite3_open.kind, ExternalEntryPointKind::Function);

    // The exported `sqlite3_open` symbol is itself a thunk wrapping the
    // real implementation -- its own `calls` list is empty, so its target
    // is only visible via `thunk_target_address`.
    let sqlite3_open_thunk = export
        .functions
        .iter()
        .find(|function| function.entry_address == "0x180001253")
        .expect("the sqlite3_open thunk should be present");
    assert!(sqlite3_open_thunk.is_thunk);
    assert!(sqlite3_open_thunk.calls.is_empty());
    assert_eq!(
        sqlite3_open_thunk.thunk_target_address.as_deref(),
        Some("0x180006890")
    );
}

#[test]
fn unknown_root_field_is_rejected() {
    let invalid_json = V2_EXAMPLE_JSON.replacen(
        "\"schema_version\": 2,",
        "\"schema_version\": 2,\n  \"unexpected_field\": true,",
        1,
    );

    let error = GhidraExport::parse_and_validate(&invalid_json)
        .expect_err("an unknown root field should be rejected");

    assert!(error.contains("unknown field"), "unexpected error: {error}");
}

#[test]
fn unsupported_schema_version_is_rejected() {
    let invalid_json =
        V2_EXAMPLE_JSON.replacen("\"schema_version\": 2", "\"schema_version\": 5", 1);

    let error = GhidraExport::parse_and_validate(&invalid_json)
        .expect_err("schema version 5 should be rejected");

    assert_eq!(
        error,
        "unsupported schema version: 5; supported versions: 1, 2"
    );
}

#[test]
fn invalid_program_sha256_is_rejected() {
    let mut export = parsed_v2_example();

    export.program.sha256 = String::from("invalid-sha256");

    let error = export
        .validate()
        .expect_err("an invalid SHA-256 should be rejected");

    assert_eq!(
        error,
        "program sha256 must contain exactly 64 lowercase hexadecimal characters"
    );
}

#[test]
fn invalid_image_base_is_rejected() {
    let mut export = parsed_v2_example();

    export.program.image_base = String::from("140000000");

    let error = export
        .validate()
        .expect_err("an address without the 0x prefix should be rejected");

    assert_eq!(
        error,
        "program.image_base must be a lowercase hexadecimal string beginning with 0x"
    );
}

#[test]
fn invalid_nested_addresses_are_rejected() {
    let mut export = parsed_v2_example();
    export.program.external_entry_points[0].address = String::from("invalid");

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid external entry point address should be rejected"),
        "program.external_entry_points[0].address must be a lowercase hexadecimal string beginning with 0x"
    );

    let mut export = parsed_v2_example();
    export.functions[0].entry_address = String::from("0xXYZ");

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid function address should be rejected"),
        "functions[0].entry_address must be a lowercase hexadecimal string beginning with 0x"
    );

    let mut export = parsed_v2_example();
    export.functions[0].calls[0].target_address = Some(String::from("401000"));

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid call target address should be rejected"),
        "functions[0].calls[0].target_address must be a lowercase hexadecimal string beginning with 0x"
    );

    let mut export = parsed_v2_example();
    export.functions[0].thunk_target_address = Some(String::from("not-an-address"));

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid thunk target address should be rejected"),
        "functions[0].thunk_target_address must be a lowercase hexadecimal string beginning with 0x"
    );
}

#[test]
fn duplicate_external_entry_point_address_is_rejected() {
    let mut export = parsed_v2_example();
    let duplicate = export.program.external_entry_points[0].clone();
    export.program.external_entry_points.push(duplicate);

    let error = export
        .validate()
        .expect_err("duplicate external entry point addresses should be rejected");

    assert_eq!(error, "duplicate external entry point address: 0x140001150");
}

#[test]
fn invalid_string_address_is_rejected() {
    let mut export = parsed_v2_example();
    export.strings[0].address = String::from("invalid");

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid string address should be rejected"),
        "strings[0].address must be a lowercase hexadecimal string beginning with 0x"
    );
}

#[test]
fn duplicate_string_address_is_rejected() {
    let mut export = parsed_v2_example();
    let duplicate = export.strings[0].clone();
    export.strings.push(duplicate);

    let error = export
        .validate()
        .expect_err("duplicate string addresses should be rejected");

    assert_eq!(error, "duplicate string address: 0x140003000");
}

#[test]
fn invalid_string_reference_address_is_rejected() {
    let mut export = parsed_v2_example();
    export.strings[0].references[0].instruction_address = String::from("invalid");

    let error = export
        .validate()
        .expect_err("an invalid reference instruction address should be rejected");

    assert_eq!(
        error,
        "strings[0].references[0].instruction_address must be a lowercase hexadecimal string beginning with 0x"
    );
}

#[test]
fn invalid_string_reference_function_address_is_rejected() {
    let mut export = parsed_v2_example();
    export.strings[0].references[0].function_address = Some(String::from("invalid"));

    let error = export
        .validate()
        .expect_err("an invalid reference function address should be rejected");

    assert_eq!(
        error,
        "strings[0].references[0].function_address must be a lowercase hexadecimal string beginning with 0x"
    );
}

#[test]
fn duplicate_function_entry_address_is_rejected() {
    let mut export = parsed_v2_example();

    let duplicate_function = export.functions[0].clone();
    export.functions.push(duplicate_function);

    let error = export
        .validate()
        .expect_err("duplicate function entry addresses should be rejected");

    assert_eq!(error, "duplicate function entry address: 0x140001150");
}

#[test]
fn empty_program_name_is_rejected() {
    let mut export = parsed_v2_example();

    export.program.name = String::from("   ");

    let error = export
        .validate()
        .expect_err("a blank program name should be rejected");

    assert_eq!(error, "program.name must not be empty");
}

#[test]
fn missing_required_nullable_field_is_rejected() {
    let mut json_value: serde_json::Value =
        serde_json::from_str(V2_EXAMPLE_JSON).expect("the example JSON should be valid");

    json_value["functions"][0]
        .as_object_mut()
        .expect("the first function should be a JSON object")
        .remove("decompiled_code");

    let json_without_field =
        serde_json::to_string(&json_value).expect("the modified JSON should serialize");

    let result = GhidraExport::parse_and_validate(&json_without_field);

    assert!(
        result.is_err(),
        "a missing decompiled_code field should be rejected"
    );
}

#[test]
fn missing_target_address_is_rejected() {
    let mut json_value: serde_json::Value =
        serde_json::from_str(V2_EXAMPLE_JSON).expect("the example JSON should be valid");

    json_value["functions"][0]["calls"][0]
        .as_object_mut()
        .expect("the first call should be a JSON object")
        .remove("target_address");

    let json_without_field =
        serde_json::to_string(&json_value).expect("the modified JSON should serialize");

    let result = GhidraExport::parse_and_validate(&json_without_field);

    assert!(
        result.is_err(),
        "a missing target_address field should be rejected"
    );
}

#[test]
fn parse_and_validate_applies_semantic_validation() {
    let invalid_json =
        V2_EXAMPLE_JSON.replacen("\"schema_version\": 2", "\"schema_version\": 5", 1);

    let error = GhidraExport::parse_and_validate(&invalid_json)
        .expect_err("parse_and_validate should reject an unsupported schema version");

    assert_eq!(
        error,
        "unsupported schema version: 5; supported versions: 1, 2"
    );
}

#[test]
fn parse_and_validate_reports_invalid_json_syntax() {
    let invalid_json = "{ this is not valid JSON }";

    let error = GhidraExport::parse_and_validate(invalid_json)
        .expect_err("invalid JSON syntax should be rejected");

    assert!(
        error.starts_with("invalid Ghidra export JSON:"),
        "unexpected error: {error}"
    );
}
