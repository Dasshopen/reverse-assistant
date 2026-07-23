use reverse_assistant_lib::models::ghidra_export::{Endianness, GhidraExport};

const V1_EXAMPLE_JSON: &str = include_str!("../../docs/contracts/ghidra-export-v1.example.json");
const V2_EXAMPLE_JSON: &str = include_str!("../../docs/contracts/ghidra-export-v2.example.json");
const REAL_V2_EXPORT_JSON: &str = include_str!("fixtures/real-fauxware-export-v2.json");

fn parsed_v2_example() -> GhidraExport {
    GhidraExport::parse_and_validate(V2_EXAMPLE_JSON).expect("the v2 example JSON should be valid")
}

#[test]
fn valid_ghidra_export_v2_deserializes() {
    let export = parsed_v2_example();

    assert_eq!(export.schema_version, 2);
    assert_eq!(export.program.name, "sample.exe");
    assert_eq!(export.program.endianness, Endianness::Little);
    assert_eq!(export.functions.len(), 1);

    let function = &export.functions[0];

    assert_eq!(function.entry_address, "0x140001150");
    assert_eq!(function.name, "FUN_140001150");
    assert_eq!(function.calls.len(), 1);
    assert_eq!(function.calls[0].target_address, None);

    // Function objects carry no wire-format `strings` field in v2 -- the
    // canonical model still exposes one, derived from the global table.
    assert_eq!(function.strings, vec!["secret"]);

    assert_eq!(export.strings.len(), 1);
    assert_eq!(export.strings[0].address, "0x140003000");
    assert_eq!(export.strings[0].value, "secret");
    assert_eq!(export.strings[0].references.len(), 1);
    assert_eq!(
        export.strings[0].references[0].function_address.as_deref(),
        Some("0x140001150")
    );
}

#[test]
fn v1_export_still_imports_with_no_string_cross_references() {
    let export = GhidraExport::parse_and_validate(V1_EXAMPLE_JSON)
        .expect("the v1 example JSON should still be accepted");

    assert_eq!(export.schema_version, 1);
    assert_eq!(export.functions.len(), 1);
    assert_eq!(export.functions[0].strings, vec!["secret"]);

    // v1 never captured string addresses -- the global cross-reference
    // table is legitimately empty, not an error.
    assert!(export.strings.is_empty());
}

#[test]
fn real_binary_v2_export_has_a_string_referenced_multiple_times_from_one_function() {
    let export = GhidraExport::parse_and_validate(REAL_V2_EXPORT_JSON)
        .expect("a real headless v2 export should be valid");

    assert_eq!(export.schema_version, 2);

    // The hardcoded backdoor password in this real fauxware CTF binary: 3
    // real Ghidra references, 2 attributed to `authenticate` (0x400664) and
    // 1 with no containing function -- a genuine real-data case of
    // reference_count > distinct-referencing-function-count.
    let backdoor = export
        .strings
        .iter()
        .find(|string| string.value == "SOSNEAKY")
        .expect("the SOSNEAKY string should be present");

    assert_eq!(backdoor.references.len(), 3);

    let authenticate_references = backdoor
        .references
        .iter()
        .filter(|reference| reference.function_address.as_deref() == Some("0x400664"))
        .count();
    assert_eq!(authenticate_references, 2);

    let unattributed_references = backdoor
        .references
        .iter()
        .filter(|reference| reference.function_address.is_none())
        .count();
    assert_eq!(unattributed_references, 1);

    // The canonical per-function view still derives correctly from the
    // global table: `authenticate` should list "SOSNEAKY" exactly once
    // (deduplicated), matching the pre-v2 per-function semantics.
    let authenticate = export
        .functions
        .iter()
        .find(|function| function.entry_address == "0x400664")
        .expect("authenticate should be present");
    assert_eq!(
        authenticate
            .strings
            .iter()
            .filter(|s| *s == "SOSNEAKY")
            .count(),
        1
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
    export.program.entry_points[0] = String::from("invalid");

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid entry point should be rejected"),
        "program.entry_points[0] must be a lowercase hexadecimal string beginning with 0x"
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
