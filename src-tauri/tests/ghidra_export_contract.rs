use reverse_assistant_lib::models::ghidra_export::{Endianness, GhidraExport};

const EXAMPLE_JSON: &str = include_str!("../../docs/contracts/ghidra-export-v1.example.json");

#[test]
fn valid_ghidra_export_v1_deserializes() {
    let export: GhidraExport =
        serde_json::from_str(EXAMPLE_JSON).expect("the v1 example JSON should be valid");

    assert_eq!(export.schema_version, 1);
    assert_eq!(export.program.name, "sample.exe");
    assert_eq!(export.program.endianness, Endianness::Little);
    assert_eq!(export.functions.len(), 1);

    let function = &export.functions[0];

    assert_eq!(function.entry_address, "0x140001150");
    assert_eq!(function.name, "FUN_140001150");
    assert_eq!(function.calls.len(), 1);
    assert_eq!(function.calls[0].target_address, None);
    assert_eq!(function.strings, vec!["secret"]);
}

#[test]
fn unknown_root_field_is_rejected() {
    let invalid_json = EXAMPLE_JSON.replacen(
        "\"schema_version\": 1,",
        "\"schema_version\": 1,\n  \"unexpected_field\": true,",
        1,
    );

    let error = serde_json::from_str::<GhidraExport>(&invalid_json)
        .expect_err("an unknown root field should be rejected");

    assert!(
        error.to_string().contains("unknown field"),
        "unexpected error: {error}"
    );
}

#[test]
fn unsupported_schema_version_is_rejected() {
    let invalid_json = EXAMPLE_JSON.replacen("\"schema_version\": 1", "\"schema_version\": 5", 1);

    let export: GhidraExport =
        serde_json::from_str(&invalid_json).expect("the JSON structure should remain valid");

    let error = export
        .validate()
        .expect_err("schema version 5 should be rejected");

    assert_eq!(error, "unsupported schema version: 5; supported version: 1");
}

#[test]
fn invalid_program_sha256_is_rejected() {
    let mut export: GhidraExport =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

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
    let mut export: GhidraExport =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

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
    let mut export: GhidraExport =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

    export.program.entry_points[0] = String::from("invalid");

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid entry point should be rejected"),
        "program.entry_points[0] must be a lowercase hexadecimal string beginning with 0x"
    );

    let mut export: GhidraExport =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

    export.functions[0].entry_address = String::from("0xXYZ");

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid function address should be rejected"),
        "functions[0].entry_address must be a lowercase hexadecimal string beginning with 0x"
    );

    let mut export: GhidraExport =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

    export.functions[0].calls[0].target_address = Some(String::from("401000"));

    assert_eq!(
        export
            .validate()
            .expect_err("an invalid call target address should be rejected"),
        "functions[0].calls[0].target_address must be a lowercase hexadecimal string beginning with 0x"
    );
}

#[test]
fn duplicate_function_entry_address_is_rejected() {
    let mut export: GhidraExport =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

    let duplicate_function = export.functions[0].clone();
    export.functions.push(duplicate_function);

    let error = export
        .validate()
        .expect_err("duplicate function entry addresses should be rejected");

    assert_eq!(error, "duplicate function entry address: 0x140001150");
}

#[test]
fn empty_program_name_is_rejected() {
    let mut export: GhidraExport =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

    export.program.name = String::from("   ");

    let error = export
        .validate()
        .expect_err("a blank program name should be rejected");

    assert_eq!(error, "program.name must not be empty");
}

#[test]
fn missing_required_nullable_field_is_rejected() {
    let mut json_value: serde_json::Value =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

    json_value["functions"][0]
        .as_object_mut()
        .expect("the first function should be a JSON object")
        .remove("decompiled_code");

    let json_without_field =
        serde_json::to_string(&json_value).expect("the modified JSON should serialize");

    let result = serde_json::from_str::<GhidraExport>(&json_without_field);

    assert!(
        result.is_err(),
        "a missing decompiled_code field should be rejected"
    );
}

#[test]
fn missing_target_address_is_rejected() {
    let mut json_value: serde_json::Value =
        serde_json::from_str(EXAMPLE_JSON).expect("the example JSON should be valid");

    json_value["functions"][0]["calls"][0]
        .as_object_mut()
        .expect("the first call should be a JSON object")
        .remove("target_address");

    let json_without_field =
        serde_json::to_string(&json_value).expect("the modified JSON should serialize");

    let result = serde_json::from_str::<GhidraExport>(&json_without_field);

    assert!(
        result.is_err(),
        "a missing target_address field should be rejected"
    );
}

#[test]
fn parse_and_validate_applies_semantic_validation() {
    let invalid_json = EXAMPLE_JSON.replacen("\"schema_version\": 1", "\"schema_version\": 5", 1);

    let error = GhidraExport::parse_and_validate(&invalid_json)
        .expect_err("parse_and_validate should reject an unsupported schema version");

    assert_eq!(error, "unsupported schema version: 5; supported version: 1");
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
