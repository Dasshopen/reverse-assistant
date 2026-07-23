use std::path::PathBuf;

use reverse_assistant_lib::services::ghidra_import::import_ghidra_export;

fn example_export_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/contracts/ghidra-export-v1.example.json")
}

#[test]
fn valid_export_file_is_imported_and_summarized() {
    let imported = import_ghidra_export(&example_export_path())
        .expect("the valid example export should be imported");

    assert_eq!(imported.export.program.name, "sample.exe");

    assert_eq!(imported.summary.function_count, 1);
    assert_eq!(imported.summary.external_function_count, 0);
    assert_eq!(imported.summary.decompiled_function_count, 1);
    assert_eq!(imported.summary.call_count, 1);
    assert_eq!(imported.summary.string_count, 1);
}

#[test]
fn missing_export_file_returns_read_error() {
    let missing_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/does-not-exist.json");

    let error =
        import_ghidra_export(&missing_path).expect_err("a missing export file should be rejected");

    assert!(
        error.starts_with("failed to read Ghidra export"),
        "unexpected error: {error}"
    );

    assert!(
        error.contains("does-not-exist.json"),
        "the error should identify the missing file: {error}"
    );
}

#[test]
fn invalid_json_file_returns_parse_error() {
    let invalid_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/invalid-syntax.json");

    let error =
        import_ghidra_export(&invalid_path).expect_err("invalid JSON syntax should be rejected");

    assert!(
        error.starts_with("invalid Ghidra export JSON:"),
        "unexpected error: {error}"
    );
}

#[test]
fn unsupported_schema_version_file_returns_validation_error() {
    let unsupported_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/unsupported-schema-version.json");

    let error = import_ghidra_export(&unsupported_path)
        .expect_err("an unsupported schema version should be rejected");

    assert_eq!(
        error,
        "unsupported schema version: 5; supported versions: 1, 2"
    );
}

#[test]
fn summary_aggregates_all_functions_calls_and_strings() {
    let export_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multiple-functions.json");

    let imported = import_ghidra_export(&export_path)
        .expect("the multiple-functions export should be imported");

    assert_eq!(imported.summary.function_count, 3);
    assert_eq!(imported.summary.external_function_count, 1);
    assert_eq!(imported.summary.decompiled_function_count, 1);
    assert_eq!(imported.summary.call_count, 3);
    assert_eq!(imported.summary.string_count, 3);
}
