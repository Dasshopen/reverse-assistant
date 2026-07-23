use std::path::{Path, PathBuf};

use reverse_assistant_lib::models::ghidra_installation::GhidraInstallation;
use reverse_assistant_lib::services::ghidra_headless::build_headless_analysis_args;

fn fake_installation(install_dir: &str, extensions_dir: &str) -> GhidraInstallation {
    GhidraInstallation {
        install_dir: PathBuf::from(install_dir),
        version_label: "ghidra_12.1.2_PUBLIC".to_owned(),
        extensions_dir: PathBuf::from(extensions_dir),
    }
}

#[test]
fn builds_the_expected_argument_order_and_values() {
    let installation = fake_installation(
        "C:/Tools/ghidra_12.1.2_PUBLIC",
        "C:/Users/test-user/AppData/Roaming/ghidra/ghidra_12.1.2_PUBLIC/Extensions/ReverseAssistantExporter",
    );

    let project_dir = Path::new(
        "C:/Users/test-user/AppData/Roaming/com.dasshopen.reverse-assistant/ghidra-analysis/sample-123",
    );
    let binary_path = Path::new("C:/binaries/sample.exe");
    let destination_json = project_dir.join("export.json");
    let identifications_json = project_dir.join("identifications.json");

    let invocation = build_headless_analysis_args(
        &installation,
        project_dir,
        "sample",
        binary_path,
        &destination_json,
        &identifications_json,
    );

    assert_eq!(
        invocation.program,
        PathBuf::from("C:/Tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless.bat")
    );

    assert_eq!(
        invocation.args,
        vec![
            project_dir.to_string_lossy().into_owned(),
            "sample".to_owned(),
            "-scriptPath".to_owned(),
            installation
                .extensions_dir
                .join("ghidra_scripts")
                .to_string_lossy()
                .into_owned(),
            "-preScript".to_owned(),
            "DisableSlowAnalyzers.java".to_owned(),
            "-import".to_owned(),
            binary_path.to_string_lossy().into_owned(),
            "-postScript".to_owned(),
            "ExportReverseAssistantJson.java".to_owned(),
            destination_json.to_string_lossy().into_owned(),
            "-postScript".to_owned(),
            "IdentifyFunctionsJson.java".to_owned(),
            identifications_json.to_string_lossy().into_owned(),
        ]
    );

    assert!(
        !invocation
            .args
            .iter()
            .any(|arg| arg.contains(' ') && arg.contains("&&")),
        "arguments must never be a combined shell string"
    );
}

#[test]
fn handles_paths_containing_spaces_as_separate_arguments() {
    let installation = fake_installation(
        "C:/Program Files/ghidra_12.1.2_PUBLIC",
        "C:/Users/test user/AppData/Roaming/ghidra/ghidra_12.1.2_PUBLIC/Extensions/ReverseAssistantExporter",
    );

    let project_dir = Path::new(
        "C:/Users/test user/AppData/Roaming/com.dasshopen.reverse-assistant/ghidra-analysis/run-1",
    );
    let binary_path = Path::new("C:/My Binaries/sample under test.exe");
    let destination_json = project_dir.join("export.json");
    let identifications_json = project_dir.join("identifications.json");

    let invocation = build_headless_analysis_args(
        &installation,
        project_dir,
        "sample-under-test",
        binary_path,
        &destination_json,
        &identifications_json,
    );

    assert_eq!(
        invocation.args[7],
        binary_path.to_string_lossy().into_owned(),
        "the binary path must be passed as a single argument, not split on spaces"
    );

    assert_eq!(invocation.args.len(), 14);
}
