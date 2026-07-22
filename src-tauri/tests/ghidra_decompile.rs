use std::path::{Path, PathBuf};

use reverse_assistant_lib::models::ghidra_installation::GhidraInstallation;
use reverse_assistant_lib::models::ghidra_session::AnalysisSession;
use reverse_assistant_lib::services::ghidra_decompile::build_decompile_function_args;

fn fake_installation(install_dir: &str, extensions_dir: &str) -> GhidraInstallation {
    GhidraInstallation {
        install_dir: PathBuf::from(install_dir),
        version_label: "ghidra_12.1.2_PUBLIC".to_owned(),
        extensions_dir: PathBuf::from(extensions_dir),
    }
}

fn fake_session(
    project_dir: &str,
    project_name: &str,
    program_path_in_project: &str,
) -> AnalysisSession {
    AnalysisSession {
        project_dir: PathBuf::from(project_dir),
        project_name: project_name.to_owned(),
        program_path_in_project: program_path_in_project.to_owned(),
    }
}

#[test]
fn builds_the_expected_argument_order_and_values() {
    let installation = fake_installation(
        "C:/Tools/ghidra_12.1.2_PUBLIC",
        "C:/Users/test-user/AppData/Roaming/ghidra/ghidra_12.1.2_PUBLIC/Extensions/ReverseAssistantExporter",
    );

    let session = fake_session(
        "C:/Users/test-user/AppData/Roaming/com.dasshopen.reverse-assistant/ghidra-analysis/sample-123",
        "sample",
        "sample.exe",
    );

    let destination_json = Path::new(&session.project_dir)
        .join("decompile-cache")
        .join("123456789.json");

    let invocation =
        build_decompile_function_args(&installation, &session, "0x140001000", &destination_json);

    assert_eq!(
        invocation.program,
        PathBuf::from("C:/Tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless.bat")
    );

    assert_eq!(
        invocation.args,
        vec![
            session.project_dir.to_string_lossy().into_owned(),
            "sample".to_owned(),
            "-process".to_owned(),
            "sample.exe".to_owned(),
            "-noanalysis".to_owned(),
            "-readOnly".to_owned(),
            "-scriptPath".to_owned(),
            installation
                .extensions_dir
                .join("ghidra_scripts")
                .to_string_lossy()
                .into_owned(),
            "-postScript".to_owned(),
            "DecompileFunctionJson.java".to_owned(),
            "0x140001000".to_owned(),
            destination_json.to_string_lossy().into_owned(),
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

    let session = fake_session(
        "C:/Users/test user/AppData/Roaming/com.dasshopen.reverse-assistant/ghidra-analysis/run-1",
        "sample-under-test",
        "sample under test.exe",
    );

    let destination_json = Path::new(&session.project_dir)
        .join("decompile-cache")
        .join("1.json");

    let invocation =
        build_decompile_function_args(&installation, &session, "0x140001000", &destination_json);

    assert_eq!(invocation.args[3], "sample under test.exe");
    assert_eq!(invocation.args.len(), 12);
}
