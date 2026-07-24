use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use reverse_assistant_lib::models::ghidra_installation::validate_ghidra_installation;

static UNIQUE_SUFFIX: AtomicU32 = AtomicU32::new(0);

fn unique_temp_dir(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after the epoch")
        .as_nanos();

    let suffix = UNIQUE_SUFFIX.fetch_add(1, Ordering::SeqCst);

    let dir = std::env::temp_dir().join(format!(
        "ra-ghidra-install-test-{test_name}-{nanos}-{suffix}"
    ));

    fs::create_dir_all(&dir).expect("failed to create a temporary test directory");

    dir
}

fn write_file(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("path should have a parent")).unwrap();
    fs::write(path, contents).expect("failed to write a test fixture file");
}

struct FakeGhidraSetup {
    install_dir: PathBuf,
    config_root: PathBuf,
}

fn build_fake_installation(test_name: &str, version_label: &str) -> FakeGhidraSetup {
    let base = unique_temp_dir(test_name);

    let install_dir = base.join(version_label);
    write_file(
        &install_dir.join("support/analyzeHeadless.bat"),
        "@echo off\n",
    );

    let config_root = base.join("ghidra-config-root");

    FakeGhidraSetup {
        install_dir,
        config_root,
    }
}

fn install_extension(setup: &FakeGhidraSetup, version_label: &str) {
    let extensions_dir = setup
        .config_root
        .join(version_label)
        .join("Extensions")
        .join("ReverseAssistantExporter");

    write_file(
        &extensions_dir.join("lib/ReverseAssistantExporter.jar"),
        "fake-jar-bytes",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/ExportReverseAssistantJson.java"),
        "// fake script\n",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/DecompileFunctionJson.java"),
        "// fake script\n",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/ApplyFunctionRenamesJson.java"),
        "// fake script\n",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/DisableSlowAnalyzers.java"),
        "// fake script\n",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/IdentifyFunctionsJson.java"),
        "// fake script\n",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/QueryBsimFunctionsJson.java"),
        "// fake script\n",
    );
}

#[test]
fn valid_installation_with_extension_installed_is_accepted() {
    let setup = build_fake_installation("happy-path", "ghidra_12.1.2_PUBLIC");
    install_extension(&setup, "ghidra_12.1.2_PUBLIC");

    let installation = validate_ghidra_installation(&setup.install_dir, &setup.config_root)
        .expect("a fully valid installation should be accepted");

    assert_eq!(installation.version_label, "ghidra_12.1.2_PUBLIC");
    assert_eq!(
        installation.extensions_dir,
        setup
            .config_root
            .join("ghidra_12.1.2_PUBLIC")
            .join("Extensions")
            .join("ReverseAssistantExporter")
    );
}

#[test]
fn missing_apply_renames_script_is_rejected() {
    let setup = build_fake_installation("missing-apply-renames", "ghidra_12.1.2_PUBLIC");
    install_extension(&setup, "ghidra_12.1.2_PUBLIC");
    let script = setup
        .config_root
        .join("ghidra_12.1.2_PUBLIC/Extensions/ReverseAssistantExporter/ghidra_scripts/ApplyFunctionRenamesJson.java");
    fs::remove_file(script).expect("the fake rename script should be removable");

    let error = validate_ghidra_installation(&setup.install_dir, &setup.config_root)
        .expect_err("a missing rename script should be rejected");
    assert!(error.contains("function-rename script is missing"));
}

#[test]
fn missing_install_directory_is_rejected() {
    let base = unique_temp_dir("missing-install-dir");
    let install_dir = base.join("does-not-exist");
    let config_root = base.join("ghidra-config-root");

    let error = validate_ghidra_installation(&install_dir, &config_root)
        .expect_err("a missing install directory should be rejected");

    assert!(
        error.starts_with("Ghidra install directory does not exist"),
        "unexpected error: {error}"
    );
}

#[test]
fn missing_analyze_headless_script_is_rejected() {
    let base = unique_temp_dir("missing-analyze-headless");
    let install_dir = base.join("ghidra_12.1.2_PUBLIC");
    fs::create_dir_all(&install_dir).unwrap();
    let config_root = base.join("ghidra-config-root");

    let error = validate_ghidra_installation(&install_dir, &config_root)
        .expect_err("a missing analyzeHeadless.bat should be rejected");

    assert!(
        error.starts_with("analyzeHeadless.bat was not found"),
        "unexpected error: {error}"
    );
}

#[test]
fn unsupported_version_prefix_is_rejected() {
    let setup = build_fake_installation("unsupported-version", "ghidra_11.0_PUBLIC");

    let error = validate_ghidra_installation(&setup.install_dir, &setup.config_root)
        .expect_err("an unsupported Ghidra version should be rejected");

    assert_eq!(
        error,
        "unsupported Ghidra version: ghidra_11.0_PUBLIC; supported versions start with ghidra_12."
    );
}

#[test]
fn missing_extension_jar_is_rejected() {
    let setup = build_fake_installation("missing-jar", "ghidra_12.1.2_PUBLIC");

    let error = validate_ghidra_installation(&setup.install_dir, &setup.config_root)
        .expect_err("a missing extension jar should be rejected");

    assert!(
        error.contains("the Reverse Assistant Ghidra extension is not installed"),
        "unexpected error: {error}"
    );
    assert!(
        error.contains("deploy-ghidra-extension.ps1"),
        "the error should point at the deployment script: {error}"
    );
}

#[test]
fn missing_headless_script_is_rejected() {
    let setup = build_fake_installation("missing-script", "ghidra_12.1.2_PUBLIC");

    let extensions_dir = setup
        .config_root
        .join("ghidra_12.1.2_PUBLIC")
        .join("Extensions")
        .join("ReverseAssistantExporter");

    write_file(
        &extensions_dir.join("lib/ReverseAssistantExporter.jar"),
        "fake-jar-bytes",
    );

    let error = validate_ghidra_installation(&setup.install_dir, &setup.config_root)
        .expect_err("a missing headless script should be rejected");

    assert!(
        error.contains("headless export script is missing"),
        "unexpected error: {error}"
    );
}

#[test]
fn missing_decompile_script_is_rejected() {
    let setup = build_fake_installation("missing-decompile-script", "ghidra_12.1.2_PUBLIC");

    let extensions_dir = setup
        .config_root
        .join("ghidra_12.1.2_PUBLIC")
        .join("Extensions")
        .join("ReverseAssistantExporter");

    write_file(
        &extensions_dir.join("lib/ReverseAssistantExporter.jar"),
        "fake-jar-bytes",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/ExportReverseAssistantJson.java"),
        "// fake script\n",
    );

    let error = validate_ghidra_installation(&setup.install_dir, &setup.config_root)
        .expect_err("a missing decompile script should be rejected");

    assert!(
        error.contains("on-demand decompile script is missing"),
        "unexpected error: {error}"
    );
}

#[test]
fn missing_disable_slow_analyzers_script_is_rejected() {
    let setup = build_fake_installation("missing-disable-analyzers-script", "ghidra_12.1.2_PUBLIC");

    let extensions_dir = setup
        .config_root
        .join("ghidra_12.1.2_PUBLIC")
        .join("Extensions")
        .join("ReverseAssistantExporter");

    write_file(
        &extensions_dir.join("lib/ReverseAssistantExporter.jar"),
        "fake-jar-bytes",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/ExportReverseAssistantJson.java"),
        "// fake script\n",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/DecompileFunctionJson.java"),
        "// fake script\n",
    );

    let error = validate_ghidra_installation(&setup.install_dir, &setup.config_root)
        .expect_err("a missing analyzer-tuning script should be rejected");

    assert!(
        error.contains("analyzer-tuning script is missing"),
        "unexpected error: {error}"
    );
}

#[test]
fn missing_identify_functions_script_is_rejected() {
    let setup = build_fake_installation("missing-identify-script", "ghidra_12.1.2_PUBLIC");

    let extensions_dir = setup
        .config_root
        .join("ghidra_12.1.2_PUBLIC")
        .join("Extensions")
        .join("ReverseAssistantExporter");

    write_file(
        &extensions_dir.join("lib/ReverseAssistantExporter.jar"),
        "fake-jar-bytes",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/ExportReverseAssistantJson.java"),
        "// fake script\n",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/DecompileFunctionJson.java"),
        "// fake script\n",
    );

    write_file(
        &extensions_dir.join("ghidra_scripts/DisableSlowAnalyzers.java"),
        "// fake script\n",
    );

    let error = validate_ghidra_installation(&setup.install_dir, &setup.config_root)
        .expect_err("a missing FunctionID identification script should be rejected");

    assert!(
        error.contains("FunctionID identification script is missing"),
        "unexpected error: {error}"
    );
}
