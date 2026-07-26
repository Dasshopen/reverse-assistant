use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

pub const SUPPORTED_GHIDRA_VERSION_PREFIX: &str = "ghidra_12.";
const EXTENSION_NAME: &str = "ReverseAssistantExporter";
const EXTENSION_JAR_NAME: &str = "ReverseAssistantExporter.jar";
const HEADLESS_SCRIPT_NAME: &str = "ExportReverseAssistantJson.java";
const DECOMPILE_SCRIPT_NAME: &str = "DecompileFunctionJson.java";
const BATCH_DECOMPILE_SCRIPT_NAME: &str = "DecompileFunctionsJson.java";
const APPLY_RENAMES_SCRIPT_NAME: &str = "ApplyFunctionRenamesJson.java";
const DISABLE_SLOW_ANALYZERS_SCRIPT_NAME: &str = "DisableSlowAnalyzers.java";
const IDENTIFY_FUNCTIONS_SCRIPT_NAME: &str = "IdentifyFunctionsJson.java";
const QUERY_BSIM_FUNCTIONS_SCRIPT_NAME: &str = "QueryBsimFunctionsJson.java";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GhidraInstallation {
    pub install_dir: PathBuf,
    pub version_label: String,
    pub extensions_dir: PathBuf,
    #[serde(default)]
    pub java_home: Option<PathBuf>,
}

pub fn configure_java_environment(command: &mut Command, installation: &GhidraInstallation) {
    let Some(java_home) = installation.java_home.as_ref() else {
        return;
    };

    command.env("JAVA_HOME", java_home);
    let java_bin = java_home.join("bin");
    let mut paths = vec![java_bin];
    if let Some(existing) = env::var_os("PATH") {
        paths.extend(env::split_paths(&existing));
    }
    if let Ok(joined) = env::join_paths(paths) {
        command.env("PATH", joined);
    }
}

pub fn derive_version_label(install_dir: &Path) -> Result<String, String> {
    install_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "unable to determine the Ghidra version from install directory: {}",
                install_dir.display()
            )
        })
}

pub fn resolve_user_extensions_dir(ghidra_config_root: &Path, version_label: &str) -> PathBuf {
    ghidra_config_root
        .join(version_label)
        .join("Extensions")
        .join(EXTENSION_NAME)
}

pub fn validate_ghidra_installation(
    install_dir: &Path,
    ghidra_config_root: &Path,
) -> Result<GhidraInstallation, String> {
    if !install_dir.is_dir() {
        return Err(format!(
            "Ghidra install directory does not exist: {}",
            install_dir.display()
        ));
    }

    let analyze_headless = install_dir.join("support").join("analyzeHeadless.bat");

    if !analyze_headless.is_file() {
        return Err(format!(
            "analyzeHeadless.bat was not found under {}; select the Ghidra installation root (the folder containing 'support')",
            install_dir.display()
        ));
    }

    let version_label = derive_version_label(install_dir)?;

    if !version_label.starts_with(SUPPORTED_GHIDRA_VERSION_PREFIX) {
        return Err(format!(
            "unsupported Ghidra version: {version_label}; supported versions start with {SUPPORTED_GHIDRA_VERSION_PREFIX}"
        ));
    }

    let extensions_dir = resolve_user_extensions_dir(ghidra_config_root, &version_label);
    let extension_jar = extensions_dir.join("lib").join(EXTENSION_JAR_NAME);

    if !extension_jar.is_file() {
        return Err(format!(
            "the Reverse Assistant Ghidra extension is not installed for {version_label} (missing {}); run scripts/deploy-ghidra-extension.ps1 -GhidraInstallDir '{}'",
            extension_jar.display(),
            install_dir.display()
        ));
    }

    let headless_script = extensions_dir
        .join("ghidra_scripts")
        .join(HEADLESS_SCRIPT_NAME);

    if !headless_script.is_file() {
        return Err(format!(
            "the Reverse Assistant headless export script is missing (expected {}); run scripts/deploy-ghidra-extension.ps1 -GhidraInstallDir '{}'",
            headless_script.display(),
            install_dir.display()
        ));
    }

    let decompile_script = extensions_dir
        .join("ghidra_scripts")
        .join(DECOMPILE_SCRIPT_NAME);

    if !decompile_script.is_file() {
        return Err(format!(
            "the Reverse Assistant on-demand decompile script is missing (expected {}); run scripts/deploy-ghidra-extension.ps1 -GhidraInstallDir '{}'",
            decompile_script.display(),
            install_dir.display()
        ));
    }

    let batch_decompile_script = extensions_dir
        .join("ghidra_scripts")
        .join(BATCH_DECOMPILE_SCRIPT_NAME);
    if !batch_decompile_script.is_file() {
        return Err(format!(
            "the Reverse Assistant batch decompile script is missing (expected {}); redeploy the extension",
            batch_decompile_script.display()
        ));
    }

    let disable_slow_analyzers_script = extensions_dir
        .join("ghidra_scripts")
        .join(DISABLE_SLOW_ANALYZERS_SCRIPT_NAME);

    if !disable_slow_analyzers_script.is_file() {
        return Err(format!(
            "the Reverse Assistant analyzer-tuning script is missing (expected {}); run scripts/deploy-ghidra-extension.ps1 -GhidraInstallDir '{}'",
            disable_slow_analyzers_script.display(),
            install_dir.display()
        ));
    }

    let identify_functions_script = extensions_dir
        .join("ghidra_scripts")
        .join(IDENTIFY_FUNCTIONS_SCRIPT_NAME);

    if !identify_functions_script.is_file() {
        return Err(format!(
            "the Reverse Assistant FunctionID identification script is missing (expected {}); run scripts/deploy-ghidra-extension.ps1 -GhidraInstallDir '{}'",
            identify_functions_script.display(),
            install_dir.display()
        ));
    }

    let query_bsim_functions_script = extensions_dir
        .join("ghidra_scripts")
        .join(QUERY_BSIM_FUNCTIONS_SCRIPT_NAME);

    if !query_bsim_functions_script.is_file() {
        return Err(format!(
            "Reverse Assistant BSim scan script is missing at {}; redeploy the extension",
            query_bsim_functions_script.display(),
        ));
    }

    let apply_renames_script = extensions_dir
        .join("ghidra_scripts")
        .join(APPLY_RENAMES_SCRIPT_NAME);

    if !apply_renames_script.is_file() {
        return Err(format!(
            "the Reverse Assistant function-rename script is missing (expected {}); run scripts/deploy-ghidra-extension.ps1 -GhidraInstallDir '{}'",
            apply_renames_script.display(),
            install_dir.display()
        ));
    }

    Ok(GhidraInstallation {
        install_dir: install_dir.to_path_buf(),
        version_label,
        extensions_dir,
        java_home: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_user_extensions_dir_joins_the_expected_layout() {
        let root = Path::new("C:/Users/test-user/AppData/Roaming/ghidra");

        let extensions_dir = resolve_user_extensions_dir(root, "ghidra_12.1.2_PUBLIC");

        assert_eq!(
            extensions_dir,
            root.join("ghidra_12.1.2_PUBLIC")
                .join("Extensions")
                .join("ReverseAssistantExporter")
        );
    }

    #[test]
    fn derive_version_label_uses_the_install_dir_leaf_name() {
        let install_dir = Path::new("C:/Tools/ghidra_12.1.2_PUBLIC");

        assert_eq!(
            derive_version_label(install_dir).expect("a version label should be derived"),
            "ghidra_12.1.2_PUBLIC"
        );
    }
}
