use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::models::ghidra_export::is_valid_address;
use crate::models::ghidra_installation::{configure_java_environment, GhidraInstallation};
use crate::models::ghidra_session::AnalysisSession;
use crate::services::ghidra_headless::{tail, HEADLESS_MAX_HEAP};
use crate::services::ghidra_installation::{load_persisted_install_dir, validate_installation};

const DISASSEMBLE_SCRIPT_NAME: &str = "DisassembleFunctionJson.java";
const STDERR_TAIL_BYTES: usize = 4000;
// Same purpose as DECOMPILE_CACHE_VERSION: bump whenever the Java result
// shape changes, so a stale cached file from a previous app version is
// never silently reused.
const DISASSEMBLE_CACHE_VERSION: &str = "listing-v1";

#[derive(Debug, Clone, PartialEq)]
pub struct DisassembleFunctionInvocation {
    pub program: PathBuf,
    pub args: Vec<String>,
}

pub fn build_disassemble_function_args(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    entry_address: &str,
    destination_json: &Path,
) -> DisassembleFunctionInvocation {
    let program = installation
        .install_dir
        .join("support")
        .join("analyzeHeadless.bat");

    let scripts_dir = installation.extensions_dir.join("ghidra_scripts");

    let args = vec![
        session.project_dir.to_string_lossy().into_owned(),
        session.project_name.clone(),
        "-process".to_owned(),
        session.program_path_in_project.clone(),
        "-noanalysis".to_owned(),
        "-readOnly".to_owned(),
        "-scriptPath".to_owned(),
        scripts_dir.to_string_lossy().into_owned(),
        "-postScript".to_owned(),
        DISASSEMBLE_SCRIPT_NAME.to_owned(),
        entry_address.to_owned(),
        destination_json.to_string_lossy().into_owned(),
    ];

    DisassembleFunctionInvocation { program, args }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisassembledInstruction {
    pub address: String,
    pub length: u32,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub flow_category: String,
    pub fall_through_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionDisassembly {
    pub instructions: Vec<DisassembledInstruction>,
}

fn parse_disassembly_result(json: &str) -> Result<FunctionDisassembly, String> {
    serde_json::from_str::<FunctionDisassembly>(json)
        .map_err(|error| format!("invalid disassembly result JSON from Ghidra: {error}"))
}

fn disassemble_cache_path(cache_dir: &Path, entry_address: &str) -> PathBuf {
    cache_dir.join(format!(
        "{}-{DISASSEMBLE_CACHE_VERSION}.json",
        &entry_address[2..],
    ))
}

fn validate_entry_address(entry_address: &str) -> Result<(), String> {
    if !is_valid_address(entry_address) {
        return Err(
            "entry_address must be a lowercase hexadecimal string beginning with 0x".to_owned(),
        );
    }

    Ok(())
}

pub fn run_disassemble_function(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    entry_address: &str,
) -> Result<FunctionDisassembly, String> {
    validate_entry_address(entry_address)?;

    let cache_dir = session.project_dir.join("disassemble-cache");

    fs::create_dir_all(&cache_dir).map_err(|error| {
        format!(
            "failed to create the disassembly working directory '{}': {error}",
            cache_dir.display()
        )
    })?;

    let destination_json = disassemble_cache_path(&cache_dir, entry_address);

    // Same reasoning as the decompile cache: a read-only headless session
    // over an immutable project means a cached listing for this address
    // never goes stale.
    if let Ok(json) = fs::read_to_string(&destination_json) {
        if let Ok(cached) = parse_disassembly_result(&json) {
            return Ok(cached);
        }

        let _ = fs::remove_file(&destination_json);
    }

    let invocation =
        build_disassemble_function_args(installation, session, entry_address, &destination_json);

    let mut command = Command::new(&invocation.program);
    command
        .args(&invocation.args)
        .env("GHIDRA_HEADLESS_MAXMEM", HEADLESS_MAX_HEAP);
    configure_java_environment(&mut command, installation);
    let output = command.output().map_err(|error| {
        format!(
            "failed to launch Ghidra headless analyzer '{}': {error}",
            invocation.program.display()
        )
    })?;

    if !output.status.success() {
        return Err(format!(
            "Ghidra on-demand disassembly failed (exit code {:?}): {}",
            output.status.code(),
            tail(&output.stderr, STDERR_TAIL_BYTES)
        ));
    }

    if !destination_json.is_file() {
        return Err(format!(
            "Ghidra on-demand disassembly completed but produced no result file at '{}'",
            destination_json.display()
        ));
    }

    let json = fs::read_to_string(&destination_json).map_err(|error| {
        format!(
            "failed to read the disassembly result '{}': {error}",
            destination_json.display()
        )
    })?;

    parse_disassembly_result(&json)
}

pub fn disassemble_function(
    app: &AppHandle,
    session: &AnalysisSession,
    entry_address: &str,
) -> Result<FunctionDisassembly, String> {
    let install_dir = load_persisted_install_dir(app)?.ok_or_else(|| {
        "No Ghidra installation is configured. Configure one before disassembling a function."
            .to_owned()
    })?;

    let installation = validate_installation(app, &install_dir)?;

    run_disassemble_function(&installation, session, entry_address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_is_stable_and_versioned() {
        assert_eq!(
            disassemble_cache_path(Path::new("cache"), "0x400664"),
            PathBuf::from("cache/400664-listing-v1.json")
        );
    }

    #[test]
    fn parses_a_real_shaped_disassembly_result() {
        let disassembly = parse_disassembly_result(
            r#"{
                "instructions": [
                    {
                        "address": "0x400664",
                        "length": 1,
                        "bytes": "55",
                        "mnemonic": "PUSH",
                        "operands": "RBP",
                        "flow_category": "fall_through",
                        "fall_through_address": "0x400665"
                    },
                    {
                        "address": "0x4006ec",
                        "length": 1,
                        "bytes": "c3",
                        "mnemonic": "RET",
                        "operands": "",
                        "flow_category": "terminator",
                        "fall_through_address": null
                    }
                ]
            }"#,
        )
        .expect("a valid disassembly result should parse");

        assert_eq!(disassembly.instructions.len(), 2);
        assert_eq!(disassembly.instructions[0].mnemonic, "PUSH");
        assert_eq!(
            disassembly.instructions[0].fall_through_address.as_deref(),
            Some("0x400665")
        );
        assert_eq!(disassembly.instructions[1].mnemonic, "RET");
        assert_eq!(disassembly.instructions[1].flow_category, "terminator");
        assert_eq!(disassembly.instructions[1].fall_through_address, None);
    }

    #[test]
    fn cached_result_does_not_launch_ghidra() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock should be after the Unix epoch")
            .as_nanos();
        let project_dir = std::env::temp_dir().join(format!(
            "reverse-assistant-disassemble-cache-test-{unique_suffix}"
        ));
        let cache_dir = project_dir.join("disassemble-cache");
        fs::create_dir_all(&cache_dir).expect("the test cache directory should be created");

        let entry_address = "0x400664";
        fs::write(
            disassemble_cache_path(&cache_dir, entry_address),
            r#"{
                "instructions": [
                    {
                        "address": "0x400664",
                        "length": 1,
                        "bytes": "55",
                        "mnemonic": "PUSH",
                        "operands": "RBP",
                        "flow_category": "fall_through",
                        "fall_through_address": "0x400665"
                    }
                ]
            }"#,
        )
        .expect("the cached result should be written");

        let installation = GhidraInstallation {
            install_dir: PathBuf::from("Z:/this-ghidra-installation-does-not-exist"),
            version_label: "ghidra_12.1.2_PUBLIC".to_owned(),
            extensions_dir: PathBuf::from("Z:/this-extension-does-not-exist"),
            java_home: None,
        };
        let session = AnalysisSession {
            project_dir: project_dir.clone(),
            project_name: "cached-test".to_owned(),
            program_path_in_project: "cached-test.exe".to_owned(),
        };

        let result = run_disassemble_function(&installation, &session, entry_address)
            .expect("a valid cached result should bypass the missing Ghidra executable");

        assert_eq!(result.instructions.len(), 1);
        assert_eq!(result.instructions[0].mnemonic, "PUSH");

        fs::remove_dir_all(&project_dir).expect("the isolated test directory should be removed");
    }

    #[test]
    fn an_invalid_entry_address_is_rejected_before_touching_the_filesystem() {
        let installation = GhidraInstallation {
            install_dir: PathBuf::from("Z:/this-ghidra-installation-does-not-exist"),
            version_label: "ghidra_12.1.2_PUBLIC".to_owned(),
            extensions_dir: PathBuf::from("Z:/this-extension-does-not-exist"),
            java_home: None,
        };
        let session = AnalysisSession {
            project_dir: PathBuf::from("Z:/does-not-exist"),
            project_name: "test".to_owned(),
            program_path_in_project: "test.exe".to_owned(),
        };

        let error = run_disassemble_function(&installation, &session, "not-an-address")
            .expect_err("an invalid address should be rejected");

        assert!(error.contains("hexadecimal"));
    }
}
