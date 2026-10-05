use crate::services::background_process::background_command;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::models::ghidra_export::is_valid_address;
use crate::models::ghidra_installation::{configure_java_environment, GhidraInstallation};
use crate::models::ghidra_session::AnalysisSession;
use crate::services::ghidra_headless::{tail, HEADLESS_MAX_HEAP};
use crate::services::ghidra_installation::{load_persisted_install_dir, validate_installation};

const DISASSEMBLE_SCRIPT_NAME: &str = "DisassembleFunctionJson.java";
const DISASSEMBLE_MANY_SCRIPT_NAME: &str = "DisassembleFunctionsJson.java";
const STDERR_TAIL_BYTES: usize = 4000;
// Same purpose as DECOMPILE_CACHE_VERSION: bump whenever the Java result
// shape changes, so a stale cached file from a previous app version is
// never silently reused.
const DISASSEMBLE_CACHE_VERSION: &str = "listing-v2";

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

// A bounded page of a "whole program" listing: the caller picks which
// function addresses belong on this page (from the already-loaded export),
// so this never asks Ghidra to walk the entire program in one call -- a
// real ~3,300-function DLL produced 250k+ instructions in testing, far too
// much for one response or one renderable table.
pub fn build_disassemble_functions_args(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    entry_addresses: &[String],
    destination_json: &Path,
) -> DisassembleFunctionInvocation {
    let program = installation
        .install_dir
        .join("support")
        .join("analyzeHeadless.bat");

    let scripts_dir = installation.extensions_dir.join("ghidra_scripts");

    let mut args = vec![
        session.project_dir.to_string_lossy().into_owned(),
        session.project_name.clone(),
        "-process".to_owned(),
        session.program_path_in_project.clone(),
        "-noanalysis".to_owned(),
        "-readOnly".to_owned(),
        "-scriptPath".to_owned(),
        scripts_dir.to_string_lossy().into_owned(),
        "-postScript".to_owned(),
        DISASSEMBLE_MANY_SCRIPT_NAME.to_owned(),
        destination_json.to_string_lossy().into_owned(),
    ];

    args.extend(entry_addresses.iter().cloned());

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
    pub function_address: String,
    pub function_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionDisassembly {
    pub instructions: Vec<DisassembledInstruction>,
}

pub(crate) fn parse_disassembly_result(json: &str) -> Result<FunctionDisassembly, String> {
    serde_json::from_str::<FunctionDisassembly>(json)
        .map_err(|error| format!("invalid disassembly result JSON from Ghidra: {error}"))
}

fn disassemble_cache_path(cache_dir: &Path, entry_address: &str) -> PathBuf {
    cache_dir.join(format!(
        "{}-{DISASSEMBLE_CACHE_VERSION}.json",
        &entry_address[2..],
    ))
}

// A short, order-sensitive hash of a page's function addresses -- a page
// with the same addresses in the same order always maps to the same
// cached file, without needing to invent a separate "page number" concept
// that could drift from what the frontend actually requested.
fn addresses_cache_key(entry_addresses: &[String]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    for address in entry_addresses {
        hasher.update(address.as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn disassemble_many_cache_path(cache_dir: &Path, cache_key: &str) -> PathBuf {
    cache_dir.join(format!("page-{cache_key}-{DISASSEMBLE_CACHE_VERSION}.json"))
}

fn validate_entry_address(entry_address: &str) -> Result<(), String> {
    if !is_valid_address(entry_address) {
        return Err(
            "entry_address must be a lowercase hexadecimal string beginning with 0x".to_owned(),
        );
    }

    Ok(())
}

// Shared by both the single-function and the bounded-page paths: read a
// cached result if one exists and parses cleanly, otherwise run the given
// invocation and read back what Ghidra wrote.
fn read_cached_or_run(
    installation: &GhidraInstallation,
    invocation: &DisassembleFunctionInvocation,
    destination_json: &Path,
) -> Result<FunctionDisassembly, String> {
    // Same reasoning as the decompile cache: a read-only headless session
    // over an immutable project means a cached listing never goes stale.
    if let Ok(json) = fs::read_to_string(destination_json) {
        if let Ok(cached) = parse_disassembly_result(&json) {
            return Ok(cached);
        }

        let _ = fs::remove_file(destination_json);
    }

    let mut command = background_command(&invocation.program);
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

    let json = fs::read_to_string(destination_json).map_err(|error| {
        format!(
            "failed to read the disassembly result '{}': {error}",
            destination_json.display()
        )
    })?;

    parse_disassembly_result(&json)
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
    let invocation =
        build_disassemble_function_args(installation, session, entry_address, &destination_json);

    read_cached_or_run(installation, &invocation, &destination_json)
}

// Disassembles a bounded page of functions (picked by the caller from the
// already-loaded export) for a "whole program" Code Browser view -- never
// the entire program in one call. A real ~3,300-function DLL produced
// 250k+ instructions when walked whole in testing, far too much for one
// response or one renderable table.
pub fn run_disassemble_functions(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    entry_addresses: &[String],
) -> Result<FunctionDisassembly, String> {
    for entry_address in entry_addresses {
        validate_entry_address(entry_address)?;
    }

    if entry_addresses.is_empty() {
        return Ok(FunctionDisassembly {
            instructions: Vec::new(),
        });
    }

    let cache_dir = session.project_dir.join("disassemble-cache");

    fs::create_dir_all(&cache_dir).map_err(|error| {
        format!(
            "failed to create the disassembly working directory '{}': {error}",
            cache_dir.display()
        )
    })?;

    let cache_key = addresses_cache_key(entry_addresses);
    let destination_json = disassemble_many_cache_path(&cache_dir, &cache_key);
    let invocation =
        build_disassemble_functions_args(installation, session, entry_addresses, &destination_json);

    read_cached_or_run(installation, &invocation, &destination_json)
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

pub fn disassemble_functions(
    app: &AppHandle,
    session: &AnalysisSession,
    entry_addresses: &[String],
) -> Result<FunctionDisassembly, String> {
    let install_dir = load_persisted_install_dir(app)?.ok_or_else(|| {
        "No Ghidra installation is configured. Configure one before disassembling functions."
            .to_owned()
    })?;

    let installation = validate_installation(app, &install_dir)?;

    run_disassemble_functions(&installation, session, entry_addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_installation() -> GhidraInstallation {
        GhidraInstallation {
            install_dir: PathBuf::from("Z:/this-ghidra-installation-does-not-exist"),
            version_label: "ghidra_12.1.2_PUBLIC".to_owned(),
            extensions_dir: PathBuf::from("Z:/this-extension-does-not-exist"),
            java_home: None,
        }
    }

    #[test]
    fn cache_path_is_stable_and_versioned() {
        assert_eq!(
            disassemble_cache_path(Path::new("cache"), "0x400664"),
            PathBuf::from("cache/400664-listing-v2.json")
        );
    }

    #[test]
    fn addresses_cache_key_is_stable_and_order_sensitive() {
        let forward = vec!["0x400664".to_owned(), "0x400700".to_owned()];
        let reversed = vec!["0x400700".to_owned(), "0x400664".to_owned()];

        assert_eq!(addresses_cache_key(&forward), addresses_cache_key(&forward));
        assert_ne!(
            addresses_cache_key(&forward),
            addresses_cache_key(&reversed)
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
                        "fall_through_address": "0x400665",
                        "function_address": "0x400664",
                        "function_name": "authenticate"
                    },
                    {
                        "address": "0x4006ec",
                        "length": 1,
                        "bytes": "c3",
                        "mnemonic": "RET",
                        "operands": "",
                        "flow_category": "terminator",
                        "fall_through_address": null,
                        "function_address": "0x400664",
                        "function_name": "authenticate"
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
        assert_eq!(disassembly.instructions[0].function_name, "authenticate");
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
                        "fall_through_address": "0x400665",
                        "function_address": "0x400664",
                        "function_name": "authenticate"
                    }
                ]
            }"#,
        )
        .expect("the cached result should be written");

        let installation = fake_installation();
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
    fn a_cached_page_of_functions_does_not_launch_ghidra() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock should be after the Unix epoch")
            .as_nanos();
        let project_dir = std::env::temp_dir().join(format!(
            "reverse-assistant-disassemble-many-cache-test-{unique_suffix}"
        ));
        let cache_dir = project_dir.join("disassemble-cache");
        fs::create_dir_all(&cache_dir).expect("the test cache directory should be created");

        let entry_addresses = vec!["0x400664".to_owned(), "0x400700".to_owned()];
        let cache_key = addresses_cache_key(&entry_addresses);
        fs::write(
            disassemble_many_cache_path(&cache_dir, &cache_key),
            r#"{
                "instructions": [
                    {
                        "address": "0x400664",
                        "length": 1,
                        "bytes": "55",
                        "mnemonic": "PUSH",
                        "operands": "RBP",
                        "flow_category": "fall_through",
                        "fall_through_address": "0x400665",
                        "function_address": "0x400664",
                        "function_name": "authenticate"
                    },
                    {
                        "address": "0x400700",
                        "length": 1,
                        "bytes": "55",
                        "mnemonic": "PUSH",
                        "operands": "RBP",
                        "flow_category": "fall_through",
                        "fall_through_address": "0x400701",
                        "function_address": "0x400700",
                        "function_name": "main"
                    }
                ]
            }"#,
        )
        .expect("the cached result should be written");

        let installation = fake_installation();
        let session = AnalysisSession {
            project_dir: project_dir.clone(),
            project_name: "cached-test".to_owned(),
            program_path_in_project: "cached-test.exe".to_owned(),
        };

        let result = run_disassemble_functions(&installation, &session, &entry_addresses)
            .expect("a valid cached page should bypass the missing Ghidra executable");

        assert_eq!(result.instructions.len(), 2);
        assert_eq!(result.instructions[0].function_name, "authenticate");
        assert_eq!(result.instructions[1].function_name, "main");

        fs::remove_dir_all(&project_dir).expect("the isolated test directory should be removed");
    }

    #[test]
    fn an_empty_page_of_functions_is_a_no_op() {
        let installation = fake_installation();
        let session = AnalysisSession {
            project_dir: PathBuf::from("Z:/does-not-exist"),
            project_name: "test".to_owned(),
            program_path_in_project: "test.exe".to_owned(),
        };

        let result = run_disassemble_functions(&installation, &session, &[])
            .expect("an empty page should not attempt to launch Ghidra");

        assert!(result.instructions.is_empty());
    }

    #[test]
    fn an_invalid_entry_address_is_rejected_before_touching_the_filesystem() {
        let installation = fake_installation();
        let session = AnalysisSession {
            project_dir: PathBuf::from("Z:/does-not-exist"),
            project_name: "test".to_owned(),
            program_path_in_project: "test.exe".to_owned(),
        };

        let error = run_disassemble_function(&installation, &session, "not-an-address")
            .expect_err("an invalid address should be rejected");

        assert!(error.contains("hexadecimal"));
    }

    #[test]
    fn an_invalid_address_in_a_page_is_rejected_before_touching_the_filesystem() {
        let installation = fake_installation();
        let session = AnalysisSession {
            project_dir: PathBuf::from("Z:/does-not-exist"),
            project_name: "test".to_owned(),
            program_path_in_project: "test.exe".to_owned(),
        };

        let error = run_disassemble_functions(
            &installation,
            &session,
            &["0x400664".to_owned(), "not-an-address".to_owned()],
        )
        .expect_err("an invalid address anywhere in the page should be rejected");

        assert!(error.contains("hexadecimal"));
    }
}
