//! Interactive code display: one JVM/project open, no BSim work.
use std::{fs, path::Path, process::Command};

use serde::Serialize;
use tauri::AppHandle;

use super::{
    ghidra_decompile::{
        build_decompile_function_args, parse_decompile_result, DecompiledFunctionDetails,
    },
    ghidra_disassemble::{
        build_disassemble_function_args, parse_disassembly_result, DisassembleFunctionInvocation,
        FunctionDisassembly,
    },
    ghidra_headless::{tail, HEADLESS_MAX_HEAP},
    ghidra_installation::{load_persisted_install_dir, validate_installation},
};
use crate::models::{
    ghidra_export::is_valid_address,
    ghidra_installation::{configure_java_environment, GhidraInstallation},
    ghidra_session::AnalysisSession,
};

#[derive(Debug, Serialize)]
pub struct BrowserFunctionResult {
    pub details: Option<DecompiledFunctionDetails>,
    pub disassembly: Option<FunctionDisassembly>,
    pub decompile_error: Option<String>,
    pub disassembly_error: Option<String>,
}

pub fn build_browser_function_args(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    address: &str,
    code_path: &Path,
    listing_path: &Path,
    need_code: bool,
    need_listing: bool,
) -> DisassembleFunctionInvocation {
    let mut invocation =
        build_disassemble_function_args(installation, session, address, listing_path);
    // Both builders share the same headless project-opening arguments.
    let listing_script = invocation.args.split_off(
        invocation
            .args
            .iter()
            .position(|arg| arg == "-postScript")
            .unwrap(),
    );
    if need_listing {
        invocation.args.extend(listing_script);
    }
    if need_code {
        let code = build_decompile_function_args(installation, session, address, code_path, &[]);
        let script = code
            .args
            .iter()
            .position(|arg| arg == "-postScript")
            .unwrap();
        invocation.args.extend(code.args[script..].iter().cloned());
    }
    invocation
}

pub fn run_browser_function(
    installation: &GhidraInstallation,
    session: &AnalysisSession,
    address: &str,
) -> Result<BrowserFunctionResult, String> {
    if !is_valid_address(address) {
        return Err("invalid function address".to_owned());
    }
    // This directory is already invalidated by the rename transaction.
    // Browser-only results cannot poison corpus-dependent identification caches.
    let dir = session.project_dir.join("decompile-cache");
    fs::create_dir_all(&dir).map_err(|error| format!("unable to create browser cache: {error}"))?;
    let code = dir.join(format!("{}-browser-v1-code.json", &address[2..]));
    let listing = dir.join(format!("{}-browser-v1-listing.json", &address[2..]));
    let read_code = || {
        fs::read_to_string(&code)
            .ok()
            .and_then(|json| parse_decompile_result(&json).ok())
    };
    let read_listing = || {
        fs::read_to_string(&listing)
            .ok()
            .and_then(|json| parse_disassembly_result(&json).ok())
    };
    let mut details = read_code();
    let mut disassembly = read_listing();
    let mut diagnostic = String::new();
    if details.is_none() || disassembly.is_none() {
        let invocation = build_browser_function_args(
            installation,
            session,
            address,
            &code,
            &listing,
            details.is_none(),
            disassembly.is_none(),
        );
        let mut command = Command::new(&invocation.program);
        command
            .args(invocation.args)
            .env("GHIDRA_HEADLESS_MAXMEM", HEADLESS_MAX_HEAP);
        configure_java_environment(&mut command, installation);
        let output = command
            .output()
            .map_err(|error| format!("unable to launch code browser: {error}"))?;
        // Preserve the successful panel even when the other script fails.
        details = read_code();
        disassembly = read_listing();
        if details.is_none() || disassembly.is_none() {
            diagnostic = format!(
                "{} {}",
                tail(&output.stdout, 2000),
                tail(&output.stderr, 2000)
            );
        }
        if !output.status.success() && details.is_none() && disassembly.is_none() {
            return Err(format!(
                "Ghidra code browser failed: {}",
                tail(&output.stderr, 4000)
            ));
        }
    }
    Ok(BrowserFunctionResult {
        decompile_error: if details.is_none() {
            Some(format!(
                "Ghidra n’a pas produit de pseudocode. {diagnostic}"
            ))
        } else {
            None
        },
        disassembly_error: if disassembly.is_none() {
            Some(format!("Ghidra n’a pas produit de listing. {diagnostic}"))
        } else {
            None
        },
        details,
        disassembly,
    })
}

pub fn load_browser_function(
    app: &AppHandle,
    session: &AnalysisSession,
    address: &str,
) -> Result<BrowserFunctionResult, String> {
    let dir = load_persisted_install_dir(app)?
        .ok_or_else(|| "No Ghidra installation is configured.".to_owned())?;
    let installation = validate_installation(app, &dir)?;
    run_browser_function(&installation, session, address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn combined_display_opens_project_once_without_bsim() {
        let installation = GhidraInstallation {
            install_dir: PathBuf::from("ghidra"),
            extensions_dir: PathBuf::from("extension"),
            version_label: "test".to_owned(),
            java_home: None,
        };
        let session = AnalysisSession {
            project_dir: PathBuf::from("project"),
            project_name: "test".to_owned(),
            program_path_in_project: "chall3".to_owned(),
        };
        for (code, listing) in [(true, true), (true, false), (false, true)] {
            let args = build_browser_function_args(
                &installation,
                &session,
                "0x401100",
                Path::new("code.json"),
                Path::new("listing.json"),
                code,
                listing,
            )
            .args;
            assert_eq!(args.iter().filter(|arg| *arg == "-process").count(), 1);
            assert_eq!(
                args.iter().filter(|arg| *arg == "-postScript").count(),
                usize::from(code) + usize::from(listing)
            );
            assert!(!args.iter().any(|arg| arg == "--bsim-corpus"));
            assert!(args.contains(&"-readOnly".to_owned()));
            assert!(args.contains(&"-noanalysis".to_owned()));
            assert_eq!(
                args.contains(&"DecompileFunctionJson.java".to_owned()),
                code
            );
            assert_eq!(
                args.contains(&"DisassembleFunctionJson.java".to_owned()),
                listing
            );
        }
    }

    #[test]
    fn invalid_address_is_rejected_before_cache_access() {
        let installation = GhidraInstallation {
            install_dir: PathBuf::new(),
            extensions_dir: PathBuf::new(),
            version_label: String::new(),
            java_home: None,
        };
        let session = AnalysisSession {
            project_dir: PathBuf::new(),
            project_name: String::new(),
            program_path_in_project: String::new(),
        };
        assert!(run_browser_function(&installation, &session, "not-an-address").is_err());
    }

    #[test]
    fn complete_cache_works_without_a_ghidra_installation() {
        let scratch = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/browser-cache-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        let cache = scratch.join("decompile-cache");
        fs::create_dir_all(&cache).unwrap();
        fs::write(
            cache.join("401100-browser-v1-code.json"),
            r#"{
            "decompiled_code":"void relay(void) { return; }", "return_type":"void",
            "parameters":[], "calling_convention":"default",
            "bsim":{"status":"unavailable","matches":[],"message":null}
        }"#,
        )
        .unwrap();
        fs::write(
            cache.join("401100-browser-v1-listing.json"),
            r#"{"instructions":[]}"#,
        )
        .unwrap();
        let installation = GhidraInstallation {
            install_dir: PathBuf::from("missing-ghidra"),
            extensions_dir: PathBuf::new(),
            version_label: String::new(),
            java_home: None,
        };
        let session = AnalysisSession {
            project_dir: scratch.clone(),
            project_name: "test".to_owned(),
            program_path_in_project: "test".to_owned(),
        };
        let result = run_browser_function(&installation, &session, "0x401100").unwrap();
        assert!(result.details.unwrap().decompiled_code.is_some());
        assert!(result.disassembly.is_some());
        assert!(result.decompile_error.is_none());
        assert!(result.disassembly_error.is_none());
        fs::remove_dir_all(scratch).unwrap();
    }
}
