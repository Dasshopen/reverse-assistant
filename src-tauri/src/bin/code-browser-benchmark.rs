// Read-only Ghidra project access; writes only the normal browser caches.
use reverse_assistant_lib::{
    models::{ghidra_installation::GhidraInstallation, ghidra_session::AnalysisSession},
    services::ghidra_browser::run_browser_function,
};
use std::{path::PathBuf, time::Instant};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 6 {
        return Err("usage: code-browser-benchmark <ghidra-dir> <extension-dir> <project-dir> <project-name> <program> <address>".to_owned());
    }
    let installation = GhidraInstallation {
        install_dir: PathBuf::from(&args[0]),
        extensions_dir: PathBuf::from(&args[1]),
        version_label: "benchmark".to_owned(),
        java_home: None,
    };
    let session = AnalysisSession {
        project_dir: PathBuf::from(&args[2]),
        project_name: args[3].clone(),
        program_path_in_project: args[4].clone(),
    };
    for label in ["first load", "cached load"] {
        let start = Instant::now();
        let result = run_browser_function(&installation, &session, &args[5])?;
        let listing = result
            .disassembly
            .ok_or_else(|| result.disassembly_error.unwrap_or_default())?;
        let details = result
            .details
            .ok_or_else(|| result.decompile_error.unwrap_or_default())?;
        println!(
            "{label}: {:.3}s, {} instructions, pseudocode={}, BSim={}",
            start.elapsed().as_secs_f64(),
            listing.instructions.len(),
            details.decompiled_code.is_some(),
            details.bsim.status
        );
    }
    Ok(())
}
