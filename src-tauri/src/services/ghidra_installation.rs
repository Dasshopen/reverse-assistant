use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::models::ghidra_installation::{validate_ghidra_installation, GhidraInstallation};

const CONFIG_FILE_NAME: &str = "ghidra-installation.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedConfig {
    install_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GhidraInstallationStatus {
    NotConfigured,
    Invalid {
        install_dir: PathBuf,
        reason: String,
    },
    Valid {
        installation: GhidraInstallation,
    },
}

fn real_ghidra_config_root(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .config_dir()
        .map(|dir| dir.join("ghidra"))
        .map_err(|error| format!("unable to resolve the Ghidra configuration directory: {error}"))
}

fn config_file_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join(CONFIG_FILE_NAME))
        .map_err(|error| {
            format!("unable to resolve the application configuration directory: {error}")
        })
}

pub fn validate_installation(
    app: &AppHandle,
    install_dir: &Path,
) -> Result<GhidraInstallation, String> {
    let ghidra_config_root = real_ghidra_config_root(app)?;

    validate_ghidra_installation(install_dir, &ghidra_config_root)
}

pub fn load_persisted_install_dir(app: &AppHandle) -> Result<Option<PathBuf>, String> {
    let config_path = config_file_path(app)?;

    if !config_path.is_file() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&config_path).map_err(|error| {
        format!(
            "failed to read persisted Ghidra installation config '{}': {error}",
            config_path.display()
        )
    })?;

    let config: PersistedConfig = serde_json::from_str(&contents).map_err(|error| {
        format!(
            "persisted Ghidra installation config is corrupt '{}': {error}",
            config_path.display()
        )
    })?;

    Ok(Some(config.install_dir))
}

pub fn persist_install_dir(app: &AppHandle, install_dir: &Path) -> Result<(), String> {
    let config_path = config_file_path(app)?;

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create the application configuration directory '{}': {error}",
                parent.display()
            )
        })?;
    }

    let config = PersistedConfig {
        install_dir: install_dir.to_path_buf(),
    };

    let json = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("failed to serialize the Ghidra installation config: {error}"))?;

    fs::write(&config_path, json).map_err(|error| {
        format!(
            "failed to write the Ghidra installation config '{}': {error}",
            config_path.display()
        )
    })
}

pub fn configure_and_persist(
    app: &AppHandle,
    install_dir: &Path,
) -> Result<GhidraInstallation, String> {
    let installation = validate_installation(app, install_dir)?;

    persist_install_dir(app, install_dir)?;

    Ok(installation)
}

pub fn current_installation_status(app: &AppHandle) -> Result<GhidraInstallationStatus, String> {
    let Some(install_dir) = load_persisted_install_dir(app)? else {
        return Ok(GhidraInstallationStatus::NotConfigured);
    };

    match validate_installation(app, &install_dir) {
        Ok(installation) => Ok(GhidraInstallationStatus::Valid { installation }),
        Err(reason) => Ok(GhidraInstallationStatus::Invalid {
            install_dir,
            reason,
        }),
    }
}
