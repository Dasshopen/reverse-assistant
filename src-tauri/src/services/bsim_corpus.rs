use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

use crate::models::ghidra_installation::configure_java_environment;
use crate::services::ghidra_installation::{self, GhidraInstallationStatus};

const CORPUS_FILE_NAME: &str = "reverse-assistant-seed.mv.db";
const CORPUS_PATH_ENV: &str = "REVERSE_ASSISTANT_BSIM_CORPUS_PATH";
pub const DEFAULT_CORPUS_SHA256: &str =
    "849f147b9273626a6fc4d292419d512256cc4504be4ad71fb7d84c70f226e5a9";
const REGISTRY_FILE_NAME: &str = "corpora.json";
const CUSTOM_DIRECTORY_NAME: &str = "custom";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BsimCorpusSummary {
    pub id: String,
    pub name: String,
    pub origin: String,
    pub enabled: bool,
    pub available: bool,
    pub path: PathBuf,
    pub size_bytes: Option<u64>,
    pub libraries: Vec<String>,
    pub description: String,
    pub removable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActiveBsimCorpus {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
struct CorpusRegistry {
    #[serde(default)]
    custom: Vec<CustomCorpusEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct CustomCorpusEntry {
    id: String,
    name: String,
    file_name: String,
    enabled: bool,
    #[serde(default)]
    libraries: Vec<String>,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<(), String> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = hex_encode(&hasher.finalize());

    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(format!(
            "SHA-256 mismatch: expected {expected_hex}, got {actual}"
        ))
    }
}

pub fn cached_db_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("bsim-corpus").join(CORPUS_FILE_NAME)
}

fn corpus_root(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("bsim-corpus")
}

fn registry_path(app_data_dir: &Path) -> PathBuf {
    corpus_root(app_data_dir).join(REGISTRY_FILE_NAME)
}

fn custom_directory(app_data_dir: &Path) -> PathBuf {
    corpus_root(app_data_dir).join(CUSTOM_DIRECTORY_NAME)
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|error| format!("unable to resolve the application data directory: {error}"))
}

fn read_registry(app_data_dir: &Path) -> Result<CorpusRegistry, String> {
    let path = registry_path(app_data_dir);
    if !path.is_file() {
        return Ok(CorpusRegistry::default());
    }

    let json = fs::read_to_string(&path).map_err(|error| {
        format!(
            "failed to read BSim corpus registry '{}': {error}",
            path.display()
        )
    })?;
    serde_json::from_str(&json)
        .map_err(|error| format!("invalid BSim corpus registry '{}': {error}", path.display()))
}

fn write_registry(app_data_dir: &Path, registry: &CorpusRegistry) -> Result<(), String> {
    let path = registry_path(app_data_dir);
    let parent = path
        .parent()
        .ok_or_else(|| "the BSim registry path has no parent directory".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create BSim corpus directory '{}': {error}",
            parent.display()
        )
    })?;
    let json = serde_json::to_string_pretty(registry)
        .map_err(|error| format!("failed to serialize BSim corpus registry: {error}"))?;
    let temporary = parent.join(".corpora.json.tmp");
    fs::write(&temporary, format!("{json}\n")).map_err(|error| {
        format!(
            "failed to write BSim corpus registry '{}': {error}",
            temporary.display()
        )
    })?;
    if path.exists() {
        fs::remove_file(&path).map_err(|error| {
            format!(
                "failed to replace BSim corpus registry '{}': {error}",
                path.display()
            )
        })?;
    }
    fs::rename(&temporary, &path).map_err(|error| {
        format!(
            "failed to install BSim corpus registry '{}': {error}",
            path.display()
        )
    })
}

fn validate_database_file(path: &Path) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !file_name.to_ascii_lowercase().ends_with(".mv.db") {
        return Err("a BSim corpus must be an H2 database whose name ends with .mv.db".to_owned());
    }
    let metadata = fs::metadata(path)
        .map_err(|error| format!("unable to read BSim corpus '{}': {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "the selected BSim corpus is empty or not a file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read BSim corpus '{}': {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex_encode(&hasher.finalize()))
}

pub fn database_url(database_path: &Path) -> Result<String, String> {
    let path = database_path.to_string_lossy();
    let base = path.strip_suffix(".mv.db").ok_or_else(|| {
        format!(
            "BSim corpus path must end with .mv.db: {}",
            database_path.display()
        )
    })?;

    let normalized = base.replace('\\', "/");
    let normalized = if let Some(unc) = normalized.strip_prefix("//?/UNC/") {
        format!("//{unc}")
    } else {
        normalized
            .strip_prefix("//?/")
            .unwrap_or(&normalized)
            .to_owned()
    };

    Ok(format!("file:/{normalized}"))
}

// Until the corpus is published as a release asset, development builds use
// the reproducibly generated database under bsim-corpus/build. An explicit
// environment override and the future app-data cache take precedence.
pub fn locate_available_corpus(app: &AppHandle) -> Result<Option<PathBuf>, String> {
    if let Some(configured) = env::var_os(CORPUS_PATH_ENV) {
        let path = PathBuf::from(configured);

        if !path.is_file() {
            return Err(format!(
                "{CORPUS_PATH_ENV} points to a missing BSim corpus: {}",
                path.display()
            ));
        }

        return fs::canonicalize(&path).map(Some).map_err(|error| {
            format!(
                "failed to resolve the configured BSim corpus '{}': {error}",
                path.display()
            )
        });
    }

    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("unable to resolve the application data directory: {error}"))?;
    locate_default_corpus(app, &app_data_dir)
}

pub fn list_corpora(app: &AppHandle) -> Result<Vec<BsimCorpusSummary>, String> {
    let app_data_dir = app_data_dir(app)?;
    let mut summaries = Vec::new();

    if let Some(configured) = env::var_os(CORPUS_PATH_ENV) {
        let path = PathBuf::from(configured);
        summaries.push(BsimCorpusSummary {
            id: "environment-override".to_owned(),
            name: "Corpus défini par l’environnement".to_owned(),
            origin: "environment".to_owned(),
            enabled: true,
            available: path.is_file(),
            size_bytes: fs::metadata(&path).ok().map(|metadata| metadata.len()),
            path,
            libraries: Vec::new(),
            description: format!("Corpus imposé par la variable {CORPUS_PATH_ENV}."),
            removable: false,
        });
    }

    let default_path = locate_default_corpus(app, &app_data_dir)?;
    let default_display_path = default_path
        .clone()
        .unwrap_or_else(|| cached_db_path(&app_data_dir));
    summaries.push(BsimCorpusSummary {
        id: "reverse-assistant-core".to_owned(),
        name: "Pack essentiel Reverse Assistant".to_owned(),
        origin: "built_in".to_owned(),
        enabled: true,
        available: default_path.is_some(),
        size_bytes: default_path
            .as_ref()
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len()),
        path: default_display_path,
        libraries: vec![
            "SQLite 3.53.3".to_owned(),
            "zlib 1.3.2".to_owned(),
            "LZ4 1.10.0".to_owned(),
            "xxHash 0.8.3".to_owned(),
        ],
        description:
            "Stockage, compression et hachage couramment intégrés aux binaires x64 optimisés."
                .to_owned(),
        removable: false,
    });

    let registry = read_registry(&app_data_dir)?;
    for entry in registry.custom {
        let path = custom_directory(&app_data_dir).join(&entry.file_name);
        summaries.push(BsimCorpusSummary {
            id: entry.id,
            name: entry.name,
            origin: "custom".to_owned(),
            enabled: entry.enabled,
            available: path.is_file(),
            size_bytes: fs::metadata(&path).ok().map(|metadata| metadata.len()),
            path,
            libraries: entry.libraries,
            description: "Corpus personnel importé localement par l’utilisateur.".to_owned(),
            removable: true,
        });
    }

    Ok(summaries)
}

fn locate_default_corpus(app: &AppHandle, app_data_dir: &Path) -> Result<Option<PathBuf>, String> {
    let cached = cached_db_path(app_data_dir);
    if cached.is_file() && file_sha256(&cached)?.eq_ignore_ascii_case(DEFAULT_CORPUS_SHA256) {
        return fs::canonicalize(&cached).map(Some).map_err(|error| {
            format!(
                "failed to resolve cached BSim corpus '{}': {error}",
                cached.display()
            )
        });
    }
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("bsim-corpus")
        .join("build")
        .join(CORPUS_FILE_NAME);
    if development.is_file()
        && file_sha256(&development)?.eq_ignore_ascii_case(DEFAULT_CORPUS_SHA256)
    {
        return fs::canonicalize(&development).map(Some).map_err(|error| {
            format!(
                "failed to resolve development BSim corpus '{}': {error}",
                development.display()
            )
        });
    }
    let _ = app;
    Ok(None)
}

pub fn active_corpora(app: &AppHandle) -> Result<Vec<ActiveBsimCorpus>, String> {
    let mut corpora = Vec::new();
    for summary in list_corpora(app)? {
        if !summary.enabled || !summary.available {
            continue;
        }
        validate_database_file(&summary.path)?;
        corpora.push(ActiveBsimCorpus {
            id: summary.id,
            name: summary.name,
            path: fs::canonicalize(&summary.path).map_err(|error| {
                format!(
                    "failed to resolve BSim corpus '{}': {error}",
                    summary.path.display()
                )
            })?,
        });
    }
    Ok(corpora)
}

pub fn import_custom_corpus(app: &AppHandle, source: &Path) -> Result<BsimCorpusSummary, String> {
    validate_database_file(source)?;
    let app_data_dir = app_data_dir(app)?;
    let hash = file_sha256(source)?;
    let id = format!("custom-{}", &hash[..16]);
    let name = source
        .file_name()
        .and_then(|value| value.to_str())
        .and_then(|value| value.strip_suffix(".mv.db"))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Corpus personnel")
        .to_owned();
    let file_name = format!("{id}.mv.db");
    let directory = custom_directory(&app_data_dir);
    fs::create_dir_all(&directory).map_err(|error| {
        format!(
            "failed to create custom BSim corpus directory '{}': {error}",
            directory.display()
        )
    })?;
    let destination = directory.join(&file_name);
    if !destination.is_file() {
        let temporary = directory.join(format!(".{id}.tmp"));
        fs::copy(source, &temporary).map_err(|error| {
            format!(
                "failed to copy custom BSim corpus '{}': {error}",
                source.display()
            )
        })?;
        if file_sha256(&temporary)? != hash {
            let _ = fs::remove_file(&temporary);
            return Err("the copied BSim corpus failed its SHA-256 integrity check".to_owned());
        }
        fs::rename(&temporary, &destination).map_err(|error| {
            format!(
                "failed to install custom BSim corpus '{}': {error}",
                destination.display()
            )
        })?;
    }

    let mut registry = read_registry(&app_data_dir)?;
    if let Some(existing) = registry.custom.iter_mut().find(|entry| entry.id == id) {
        existing.enabled = true;
    } else {
        registry.custom.push(CustomCorpusEntry {
            id: id.clone(),
            name: name.clone(),
            file_name,
            enabled: true,
            libraries: Vec::new(),
        });
    }
    write_registry(&app_data_dir, &registry)?;
    list_corpora(app)?
        .into_iter()
        .find(|summary| summary.id == id)
        .ok_or_else(|| "the imported BSim corpus was not found in its registry".to_owned())
}

fn command_error(tool: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    let mut tail = details.chars().rev().take(4_000).collect::<String>();
    tail = tail.chars().rev().collect();
    format!("{tool} failed with {}: {}", output.status, tail.trim())
}

fn safe_stem(path: &Path) -> String {
    let raw = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("library");
    let value = raw
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if value.is_empty() {
        "library".to_owned()
    } else {
        value
    }
}

pub fn build_corpus_from_library(
    app: &AppHandle,
    source: &Path,
) -> Result<BsimCorpusSummary, String> {
    let source = fs::canonicalize(source).map_err(|error| {
        format!(
            "unable to resolve the reference library '{}': {error}",
            source.display()
        )
    })?;
    if !source.is_file() {
        return Err(format!(
            "the selected reference library is not a file: {}",
            source.display()
        ));
    }

    let installation = match ghidra_installation::current_installation_status(app)? {
        GhidraInstallationStatus::Valid { installation } => installation,
        GhidraInstallationStatus::NotConfigured => {
            return Err("Ghidra must be installed before adding a reference library".to_owned());
        }
        GhidraInstallationStatus::Invalid { reason, .. } => {
            return Err(format!(
                "the configured Ghidra installation is invalid: {reason}"
            ));
        }
    };

    let app_data_dir = app_data_dir(app)?;
    let source_hash = file_sha256(&source)?;
    let stem = safe_stem(&source);
    let id = format!(
        "library-{}-{}",
        stem.to_ascii_lowercase(),
        &source_hash[..12]
    );
    let file_name = format!("{id}.mv.db");
    let custom_dir = custom_directory(&app_data_dir);
    fs::create_dir_all(&custom_dir).map_err(|error| {
        format!(
            "failed to create custom BSim corpus directory '{}': {error}",
            custom_dir.display()
        )
    })?;
    let database = custom_dir.join(&file_name);

    let mut registry = read_registry(&app_data_dir)?;
    if registry.custom.iter().any(|entry| entry.id == id) && database.is_file() {
        return list_corpora(app)?
            .into_iter()
            .find(|summary| summary.id == id)
            .ok_or_else(|| "the existing reference library corpus is not registered".to_owned());
    }

    let work_dir = corpus_root(&app_data_dir).join("build-work").join(&id);
    let project_dir = work_dir.join("project");
    let signatures_dir = work_dir.join("signatures");
    if work_dir.exists() {
        fs::remove_dir_all(&work_dir)
            .map_err(|error| format!("failed to reset the BSim build workspace: {error}"))?;
    }
    fs::create_dir_all(&project_dir)
        .and_then(|_| fs::create_dir_all(&signatures_dir))
        .map_err(|error| format!("failed to prepare the BSim build workspace: {error}"))?;
    if database.exists() {
        fs::remove_file(&database).map_err(|error| {
            format!(
                "failed to replace the existing custom corpus '{}': {error}",
                database.display()
            )
        })?;
    }

    let bsim = installation.install_dir.join("support").join("bsim.bat");
    let analyze_headless = installation
        .install_dir
        .join("support")
        .join("analyzeHeadless.bat");
    let database_url = database_url(&database)?;
    let project_name = format!("reference_{stem}");

    let mut create = Command::new(&bsim);
    configure_java_environment(&mut create, &installation);
    let output = create
        .arg("createdatabase")
        .arg(&database_url)
        .arg("medium_64")
        .output()
        .map_err(|error| format!("failed to launch Ghidra BSim: {error}"))?;
    if !output.status.success() {
        return Err(command_error("Ghidra BSim database creation", &output));
    }

    let mut analyze = Command::new(&analyze_headless);
    configure_java_environment(&mut analyze, &installation);
    analyze.env("GHIDRA_HEADLESS_MAXMEM", "8G");
    let output = analyze
        .arg(&project_dir)
        .arg(&project_name)
        .arg("-import")
        .arg(&source)
        .output()
        .map_err(|error| format!("failed to launch Ghidra headless analysis: {error}"))?;
    if !output.status.success() {
        return Err(command_error("Ghidra reference library analysis", &output));
    }

    let project_url = format!(
        "ghidra:/{}/{}",
        project_dir.to_string_lossy().replace('\\', "/"),
        project_name
    );
    let mut generate = Command::new(&bsim);
    configure_java_environment(&mut generate, &installation);
    let output = generate
        .arg("generatesigs")
        .arg(project_url)
        .arg(&signatures_dir)
        .arg("--bsim")
        .arg(&database_url)
        .arg("--commit")
        .output()
        .map_err(|error| format!("failed to launch BSim signature generation: {error}"))?;
    if !output.status.success() {
        return Err(command_error("Ghidra BSim signature generation", &output));
    }

    validate_database_file(&database)?;
    let library_name = source
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(&stem)
        .to_owned();
    registry.custom.retain(|entry| entry.id != id);
    registry.custom.push(CustomCorpusEntry {
        id: id.clone(),
        name: format!("Bibliothèque : {library_name}"),
        file_name,
        enabled: true,
        libraries: vec![library_name],
    });
    write_registry(&app_data_dir, &registry)?;
    let _ = fs::remove_dir_all(&work_dir);

    list_corpora(app)?
        .into_iter()
        .find(|summary| summary.id == id)
        .ok_or_else(|| "the generated reference library corpus was not registered".to_owned())
}

pub fn set_corpus_enabled(app: &AppHandle, id: &str, enabled: bool) -> Result<(), String> {
    let app_data_dir = app_data_dir(app)?;
    let mut registry = read_registry(&app_data_dir)?;
    let entry = registry
        .custom
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or_else(|| "only a custom BSim corpus can be enabled or disabled".to_owned())?;
    entry.enabled = enabled;
    write_registry(&app_data_dir, &registry)
}

pub fn remove_custom_corpus(app: &AppHandle, id: &str) -> Result<(), String> {
    let app_data_dir = app_data_dir(app)?;
    let mut registry = read_registry(&app_data_dir)?;
    let index = registry
        .custom
        .iter()
        .position(|entry| entry.id == id)
        .ok_or_else(|| "only a registered custom BSim corpus can be removed".to_owned())?;
    let entry = registry.custom.remove(index);
    let target = custom_directory(&app_data_dir).join(entry.file_name);
    if target.exists() {
        let directory = fs::canonicalize(custom_directory(&app_data_dir)).map_err(|error| {
            format!("failed to resolve the managed custom corpus directory: {error}")
        })?;
        let canonical_target = fs::canonicalize(&target).map_err(|error| {
            format!(
                "failed to resolve custom BSim corpus '{}': {error}",
                target.display()
            )
        })?;
        if !canonical_target.starts_with(&directory) || canonical_target == directory {
            return Err(
                "refusing to remove a BSim corpus outside the managed corpus directory".to_owned(),
            );
        }
        fs::remove_file(&canonical_target).map_err(|error| {
            format!(
                "failed to remove custom BSim corpus '{}': {error}",
                canonical_target.display()
            )
        })?;
    }
    write_registry(&app_data_dir, &registry)
}

// Downloads the BSim seed corpus from a GitHub Release asset on first use,
// verifies it against the expected SHA-256, and caches it at `destination`
// so subsequent runs work fully offline. A cached copy that fails
// verification is treated as stale/corrupt and re-downloaded rather than
// trusted silently. Split from `ensure_corpus_downloaded` so the network/fs
// mechanics can be exercised directly in a test without needing a Tauri
// `AppHandle`.
fn download_and_cache(
    destination: &Path,
    release_asset_url: &str,
    expected_sha256: &str,
) -> Result<PathBuf, String> {
    if destination.is_file() {
        let existing = fs::read(destination).map_err(|error| {
            format!(
                "failed to read the cached BSim corpus '{}': {error}",
                destination.display()
            )
        })?;

        if verify_sha256(&existing, expected_sha256).is_ok() {
            return Ok(destination.to_path_buf());
        }
    }

    let parent = destination.parent().ok_or_else(|| {
        format!(
            "the BSim corpus cache path has no parent directory: {}",
            destination.display()
        )
    })?;

    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create the BSim corpus cache directory '{}': {error}",
            parent.display()
        )
    })?;

    let response = ureq::get(release_asset_url).call().map_err(|error| {
        format!("failed to download the BSim corpus from '{release_asset_url}': {error}")
    })?;

    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read the BSim corpus download body: {error}"))?;

    verify_sha256(&bytes, expected_sha256)?;

    let temp_path = parent.join(format!(".{CORPUS_FILE_NAME}.tmp"));

    fs::write(&temp_path, &bytes).map_err(|error| {
        format!(
            "failed to write the downloaded BSim corpus to '{}': {error}",
            temp_path.display()
        )
    })?;

    fs::rename(&temp_path, destination).map_err(|error| {
        format!(
            "failed to move the downloaded BSim corpus into place '{}': {error}",
            destination.display()
        )
    })?;

    Ok(destination.to_path_buf())
}

pub fn ensure_corpus_downloaded(
    app: &AppHandle,
    release_asset_url: &str,
    expected_sha256: &str,
) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("unable to resolve the application data directory: {error}"))?;

    download_and_cache(
        &cached_db_path(&app_data_dir),
        release_asset_url,
        expected_sha256,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_sha256_accepts_the_correct_hash() {
        let bytes = b"reverse assistant bsim corpus";
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let expected = hex_encode(&hasher.finalize());

        verify_sha256(bytes, &expected).expect("the matching hash should be accepted");
    }

    #[test]
    fn verify_sha256_is_case_insensitive() {
        let bytes = b"reverse assistant bsim corpus";
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let expected = hex_encode(&hasher.finalize()).to_uppercase();

        verify_sha256(bytes, &expected).expect("hash comparison should ignore case");
    }

    #[test]
    fn verify_sha256_rejects_a_mismatched_hash() {
        let error = verify_sha256(
            b"some bytes",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("a mismatched hash should be rejected");

        assert!(error.contains("SHA-256 mismatch"));
    }

    #[test]
    fn database_validation_accepts_a_non_empty_mv_db_file() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "reverse-assistant-bsim-validation-test-{unique_suffix}"
        ));
        let database = directory.join("personal-corpus.mv.db");

        fs::create_dir_all(&directory).expect("the test directory should be created");
        fs::write(&database, b"test database").expect("the test database should be written");

        validate_database_file(&database).expect("a non-empty .mv.db file should be accepted");

        fs::remove_dir_all(directory).expect("the test directory should be removed");
    }

    #[test]
    fn database_validation_rejects_an_empty_or_wrongly_named_file() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "reverse-assistant-bsim-validation-errors-{unique_suffix}"
        ));
        let empty_database = directory.join("empty.mv.db");
        let wrong_extension = directory.join("corpus.db");

        fs::create_dir_all(&directory).expect("the test directory should be created");
        fs::write(&empty_database, []).expect("the empty test file should be written");
        fs::write(&wrong_extension, b"test database")
            .expect("the wrongly named test file should be written");

        assert!(validate_database_file(&empty_database)
            .expect_err("an empty database should be rejected")
            .contains("empty"));
        assert!(validate_database_file(&wrong_extension)
            .expect_err("a database without the .mv.db suffix should be rejected")
            .contains(".mv.db"));

        fs::remove_dir_all(directory).expect("the test directory should be removed");
    }

    // Not run by default (needs network access) -- exercises the real
    // download+verify+cache mechanics end to end against a small, immutable
    // file (a tag-pinned GitHub raw URL), ahead of the real BSim corpus
    // release existing. Run manually with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn download_and_cache_downloads_verifies_and_caches_a_real_file() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock should be after the Unix epoch")
            .as_nanos();
        let cache_dir = std::env::temp_dir().join(format!(
            "reverse-assistant-bsim-corpus-download-test-{unique_suffix}"
        ));
        let destination = cache_dir.join("zlib-license-test.txt");
        let url = "https://raw.githubusercontent.com/madler/zlib/v1.3.2/LICENSE";
        let expected_sha256 = "e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2";

        let downloaded = download_and_cache(&destination, url, expected_sha256)
            .expect("the real download should succeed and verify");

        assert_eq!(downloaded, destination);
        assert!(destination.is_file());

        // Second call should hit the cache (already verified) without erroring.
        let cached = download_and_cache(&destination, url, expected_sha256)
            .expect("a cached, verified file should be reused without re-downloading");

        assert_eq!(cached, destination);

        fs::remove_dir_all(&cache_dir).expect("the isolated test directory should be removed");
    }

    #[test]
    fn cached_db_path_is_stable() {
        let path = cached_db_path(Path::new(
            "C:/Users/test-user/AppData/Roaming/reverse-assistant",
        ));

        assert_eq!(
            path,
            PathBuf::from("C:/Users/test-user/AppData/Roaming/reverse-assistant/bsim-corpus/reverse-assistant-seed.mv.db")
        );
    }

    #[test]
    fn database_url_removes_the_h2_file_suffix() {
        let url = database_url(Path::new(
            "C:/Reverse Assistant/bsim/reverse-assistant-seed.mv.db",
        ))
        .expect("a valid H2 database path should become a BSim URL");

        assert_eq!(
            url,
            "file:/C:/Reverse Assistant/bsim/reverse-assistant-seed"
        );
    }

    #[test]
    fn database_url_rejects_a_non_h2_path() {
        let error = database_url(Path::new("C:/corpus/database.sqlite"))
            .expect_err("a non-H2 path should be rejected");

        assert!(error.contains("must end with .mv.db"));
    }

    #[test]
    fn database_url_normalizes_a_windows_verbatim_path() {
        let url = database_url(Path::new(
            r"\\?\C:\Reverse Assistant\reverse-assistant-seed.mv.db",
        ))
        .expect("a canonical Windows path should become a regular file URL");

        assert_eq!(url, "file:/C:/Reverse Assistant/reverse-assistant-seed");
    }
}
