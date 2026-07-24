use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::path::BaseDirectory;
use tauri::{AppHandle, Emitter, Manager};
use zip::ZipArchive;

use crate::models::ghidra_installation::resolve_user_extensions_dir;
use crate::models::ghidra_installation::{derive_version_label, SUPPORTED_GHIDRA_VERSION_PREFIX};
use crate::services::{bsim_corpus, ghidra_installation};

const REQUIRED_JAVA_MAJOR: u32 = 21;
const GHIDRA_VERSION: &str = "12.1.2";
const GHIDRA_VERSION_LABEL: &str = "ghidra_12.1.2_PUBLIC";
const GHIDRA_ARCHIVE_NAME: &str = "ghidra_12.1.2_PUBLIC_20260605.zip";
const GHIDRA_DOWNLOAD_URL: &str = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip";
const GHIDRA_SHA256: &str = "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d";
const TEMURIN_DOWNLOAD_URL: &str =
    "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse";
const EXTENSION_RESOURCE: &str = "managed/ReverseAssistantExporter.zip";
const EXTENSION_SOURCE_RESOURCE: &str = "managed/extension-source";
const EXTENSION_SHA256: &str = "0d20b2808a4074bcd17e2913df6eda0b36450e505bf4e262110bfd2ec02833b5";
const BSIM_RESOURCE: &str = "managed/reverse-assistant-seed.mv.db";
const BSIM_SHA256: &str = "94daf5e4da0ddf30d766f0cd42d7da5c15b0a9dc94a606a9ea9dc70d70d0a7d6";

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupComponentState {
    Ready,
    Missing,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SetupComponent {
    pub id: &'static str,
    pub label: &'static str,
    pub state: SetupComponentState,
    pub version: Option<String>,
    pub path: Option<PathBuf>,
    pub detail: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SetupOverview {
    pub ready: bool,
    pub managed_install_available: bool,
    pub managed_root: PathBuf,
    pub components: Vec<SetupComponent>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SetupInstallItem {
    pub id: &'static str,
    pub label: &'static str,
    pub version: &'static str,
    pub source: &'static str,
    pub license: &'static str,
    pub license_url: &'static str,
    pub download_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SetupInstallPlan {
    pub destination: PathBuf,
    pub administrator_required: bool,
    pub items: Vec<SetupInstallItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SetupProgress {
    pub stage: &'static str,
    pub message: String,
    pub completed_percent: u8,
}

fn emit_progress(app: &AppHandle, stage: &'static str, message: impl Into<String>, percent: u8) {
    let _ = app.emit(
        "setup-progress",
        SetupProgress {
            stage,
            message: message.into(),
            completed_percent: percent,
        },
    );
}

pub fn managed_install_plan(app: &AppHandle) -> Result<SetupInstallPlan, String> {
    let overview = inspect_setup(app)?;
    let state = |id: &str| {
        overview
            .components
            .iter()
            .find(|component| component.id == id)
            .map(|component| component.state.clone())
            .unwrap_or(SetupComponentState::Missing)
    };

    Ok(SetupInstallPlan {
        destination: overview.managed_root,
        administrator_required: false,
        items: vec![
            SetupInstallItem {
                id: "java",
                label: "Eclipse Temurin JDK",
                version: "Latest security update for Java 21 LTS",
                source: "Eclipse Adoptium official API",
                license: "GPLv2 with Classpath Exception",
                license_url: "https://adoptium.net/about/",
                download_required: state("java") != SetupComponentState::Ready,
            },
            SetupInstallItem {
                id: "ghidra",
                label: "Ghidra",
                version: GHIDRA_VERSION,
                source: "NSA official GitHub release",
                license: "Apache License 2.0",
                license_url: "https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE",
                download_required: state("ghidra") != SetupComponentState::Ready,
            },
            SetupInstallItem {
                id: "extension",
                label: "Reverse Assistant extension",
                version: env!("CARGO_PKG_VERSION"),
                source: "Bundled with Reverse Assistant",
                license: "MIT",
                license_url: "https://opensource.org/license/mit",
                download_required: false,
            },
            SetupInstallItem {
                id: "bsim",
                label: "BSim seed corpus",
                version: "SQLite 3.53.3 + zlib 1.3.2",
                source: "Locally reproducible Reverse Assistant corpus",
                license: "Public Domain + zlib License",
                license_url: "https://www.zlib.net/zlib_license.html",
                download_required: false,
            },
        ],
    })
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| {
        format!(
            "failed to open '{}' for verification: {error}",
            path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read '{}': {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn verify_file(path: &Path, expected_sha256: &str) -> Result<(), String> {
    let actual = hash_file(path)?;
    if actual.eq_ignore_ascii_case(expected_sha256) {
        Ok(())
    } else {
        Err(format!(
            "SHA-256 mismatch for '{}': expected {expected_sha256}, got {actual}",
            path.display()
        ))
    }
}

fn download_to_file(
    app: &AppHandle,
    url: &str,
    destination: &Path,
    expected_sha256: Option<&str>,
    progress_start: u8,
    progress_end: u8,
) -> Result<(), String> {
    if destination.is_file()
        && expected_sha256
            .map(|expected| verify_file(destination, expected).is_ok())
            .unwrap_or(false)
    {
        return Ok(());
    }

    let parent = destination.parent().ok_or_else(|| {
        format!(
            "download destination has no parent: {}",
            destination.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create download directory '{}': {error}",
            parent.display()
        )
    })?;
    let temporary = destination.with_extension("zip.part");
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(|error| {
            format!(
                "failed to clear incomplete download '{}': {error}",
                temporary.display()
            )
        })?;
    }

    let response = ureq::get(url)
        .set("User-Agent", "Reverse-Assistant-Setup")
        .call()
        .map_err(|error| format!("failed to download '{url}': {error}"))?;
    let final_url = response.get_url().to_owned();
    let total = response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok());
    let mut reader = response.into_reader();
    let mut output = File::create(&temporary).map_err(|error| {
        format!(
            "failed to create download '{}': {error}",
            temporary.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut downloaded = 0_u64;
    let mut last_percent = progress_start;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed while downloading '{url}': {error}"))?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|error| format!("failed to write '{}': {error}", temporary.display()))?;
        hasher.update(&buffer[..count]);
        downloaded += count as u64;
        if let Some(total) = total.filter(|value| *value > 0) {
            let span = u64::from(progress_end.saturating_sub(progress_start));
            let percent = progress_start + ((downloaded.saturating_mul(span) / total) as u8);
            if percent > last_percent {
                last_percent = percent;
                emit_progress(
                    app,
                    "download",
                    "Downloading required components...",
                    percent,
                );
            }
        }
    }
    output
        .flush()
        .map_err(|error| format!("failed to finish '{}': {error}", temporary.display()))?;

    let actual: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let expected = if let Some(expected) = expected_sha256 {
        expected.to_owned()
    } else {
        let checksum_url = format!("{final_url}.sha256.txt");
        ureq::get(&checksum_url)
            .set("User-Agent", "Reverse-Assistant-Setup")
            .call()
            .map_err(|error| format!("failed to download checksum '{checksum_url}': {error}"))?
            .into_string()
            .map_err(|error| format!("failed to read checksum '{checksum_url}': {error}"))?
            .split_whitespace()
            .next()
            .ok_or_else(|| format!("checksum response was empty: {checksum_url}"))?
            .to_owned()
    };
    if !actual.eq_ignore_ascii_case(&expected) {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "downloaded file failed SHA-256 verification: expected {expected}, got {actual}"
        ));
    }

    if destination.exists() {
        fs::remove_file(destination).map_err(|error| {
            format!(
                "failed to replace cached download '{}': {error}",
                destination.display()
            )
        })?;
    }
    fs::rename(&temporary, destination).map_err(|error| {
        format!(
            "failed to finalize download '{}': {error}",
            destination.display()
        )
    })
}

fn extract_zip(archive_path: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "failed to create extraction directory '{}': {error}",
            destination.display()
        )
    })?;
    let file = File::open(archive_path).map_err(|error| {
        format!(
            "failed to open archive '{}': {error}",
            archive_path.display()
        )
    })?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| format!("invalid ZIP archive '{}': {error}", archive_path.display()))?;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to read ZIP entry {index}: {error}"))?;
        let relative = entry
            .enclosed_name()
            .ok_or_else(|| format!("unsafe path in ZIP archive: {}", entry.name()))?;
        let output_path = destination.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(&output_path).map_err(|error| {
                format!("failed to create '{}': {error}", output_path.display())
            })?;
            continue;
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create '{}': {error}", parent.display()))?;
        }
        let mut output = File::create(&output_path)
            .map_err(|error| format!("failed to create '{}': {error}", output_path.display()))?;
        std::io::copy(&mut entry, &mut output)
            .map_err(|error| format!("failed to extract '{}': {error}", output_path.display()))?;
    }
    Ok(())
}

fn copy_directory(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|error| format!("failed to create '{}': {error}", destination.display()))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("failed to read '{}': {error}", source.display()))?
    {
        let entry = entry.map_err(|error| format!("failed to read directory entry: {error}"))?;
        let target = destination.join(entry.file_name());
        if entry
            .file_type()
            .map_err(|error| format!("failed to inspect '{}': {error}", entry.path().display()))?
            .is_dir()
        {
            copy_directory(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)
                .map_err(|error| format!("failed to copy to '{}': {error}", target.display()))?;
        }
    }
    Ok(())
}

fn extension_archive(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(resource) = app
        .path()
        .resolve(EXTENSION_RESOURCE, BaseDirectory::Resource)
    {
        if resource.is_file() {
            verify_file(&resource, EXTENSION_SHA256)?;
            return Ok(resource);
        }
    }
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("ghidra-extension")
        .join("ReverseAssistantExporter")
        .join("dist")
        .join("ghidra_12.1.2_PUBLIC_20260723_ReverseAssistantExporter.zip");
    if development.is_file() {
        verify_file(&development, EXTENSION_SHA256)?;
        Ok(development)
    } else {
        Err("the bundled Reverse Assistant Ghidra extension is missing".to_owned())
    }
}

fn extension_source(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(resource) = app
        .path()
        .resolve(EXTENSION_SOURCE_RESOURCE, BaseDirectory::Resource)
    {
        if resource.join("build.gradle").is_file() {
            return Ok(resource);
        }
    }
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("ghidra-extension")
        .join("ReverseAssistantExporter");
    if development.join("build.gradle").is_file() {
        Ok(development)
    } else {
        Err("the Reverse Assistant extension sources are missing".to_owned())
    }
}

fn copy_extension_sources(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "failed to create extension build directory '{}': {error}",
            destination.display()
        )
    })?;
    for file_name in ["build.gradle", "extension.properties", "Module.manifest"] {
        fs::copy(source.join(file_name), destination.join(file_name))
            .map_err(|error| format!("failed to stage extension file '{file_name}': {error}"))?;
    }
    for directory in ["src", "ghidra_scripts"] {
        copy_directory(&source.join(directory), &destination.join(directory))?;
    }
    Ok(())
}

fn build_extension_archive(
    app: &AppHandle,
    install_dir: &Path,
    java_home: Option<&Path>,
) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("unable to resolve application data directory: {error}"))?;
    let build_source = app_data_dir
        .join("managed-tools")
        .join("extension-build-source");
    if build_source.exists() {
        fs::remove_dir_all(&build_source).map_err(|error| {
            format!(
                "failed to clear extension build directory '{}': {error}",
                build_source.display()
            )
        })?;
    }
    copy_extension_sources(&extension_source(app)?, &build_source)?;

    let gradle = install_dir
        .join("support")
        .join("gradle")
        .join(if cfg!(windows) {
            "gradlew.bat"
        } else {
            "gradlew"
        });
    if !gradle.is_file() {
        return Err(format!(
            "the Ghidra Gradle wrapper is missing: {}",
            gradle.display()
        ));
    }
    let mut command = Command::new(&gradle);
    command
        .arg("-p")
        .arg(&build_source)
        .arg(format!("-PGHIDRA_INSTALL_DIR={}", install_dir.display()))
        .arg("buildExtension");
    if let Some(java_home) = java_home {
        command.env("JAVA_HOME", java_home);
        let mut paths = vec![java_home.join("bin")];
        if let Some(existing) = env::var_os("PATH") {
            paths.extend(env::split_paths(&existing));
        }
        if let Ok(joined) = env::join_paths(paths) {
            command.env("PATH", joined);
        }
    }
    let output = command.output().map_err(|error| {
        format!(
            "failed to start the Ghidra extension build '{}': {error}",
            gradle.display()
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "the Ghidra extension build failed: {} {}",
            stdout.trim(),
            stderr.trim()
        ));
    }
    fs::read_dir(build_source.join("dist"))
        .map_err(|error| format!("the extension build produced no dist directory: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "zip"))
        .max_by_key(|path| {
            fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .ok()
        })
        .ok_or_else(|| "the extension build produced no ZIP archive".to_owned())
}

fn install_bsim_corpus(app: &AppHandle) -> Result<Option<PathBuf>, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("unable to resolve application data directory: {error}"))?;
    let destination = bsim_corpus::cached_db_path(&app_data_dir);
    if destination.is_file() && verify_file(&destination, BSIM_SHA256).is_ok() {
        return Ok(Some(destination));
    }

    let bundled = app
        .path()
        .resolve(BSIM_RESOURCE, BaseDirectory::Resource)
        .ok()
        .filter(|path| path.is_file())
        .or_else(|| {
            let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("bsim-corpus")
                .join("build")
                .join("reverse-assistant-seed.mv.db");
            development.is_file().then_some(development)
        });
    let Some(bundled) = bundled else {
        return Ok(None);
    };
    verify_file(&bundled, BSIM_SHA256)?;
    let parent = destination
        .parent()
        .ok_or_else(|| "the BSim destination has no parent directory".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create BSim directory '{}': {error}",
            parent.display()
        )
    })?;
    let temporary = parent.join(".reverse-assistant-seed.mv.db.tmp");
    fs::copy(&bundled, &temporary)
        .map_err(|error| format!("failed to copy bundled BSim corpus: {error}"))?;
    verify_file(&temporary, BSIM_SHA256)?;
    if destination.exists() {
        fs::remove_file(&destination).map_err(|error| {
            format!(
                "failed to replace BSim corpus '{}': {error}",
                destination.display()
            )
        })?;
    }
    fs::rename(&temporary, &destination).map_err(|error| {
        format!(
            "failed to install BSim corpus '{}': {error}",
            destination.display()
        )
    })?;
    Ok(Some(destination))
}

fn install_extension(
    app: &AppHandle,
    install_dir: &Path,
    version_label: &str,
    java_home: Option<&Path>,
) -> Result<PathBuf, String> {
    let archive =
        extension_archive(app).or_else(|_| build_extension_archive(app, install_dir, java_home))?;
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("unable to resolve application data directory: {error}"))?;
    let staging = app_data_dir.join("managed-tools").join("extension-staging");
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|error| {
            format!(
                "failed to clear extension staging directory '{}': {error}",
                staging.display()
            )
        })?;
    }
    extract_zip(&archive, &staging)?;
    let extracted = staging.join("ReverseAssistantExporter");
    if !extracted.is_dir() {
        return Err("the bundled extension archive has an unexpected layout".to_owned());
    }
    let destination = resolve_user_extensions_dir(
        &ghidra_installation::ghidra_config_root(app)?,
        version_label,
    );
    if destination.exists() {
        fs::remove_dir_all(&destination).map_err(|error| {
            format!(
                "failed to replace extension '{}': {error}",
                destination.display()
            )
        })?;
    }
    copy_directory(&extracted, &destination)?;
    let _ = fs::remove_dir_all(&staging);
    Ok(destination)
}

fn install_java(app: &AppHandle, managed_root: &Path) -> Result<PathBuf, String> {
    let archive = managed_root.join("downloads").join("temurin-jdk-21.zip");
    download_to_file(app, TEMURIN_DOWNLOAD_URL, &archive, None, 5, 25)?;
    let staging = managed_root.join("jdk-staging");
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|error| {
            format!(
                "failed to clear Java staging directory '{}': {error}",
                staging.display()
            )
        })?;
    }
    emit_progress(app, "extract", "Installing Java...", 28);
    extract_zip(&archive, &staging)?;
    let java_home = fs::read_dir(&staging)
        .map_err(|error| format!("failed to inspect Java archive: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| java_executable(path).is_file())
        .ok_or_else(|| "the Java archive has an unexpected layout".to_owned())?;
    let destination = managed_root.join("jdk-21");
    if destination.exists() {
        fs::remove_dir_all(&destination).map_err(|error| {
            format!(
                "failed to replace managed Java '{}': {error}",
                destination.display()
            )
        })?;
    }
    fs::rename(&java_home, &destination).map_err(|error| {
        format!(
            "failed to install Java to '{}': {error}",
            destination.display()
        )
    })?;
    let _ = fs::remove_dir_all(&staging);
    Ok(destination)
}

fn install_ghidra(app: &AppHandle, managed_root: &Path) -> Result<PathBuf, String> {
    let archive = managed_root.join("downloads").join(GHIDRA_ARCHIVE_NAME);
    download_to_file(
        app,
        GHIDRA_DOWNLOAD_URL,
        &archive,
        Some(GHIDRA_SHA256),
        30,
        72,
    )?;
    let staging = managed_root.join("ghidra-staging");
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|error| {
            format!(
                "failed to clear Ghidra staging directory '{}': {error}",
                staging.display()
            )
        })?;
    }
    emit_progress(app, "extract", "Installing Ghidra...", 75);
    extract_zip(&archive, &staging)?;
    let extracted = staging.join(GHIDRA_VERSION_LABEL);
    if !extracted
        .join("support")
        .join("analyzeHeadless.bat")
        .is_file()
    {
        return Err("the Ghidra archive has an unexpected layout".to_owned());
    }
    let destination = managed_root.join(GHIDRA_VERSION_LABEL);
    if destination.exists() {
        fs::remove_dir_all(&destination).map_err(|error| {
            format!(
                "failed to replace managed Ghidra '{}': {error}",
                destination.display()
            )
        })?;
    }
    fs::rename(&extracted, &destination).map_err(|error| {
        format!(
            "failed to install Ghidra to '{}': {error}",
            destination.display()
        )
    })?;
    let _ = fs::remove_dir_all(&staging);
    Ok(destination)
}

pub fn install_managed_setup(
    app: &AppHandle,
    licenses_accepted: bool,
) -> Result<SetupOverview, String> {
    if !licenses_accepted {
        return Err(
            "installation requires explicit acceptance of the displayed licenses".to_owned(),
        );
    }
    if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        return Err("automatic setup is currently available only on 64-bit Windows".to_owned());
    }

    let before = inspect_setup(app)?;
    fs::create_dir_all(&before.managed_root).map_err(|error| {
        format!(
            "failed to create managed tools directory '{}': {error}",
            before.managed_root.display()
        )
    })?;
    emit_progress(app, "prepare", "Preparing local installation...", 2);

    let java_ready = before
        .components
        .iter()
        .any(|component| component.id == "java" && component.state == SetupComponentState::Ready);
    let managed_java = if java_ready {
        None
    } else {
        Some(install_java(app, &before.managed_root)?)
    };

    let configured_dir = ghidra_installation::load_persisted_install_dir(app)?;
    let base_is_usable = configured_dir.as_ref().is_some_and(|path| {
        path.join("support").join("analyzeHeadless.bat").is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("ghidra_12."))
    });
    let install_dir = if base_is_usable {
        configured_dir.expect("checked as present")
    } else {
        install_ghidra(app, &before.managed_root)?
    };

    let version_label = install_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "unable to determine installed Ghidra version".to_owned())?;
    emit_progress(
        app,
        "extension",
        "Installing Reverse Assistant integration...",
        88,
    );
    install_extension(app, &install_dir, version_label, managed_java.as_deref())?;
    emit_progress(app, "corpus", "Installing the BSim seed corpus...", 92);
    let _ = install_bsim_corpus(app)?;
    ghidra_installation::persist_installation(app, &install_dir, managed_java.as_deref())?;
    emit_progress(app, "verify", "Verifying the complete toolchain...", 96);
    ghidra_installation::validate_installation(app, &install_dir)?;
    let result = inspect_setup(app)?;
    if !result.ready {
        return Err(
            "setup completed, but one or more required components failed validation".to_owned(),
        );
    }
    emit_progress(
        app,
        "complete",
        "Reverse Assistant is ready to analyze binaries.",
        100,
    );
    Ok(result)
}

pub fn adopt_existing_ghidra(app: &AppHandle, install_dir: &Path) -> Result<SetupOverview, String> {
    if !install_dir.is_dir()
        || !install_dir
            .join("support")
            .join(if cfg!(windows) {
                "analyzeHeadless.bat"
            } else {
                "analyzeHeadless"
            })
            .is_file()
    {
        return Err(format!(
            "the selected folder is not a Ghidra installation root: {}",
            install_dir.display()
        ));
    }
    let version_label = derive_version_label(install_dir)?;
    if !version_label.starts_with(SUPPORTED_GHIDRA_VERSION_PREFIX) {
        return Err(format!(
            "unsupported Ghidra version '{version_label}'; a Ghidra 12.x installation is required"
        ));
    }

    emit_progress(
        app,
        "extension",
        "Installing Reverse Assistant integration...",
        70,
    );
    install_extension(app, install_dir, &version_label, None)?;
    let _ = install_bsim_corpus(app)?;
    ghidra_installation::persist_installation(app, install_dir, None)?;
    ghidra_installation::validate_installation(app, install_dir)?;
    emit_progress(
        app,
        "complete",
        "Existing Ghidra installation is ready.",
        100,
    );
    inspect_setup(app)
}

fn parse_java_major(version_output: &str) -> Option<u32> {
    let marker = "version \"";
    let start = version_output.find(marker)? + marker.len();
    let version = version_output.get(start..)?.split('"').next()?;
    let first = version.split('.').next()?;
    let major = if first == "1" {
        version.split('.').nth(1)?
    } else {
        first
    };

    major.parse().ok()
}

fn java_version_label(version_output: &str) -> Option<String> {
    let marker = "version \"";
    let start = version_output.find(marker)? + marker.len();
    version_output
        .get(start..)?
        .split('"')
        .next()
        .map(str::to_owned)
}

fn java_executable(java_home: &Path) -> PathBuf {
    if cfg!(windows) {
        java_home.join("bin").join("java.exe")
    } else {
        java_home.join("bin").join("java")
    }
}

fn inspect_java_command(program: &Path, java_home: Option<&Path>) -> SetupComponent {
    let mut command = Command::new(program);
    command.arg("-version");
    if let Some(home) = java_home {
        command.env("JAVA_HOME", home);
    }

    match command.output() {
        Ok(output) => {
            let mut combined = String::from_utf8_lossy(&output.stderr).into_owned();
            combined.push_str(&String::from_utf8_lossy(&output.stdout));
            let version = java_version_label(&combined);
            let major = parse_java_major(&combined);

            if output.status.success() && major.is_some_and(|value| value >= REQUIRED_JAVA_MAJOR) {
                SetupComponent {
                    id: "java",
                    label: "Java 21 (JDK)",
                    state: SetupComponentState::Ready,
                    version,
                    path: java_home.map(Path::to_path_buf),
                    detail: "Un environnement Java 64 bits compatible est disponible pour Ghidra."
                        .to_owned(),
                    required: true,
                }
            } else {
                SetupComponent {
                    id: "java",
                    label: "Java 21 (JDK)",
                    state: SetupComponentState::Invalid,
                    version,
                    path: java_home.map(Path::to_path_buf),
                    detail: format!("Ghidra requires a 64-bit JDK {REQUIRED_JAVA_MAJOR} or newer."),
                    required: true,
                }
            }
        }
        Err(error) => SetupComponent {
            id: "java",
            label: "Java 21 (JDK)",
            state: SetupComponentState::Missing,
            version: None,
            path: java_home.map(Path::to_path_buf),
            detail: format!("No compatible Java runtime was found: {error}"),
            required: true,
        },
    }
}

fn inspect_java(managed_root: &Path) -> SetupComponent {
    let managed_home = managed_root.join("jdk-21");
    let managed_java = java_executable(&managed_home);
    if managed_java.is_file() {
        return inspect_java_command(&managed_java, Some(&managed_home));
    }

    if let Some(java_home) = env::var_os("JAVA_HOME").map(PathBuf::from) {
        let executable = java_executable(&java_home);
        if executable.is_file() {
            return inspect_java_command(&executable, Some(&java_home));
        }
    }

    inspect_java_command(
        Path::new(if cfg!(windows) { "java.exe" } else { "java" }),
        None,
    )
}

pub fn inspect_setup(app: &AppHandle) -> Result<SetupOverview, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("unable to resolve the application data directory: {error}"))?;
    let managed_root = app_data_dir.join("managed-tools");
    let java = inspect_java(&managed_root);

    let ghidra_status = ghidra_installation::current_installation_status(app)?;
    let (ghidra, extension) = match ghidra_status {
        ghidra_installation::GhidraInstallationStatus::Valid { installation } => (
            SetupComponent {
                id: "ghidra",
                label: "Ghidra",
                state: SetupComponentState::Ready,
                version: Some(installation.version_label.clone()),
                path: Some(installation.install_dir),
                detail: "Le mode headless de Ghidra est configuré et prêt.".to_owned(),
                required: true,
            },
            SetupComponent {
                id: "extension",
                label: "Extension Reverse Assistant",
                state: SetupComponentState::Ready,
                version: None,
                path: Some(installation.extensions_dir),
                detail: "Les scripts d’export, de décompilation, FunctionID et de renommage sont installés."
                    .to_owned(),
                required: true,
            },
        ),
        ghidra_installation::GhidraInstallationStatus::NotConfigured => (
            SetupComponent {
                id: "ghidra",
                label: "Ghidra",
                state: SetupComponentState::Missing,
                version: None,
                path: None,
                detail: "Aucune installation Ghidra n’est configurée.".to_owned(),
                required: true,
            },
            SetupComponent {
                id: "extension",
                label: "Extension Reverse Assistant",
                state: SetupComponentState::Missing,
                version: None,
                path: None,
                detail: "L’extension sera installée après Ghidra.".to_owned(),
                required: true,
            },
        ),
        ghidra_installation::GhidraInstallationStatus::Invalid {
            install_dir,
            reason,
        } => {
            let extension_problem = reason.contains("extension") || reason.contains("script");
            (
                SetupComponent {
                    id: "ghidra",
                    label: "Ghidra",
                    state: if extension_problem {
                        SetupComponentState::Ready
                    } else {
                        SetupComponentState::Invalid
                    },
                    version: install_dir
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(str::to_owned),
                    path: Some(install_dir),
                    detail: if extension_problem {
                        "The Ghidra installation was found, but its integration needs repair."
                            .to_owned()
                    } else {
                        reason.clone()
                    },
                    required: true,
                },
                SetupComponent {
                    id: "extension",
                    label: "Extension Reverse Assistant",
                    state: if extension_problem {
                        SetupComponentState::Invalid
                    } else {
                        SetupComponentState::Missing
                    },
                    version: None,
                    path: None,
                    detail: reason,
                    required: true,
                },
            )
        }
    };

    let corpus = match bsim_corpus::locate_available_corpus(app) {
        Ok(Some(path)) => SetupComponent {
            id: "bsim",
            label: "Corpus de référence BSim",
            state: SetupComponentState::Ready,
            version: None,
            path: Some(path),
            detail: "Le corpus local de similarité est disponible.".to_owned(),
            required: false,
        },
        Ok(None) => SetupComponent {
            id: "bsim",
            label: "Corpus de référence BSim",
            state: SetupComponentState::Missing,
            version: None,
            path: None,
            detail: "La recherche de fonctions similaires restera indisponible tant que le corpus ne sera pas installé."
                .to_owned(),
            required: false,
        },
        Err(error) => SetupComponent {
            id: "bsim",
            label: "Corpus de référence BSim",
            state: SetupComponentState::Invalid,
            version: None,
            path: None,
            detail: error,
            required: false,
        },
    };

    let components = vec![java, ghidra, extension, corpus];
    let ready = components
        .iter()
        .filter(|component| component.required)
        .all(|component| component.state == SetupComponentState::Ready);

    Ok(SetupOverview {
        ready,
        managed_install_available: cfg!(all(target_os = "windows", target_arch = "x86_64")),
        managed_root,
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;

    #[test]
    fn parses_modern_java_versions() {
        assert_eq!(
            parse_java_major("openjdk version \"21.0.11\" 2026-04-21"),
            Some(21)
        );
        assert_eq!(
            java_version_label("openjdk version \"21.0.11\" 2026-04-21"),
            Some("21.0.11".to_owned())
        );
    }

    #[test]
    fn parses_legacy_java_version_format() {
        assert_eq!(parse_java_major("java version \"1.8.0_451\""), Some(8));
    }

    #[test]
    fn rejects_unrelated_output() {
        assert_eq!(parse_java_major("not a Java version"), None);
        assert_eq!(java_version_label("not a Java version"), None);
    }

    fn isolated_directory(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("reverse-assistant-setup-{name}-{unique}"))
    }

    #[test]
    fn extracts_a_regular_zip_archive() {
        let root = isolated_directory("extract-safe");
        fs::create_dir_all(&root).expect("test root should be created");
        let archive_path = root.join("safe.zip");
        let file = File::create(&archive_path).expect("archive should be created");
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("tool/bin/example.txt", SimpleFileOptions::default())
            .expect("entry should start");
        archive
            .write_all(b"verified")
            .expect("entry should be written");
        archive.finish().expect("archive should finish");

        let destination = root.join("out");
        extract_zip(&archive_path, &destination).expect("safe archive should extract");
        assert_eq!(
            fs::read(destination.join("tool/bin/example.txt")).expect("file should exist"),
            b"verified"
        );
        fs::remove_dir_all(root).expect("test root should be removed");
    }

    #[test]
    fn rejects_zip_entries_that_escape_the_destination() {
        let root = isolated_directory("extract-traversal");
        fs::create_dir_all(&root).expect("test root should be created");
        let archive_path = root.join("unsafe.zip");
        let file = File::create(&archive_path).expect("archive should be created");
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("../escape.txt", SimpleFileOptions::default())
            .expect("entry should start");
        archive
            .write_all(b"unsafe")
            .expect("entry should be written");
        archive.finish().expect("archive should finish");

        let destination = root.join("out");
        let error = extract_zip(&archive_path, &destination)
            .expect_err("parent traversal must be rejected");
        assert!(error.contains("unsafe path"));
        assert!(!root.join("escape.txt").exists());
        fs::remove_dir_all(root).expect("test root should be removed");
    }
}
