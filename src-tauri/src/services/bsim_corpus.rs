use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

const CORPUS_FILE_NAME: &str = "reverse-assistant-seed.mv.db";
const CORPUS_PATH_ENV: &str = "REVERSE_ASSISTANT_BSIM_CORPUS_PATH";

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
    let cached = cached_db_path(&app_data_dir);

    if cached.is_file() {
        return fs::canonicalize(&cached).map(Some).map_err(|error| {
            format!(
                "failed to resolve the cached BSim corpus '{}': {error}",
                cached.display()
            )
        });
    }

    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("bsim-corpus")
        .join("build")
        .join(CORPUS_FILE_NAME);

    if development.is_file() {
        return fs::canonicalize(&development).map(Some).map_err(|error| {
            format!(
                "failed to resolve the development BSim corpus '{}': {error}",
                development.display()
            )
        });
    }

    Ok(None)
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
