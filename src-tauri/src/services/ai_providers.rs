// Local, persisted settings for the AI naming agents' provider(s). Mirrors
// the BSim corpus registry pattern already used in this project
// (services/bsim_corpus.rs): a small JSON file under the app data
// directory, one or several entries that can each be enabled/disabled
// independently, add/remove commands rather than in-place editing.
//
// Every configured provider speaks the same OpenAI-compatible chat
// completions shape (see services/ai_provider.rs) -- only `base_url`,
// `api_key`, and `model` differ between a local Ollama server, OpenAI, or
// any other compatible backend, which is what keeps this genuinely
// provider-agnostic rather than hardcoding one vendor's concepts.
//
// The API key is a local secret: it is written to disk (same trust
// boundary as every other local setting in this app, e.g. the Ghidra
// installation path) but is never echoed back to the frontend in
// `list_providers` -- callers only ever learn whether a key is set
// (`has_api_key`), never its value, once it has been saved.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

const REGISTRY_FILE_NAME: &str = "ai_providers.json";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AiProviderSummary {
    pub id: String,
    pub label: String,
    pub base_url: String,
    pub model: String,
    pub has_api_key: bool,
    pub enabled: bool,
}

/// Everything actually needed to make a real call, including the secret.
/// Only ever used internally (never returned by a Tauri command as-is).
#[derive(Debug, Clone, PartialEq)]
pub struct AiProviderSecrets {
    pub id: String,
    pub label: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
struct ProviderRegistry {
    #[serde(default)]
    providers: Vec<ProviderEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ProviderEntry {
    id: String,
    label: String,
    base_url: String,
    #[serde(default)]
    api_key: Option<String>,
    model: String,
    enabled: bool,
}

fn summarize(entry: &ProviderEntry) -> AiProviderSummary {
    AiProviderSummary {
        id: entry.id.clone(),
        label: entry.label.clone(),
        base_url: entry.base_url.clone(),
        model: entry.model.clone(),
        has_api_key: entry.api_key.is_some(),
        enabled: entry.enabled,
    }
}

fn registry_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(REGISTRY_FILE_NAME)
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|error| format!("unable to resolve the application data directory: {error}"))
}

fn read_registry(app_data_dir: &Path) -> Result<ProviderRegistry, String> {
    let path = registry_path(app_data_dir);
    if !path.is_file() {
        return Ok(ProviderRegistry::default());
    }

    let json = fs::read_to_string(&path).map_err(|error| {
        format!(
            "failed to read the AI provider registry '{}': {error}",
            path.display()
        )
    })?;
    serde_json::from_str(&json).map_err(|error| {
        format!(
            "invalid AI provider registry '{}': {error}",
            path.display()
        )
    })
}

fn write_registry(app_data_dir: &Path, registry: &ProviderRegistry) -> Result<(), String> {
    fs::create_dir_all(app_data_dir).map_err(|error| {
        format!(
            "failed to create the application data directory '{}': {error}",
            app_data_dir.display()
        )
    })?;
    let path = registry_path(app_data_dir);
    let json = serde_json::to_string_pretty(registry)
        .map_err(|error| format!("failed to serialize the AI provider registry: {error}"))?;
    let temporary = app_data_dir.join(".ai_providers.json.tmp");
    fs::write(&temporary, format!("{json}\n")).map_err(|error| {
        format!(
            "failed to write the AI provider registry '{}': {error}",
            temporary.display()
        )
    })?;
    if path.exists() {
        fs::remove_file(&path).map_err(|error| {
            format!(
                "failed to replace the AI provider registry '{}': {error}",
                path.display()
            )
        })?;
    }
    fs::rename(&temporary, &path).map_err(|error| {
        format!(
            "failed to install the AI provider registry '{}': {error}",
            path.display()
        )
    })
}

fn generate_provider_id() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock error while configuring an AI provider: {error}"))?
        .as_nanos();
    Ok(format!("provider-{nanos}"))
}

pub fn list_providers(app_data_dir: &Path) -> Result<Vec<AiProviderSummary>, String> {
    let registry = read_registry(app_data_dir)?;
    Ok(registry.providers.iter().map(summarize).collect())
}

pub fn add_provider(
    app_data_dir: &Path,
    label: &str,
    base_url: &str,
    api_key: Option<String>,
    model: &str,
) -> Result<AiProviderSummary, String> {
    let label = label.trim();
    if label.is_empty() {
        return Err("le nom du fournisseur ne peut pas être vide".to_owned());
    }
    let base_url = base_url.trim();
    if base_url.is_empty() {
        return Err("l'adresse du fournisseur ne peut pas être vide".to_owned());
    }
    let model = model.trim();
    if model.is_empty() {
        return Err("le nom du modèle ne peut pas être vide".to_owned());
    }

    let mut registry = read_registry(app_data_dir)?;
    let entry = ProviderEntry {
        id: generate_provider_id()?,
        label: label.to_owned(),
        base_url: base_url.trim_end_matches('/').to_owned(),
        api_key: api_key.filter(|key| !key.trim().is_empty()),
        model: model.to_owned(),
        enabled: true,
    };
    let summary = summarize(&entry);
    registry.providers.push(entry);
    write_registry(app_data_dir, &registry)?;

    Ok(summary)
}

pub fn set_provider_enabled(app_data_dir: &Path, id: &str, enabled: bool) -> Result<(), String> {
    let mut registry = read_registry(app_data_dir)?;
    let entry = registry
        .providers
        .iter_mut()
        .find(|provider| provider.id == id)
        .ok_or_else(|| format!("no AI provider is configured with id '{id}'"))?;
    entry.enabled = enabled;
    write_registry(app_data_dir, &registry)
}

pub fn remove_provider(app_data_dir: &Path, id: &str) -> Result<(), String> {
    let mut registry = read_registry(app_data_dir)?;
    let before = registry.providers.len();
    registry.providers.retain(|provider| provider.id != id);
    if registry.providers.len() == before {
        return Err(format!("no AI provider is configured with id '{id}'"));
    }
    write_registry(app_data_dir, &registry)
}

/// The enabled providers, with their real secrets -- for internal use by
/// the agents themselves, never exposed to the frontend as a whole.
pub fn enabled_providers_with_secrets(
    app_data_dir: &Path,
) -> Result<Vec<AiProviderSecrets>, String> {
    let registry = read_registry(app_data_dir)?;
    Ok(registry
        .providers
        .iter()
        .filter(|provider| provider.enabled)
        .map(|provider| AiProviderSecrets {
            id: provider.id.clone(),
            label: provider.label.clone(),
            base_url: provider.base_url.clone(),
            api_key: provider.api_key.clone(),
            model: provider.model.clone(),
        })
        .collect())
}

pub fn list_providers_for_app(app: &AppHandle) -> Result<Vec<AiProviderSummary>, String> {
    list_providers(&app_data_dir(app)?)
}

pub fn add_provider_for_app(
    app: &AppHandle,
    label: &str,
    base_url: &str,
    api_key: Option<String>,
    model: &str,
) -> Result<AiProviderSummary, String> {
    add_provider(&app_data_dir(app)?, label, base_url, api_key, model)
}

pub fn set_provider_enabled_for_app(
    app: &AppHandle,
    id: &str,
    enabled: bool,
) -> Result<(), String> {
    set_provider_enabled(&app_data_dir(app)?, id, enabled)
}

pub fn remove_provider_for_app(app: &AppHandle, id: &str) -> Result<(), String> {
    remove_provider(&app_data_dir(app)?, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_app_data_dir(test_name: &str) -> PathBuf {
        let unique_suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "reverse-assistant-ai-providers-test-{test_name}-{unique_suffix}"
        ))
    }

    #[test]
    fn listing_with_no_registry_file_yet_is_an_empty_list() {
        let dir = temp_app_data_dir("empty");

        let providers = list_providers(&dir).expect("a missing registry should default to empty");

        assert!(providers.is_empty());
    }

    #[test]
    fn a_newly_added_provider_is_enabled_by_default_and_never_echoes_its_key() {
        let dir = temp_app_data_dir("add");

        let summary = add_provider(
            &dir,
            "OpenAI",
            "https://api.openai.com/v1",
            Some("sk-real-secret-value".to_owned()),
            "gpt-4o-mini",
        )
        .expect("a well-formed provider should be accepted");

        assert!(summary.enabled);
        assert!(summary.has_api_key);
        assert_eq!(summary.base_url, "https://api.openai.com/v1");

        let providers = list_providers(&dir).expect("listing should succeed");
        assert_eq!(providers.len(), 1);
        assert!(providers[0].has_api_key);

        let raw_file = fs::read_to_string(registry_path(&dir)).expect("registry file should exist");
        assert!(
            raw_file.contains("sk-real-secret-value"),
            "the registry file itself legitimately stores the real key on disk"
        );
    }

    #[test]
    fn a_local_provider_without_an_api_key_is_valid() {
        let dir = temp_app_data_dir("local");

        let summary = add_provider(
            &dir,
            "Ollama local",
            "http://localhost:11434/v1",
            None,
            "llama3.1",
        )
        .expect("a provider without an api key should be accepted");

        assert!(!summary.has_api_key);
    }

    #[test]
    fn an_empty_api_key_is_treated_as_no_key() {
        let dir = temp_app_data_dir("blank-key");

        let summary = add_provider(&dir, "Local", "http://localhost:1234/v1", Some("   ".to_owned()), "model")
            .expect("a blank api key should be accepted as absent");

        assert!(!summary.has_api_key);
    }

    #[test]
    fn a_blank_label_is_rejected() {
        let dir = temp_app_data_dir("blank-label");

        let error = add_provider(&dir, "   ", "http://localhost:1234/v1", None, "model")
            .expect_err("a blank label should be rejected");

        assert!(error.contains("nom du fournisseur"));
    }

    #[test]
    fn disabling_a_provider_removes_it_from_the_enabled_secrets_list() {
        let dir = temp_app_data_dir("disable");
        let summary = add_provider(&dir, "OpenAI", "https://api.openai.com/v1", Some("key".to_owned()), "gpt-4o-mini")
            .expect("adding should succeed");

        let enabled_before = enabled_providers_with_secrets(&dir).expect("listing enabled providers should succeed");
        assert_eq!(enabled_before.len(), 1);

        set_provider_enabled(&dir, &summary.id, false).expect("disabling should succeed");

        let enabled_after = enabled_providers_with_secrets(&dir).expect("listing enabled providers should succeed");
        assert!(enabled_after.is_empty());

        let all_providers = list_providers(&dir).expect("listing all providers should still show it");
        assert_eq!(all_providers.len(), 1);
        assert!(!all_providers[0].enabled);
    }

    #[test]
    fn several_providers_can_be_configured_and_enabled_at_once() {
        let dir = temp_app_data_dir("multiple");
        add_provider(&dir, "OpenAI", "https://api.openai.com/v1", Some("key-1".to_owned()), "gpt-4o-mini")
            .expect("adding the first provider should succeed");
        add_provider(&dir, "Ollama local", "http://localhost:11434/v1", None, "llama3.1")
            .expect("adding the second provider should succeed");

        let enabled = enabled_providers_with_secrets(&dir).expect("listing enabled providers should succeed");

        assert_eq!(enabled.len(), 2);
    }

    #[test]
    fn removing_an_unknown_provider_id_is_an_error() {
        let dir = temp_app_data_dir("remove-unknown");

        let error = remove_provider(&dir, "does-not-exist")
            .expect_err("removing an unconfigured provider id should fail");

        assert!(error.contains("does-not-exist"));
    }

    #[test]
    fn removing_a_provider_deletes_it_but_keeps_the_others() {
        let dir = temp_app_data_dir("remove");
        let first = add_provider(&dir, "OpenAI", "https://api.openai.com/v1", Some("key".to_owned()), "gpt-4o-mini")
            .expect("adding the first provider should succeed");
        add_provider(&dir, "Ollama local", "http://localhost:11434/v1", None, "llama3.1")
            .expect("adding the second provider should succeed");

        remove_provider(&dir, &first.id).expect("removing the first provider should succeed");

        let remaining = list_providers(&dir).expect("listing should succeed");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].label, "Ollama local");
    }

    #[test]
    fn a_trailing_slash_in_the_base_url_is_normalized_away() {
        let dir = temp_app_data_dir("trailing-slash");

        let summary = add_provider(&dir, "OpenAI", "https://api.openai.com/v1/", None, "gpt-4o-mini")
            .expect("adding should succeed");

        assert_eq!(summary.base_url, "https://api.openai.com/v1");
    }
}
