use base64::{engine::general_purpose::STANDARD, Engine};
use minisign_verify::{PublicKey, Signature};

fn configured_public_key() -> PublicKey {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let encoded = config["plugins"]["updater"]["pubkey"].as_str().unwrap();
    let decoded = String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
    PublicKey::decode(&decoded).unwrap()
}

#[test]
fn updater_has_a_valid_public_key_and_only_the_expected_https_feed() {
    let _ = configured_public_key();
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    assert_eq!(
        config["plugins"]["updater"]["endpoints"],
        serde_json::json!([
            "https://raw.githubusercontent.com/Dasshopen/reverse-assistant/main/updates/latest.json"
        ])
    );
    assert!(config["plugins"]["updater"]
        .get("dangerousInsecureTransportProtocol")
        .is_none());
    assert_eq!(config["plugins"]["updater"]["requireSignedVersion"], true);
    assert_eq!(config["plugins"]["updater"]["allowDowngrades"], false);
    let release: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.release.conf.json")).unwrap();
    assert_eq!(release["bundle"]["createUpdaterArtifacts"], true);
}

#[test]
#[ignore = "requires the packaged installer via RA_SIGNED_UPDATER_ARTIFACT"]
fn signed_installer_matches_embedded_key_and_rejects_tampering() {
    // Read only: this test never starts the installer or downloads an update.
    let path = std::env::var("RA_SIGNED_UPDATER_ARTIFACT").expect("Set installer path");
    let data = std::fs::read(&path).unwrap();
    let encoded_signature = std::fs::read_to_string(format!("{path}.sig")).unwrap();
    let decoded_signature =
        String::from_utf8(STANDARD.decode(encoded_signature.trim()).unwrap()).unwrap();
    let signature = Signature::decode(&decoded_signature).unwrap();
    let key = configured_public_key();
    key.verify(&data, &signature, true)
        .expect("Installer must match the embedded updater key");
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let signed_version = signature
        .trusted_comment()
        .split('\t')
        .find_map(|field| field.strip_prefix("version:"));
    assert_eq!(
        signed_version,
        config["version"].as_str(),
        "Signed artifact must match the announced application version"
    );
    let mut tampered = data;
    tampered[0] ^= 1;
    assert!(key.verify(&tampered, &signature, true).is_err());
}
