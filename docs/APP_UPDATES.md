# Application updates

## For users

The application checks for updates at startup in packaged builds. Open
**Settings → Application updates** (`Paramètres → Mises à jour de l’application`)
to check manually or turn automatic checks off.

When an update is available, download it from this panel. The application
verifies its cryptographic signature before allowing installation. Downloading
does not rename functions or change projects. Installation requires a separate
confirmation, closes the app and restarts it after the Windows installer runs.
Finish current operations and save your work before confirming.

A failed check does not mean the application is up to date. You can continue
using the installed version when offline. Failed downloads or signature checks
do not start the installer. This updates Reverse Assistant, not Java, Ghidra,
Ollama or AI models.

Older versions without the updater need one manual installation of the first
updater-enabled build. They cannot acquire this feature automatically.

The updater signature is separate from Windows Authenticode signing. Windows
may still warn about the unsigned installer. Keep security protections enabled.

## For maintainers

The implementation uses the [official Tauri updater](https://v2.tauri.app/plugin/updater/)
with HTTPS, signature verification and the default newer-version comparison.
The version must also be included in the signed artifact metadata and match
the announced version. Downgrades and legacy signatures without a version are
rejected.
No GitHub token or private signing key is included in the client.

### Signing key

Keep the private key outside the repository, with a secure backup. The initial
local key is stored under `%USERPROFILE%\.tauri\reverse-assistant\updater.key`;
its directory is restricted to the local Windows account and SYSTEM. Only the
public key is embedded in `tauri.conf.json`.

Do not replace this key casually: existing clients trust its public counterpart.
Do not commit private keys, upload them as release assets or include them in
diagnostic logs. Keep the key directory out of shared backups unless protected.
If using a password-protected key, supply `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
through your local environment or secret store, not repository files.

### Build and publish an Alpha update

Use Tauri CLI 2.12.1 or newer within Tauri 2. Older CLI versions can create
signatures without version metadata; this application deliberately rejects
those signatures. Packaging runs in non-interactive mode and fails closed if
the signature or version binding is missing.

1. Increase the numeric app version in package files, Cargo files and Tauri
   configuration. Use a new version for every distributed build.
2. Run `scripts/build-windows-installer.ps1` with your Ghidra installation,
   `-ReleaseTag vVERSION-alpha.1` and a release-notes file. The script uses the
   local key or `TAURI_SIGNING_PRIVATE_KEY`, generates the signed installer,
   its `.sig`, checksums, notices and a candidate `latest.json`.
3. Test installation, analysis, renaming and save/reopen in a clean Windows VM.
   Do not advertise a candidate before validating it.
4. Publish the matching GitHub release and upload the exact installer, its
   `.sig`, `SHA256SUMS.txt` and `THIRD_PARTY_NOTICES.txt`. Include `latest.json`
   as a release asset for inspection. Never edit a signed installer afterward.
5. Confirm the versioned installer URL is publicly accessible without login.
   Copy the generated `latest.json` to `updates/latest.json`, review it, then
   commit and push that public manifest to `main`.
6. On a previous updater-enabled installation, check for the new version,
   download it, confirm installation, and verify the new version and retained
   projects. Also test an offline check and cancelled installation.

The fixed feed is
`https://raw.githubusercontent.com/Dasshopen/reverse-assistant/main/updates/latest.json`.
It does not use GitHub's “latest release” redirect, so prereleases can be served
explicitly. The candidate manifest is not published automatically by the build
script. Until a valid public feed is published, checks report unavailable.

**A private repository cannot serve this unauthenticated feed.** Make the
release/feed public or use a separate public distribution repository and
change the configured endpoint. Never work around this by embedding a token.

The first updater-enabled build can only validate checks/downloads initially;
a full upgrade test needs a second, higher-version signed build. Unit tests
and signature generation alone are not an end-to-end installation test.
