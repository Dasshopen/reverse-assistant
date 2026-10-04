# Windows release checklist (maintainers)

## Prepare

1. Generate and verify the corpus using the pinned reference pipeline.
2. Review redistribution rights, including Microsoft runtime signatures and
   transitive reference components. A manifest and collected license files
   do not establish legal compatibility by themselves.
3. Run `scripts/build-windows-installer.ps1 -GhidraInstallDir <installation>`.
   The script rebuilds the extension, collects notices, runs checks, and builds
   a per-user NSIS installer with precompiled extension and prebuilt corpus.
   It sanitizes repository/path metadata in a corpus copy and remaps compiler
   paths. The original development corpus is not modified.
4. Inspect `src-tauri/target/release/bundle/nsis`: installer,
   `SHA256SUMS.txt`, and `THIRD_PARTY_NOTICES.txt`.

## Validate on clean Windows

Use a VM with no Java, Ghidra, Node.js, Rust, Visual Studio or application cache.
Do not validate only on the development account.

- Install as a standard user; check WebView2 installation where absent.
- Open the app, accept licenses, and complete automatic setup.
- Confirm no compilation, terminal setup or environment-variable edits.
- Interrupt a download, retry, then restart: tools must remain usable.
- Analyze a small authorized binary; display code, inspect BSim evidence,
  rename, save and reopen. Check the renamed function across views.
- Confirm the app works without an AI provider; test optional AI separately.
- Verify upgrade/uninstall behavior without deleting user projects.

## Publish

Create a **draft prerelease** targeting the verified commit in GitHub Releases.
Attach the setup executable, checksum file and third-party notices. Mention
alpha limitations, network-required first setup and whether the binary is signed.
Publish only after clean-Windows checks and redistribution review pass.
Update the installation guide's release-status paragraph when the download
is actually available. Do not advertise a draft or source ZIP as a ready installer.
