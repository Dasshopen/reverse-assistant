# Contributing

This page is for developers. To use the packaged application, start with the
[installation guide](docs/INSTALLATION_WINDOWS.md).

## Set up a development environment

Follow [Build from source](docs/BUILD_FROM_SOURCE.md), including the corpus
generation instructions. Generated reference binaries and databases remain local.
Do not commit downloaded tools, sample binaries, personal settings or API keys.

## Verify changes

From the repository root:

```powershell
npm.cmd run check
cargo check --manifest-path src-tauri/Cargo.toml --all-targets
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
.\scripts\audit-publication.ps1 -IncludeHistory
```

Close the running development application before rebuilding its executable
on Windows. Ghidra integration checks are documented in
[tests/ghidra](tests/ghidra/README.md). Tests are regression controls, not
required end-user steps or proof of a successful clean-machine installation.

## Keep evidence and claims clear

- Preserve the separation between reference matches and generated hypotheses.
- Do not treat AI confidence as a calibrated probability.
- Cover changed naming, persistence and parsing rules with regression tests.
- Document observed limitations rather than hiding failed analyses.
- Update the user guide when changing a visible workflow or control.
- Keep current user instructions separate from historical design notes.

## Prepare releases

Follow the [release checklist](docs/RELEASE_CHECKLIST.md). A successful build
is not sufficient: verify the packaged app on clean Windows and review
redistribution rights. Keep installers in Release assets, not Git source history.
