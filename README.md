# Reverse Assistant

A local-first reverse-engineering desktop application built with Rust, Tauri 2,
Svelte 5 and TypeScript, connecting Ghidra with function identification and
optional AI-assisted naming.

## Install from GitHub

**Start here: [step-by-step Windows installation guide](docs/INSTALLATION_WINDOWS.md).**
Follow the guide to install prerequisites, download or clone the project,
generate the BSim corpus, configure Ghidra and Ollama, and run your first test.
Troubleshooting instructions are included.

This repository contains **source code**, not a ready-to-run installer.
The generated BSim corpus is not included in the GitHub download.

## Status and features

**Early alpha, primarily tested on Windows.** Only analyze software you are
authorized to inspect. Naming suggestions are not ground truth.

- Automatic Ghidra Headless analysis and import of JSON exports (schemas v1/v2).
- Function explorer, assembly, pseudocode, strings, types, imports/exports,
  call graphs, comparison and reporting tools.
- Symbols, RTTI, FunctionID (FID) and BSim reference matches before AI naming.
- Arbitration of ambiguous matches and manual review of unconfirmed hypotheses.
- Confirmed renaming in the local Ghidra project, saved projects and reopening.
- Combined assembly/pseudocode loading in the Code Browser, without BSim work
  just to display code, plus local caching.

FID uses reference fingerprints; BSim compares function features with a reference
database. Both have limited coverage. AI confidence is a signal, not a calibrated
probability, and the AI layer does not replace evidence.

## Privacy

Analysis runs locally. With local Ollama, AI prompts can also remain local.
**A configured remote provider receives analysis context, including pseudocode
and strings.** Review its policy before using confidential binaries.
See [SECURITY.md](SECURITY.md) for data boundaries and publication precautions.

## Development setup (Windows)

Prerequisites:

- Node.js/npm and stable Rust with the MSVC toolchain.
- Microsoft C++ Build Tools, Windows SDK and WebView2.
- Ghidra 12.1.2 and Java 21 for the current integration. The setup assistant can
  help configure these tools and the Reverse Assistant extension.
- Optional Ollama with a downloaded model, or an OpenAI-compatible AI provider.

From the repository root:

For a fresh download, first follow the installation guide above, including
the corpus generation step. The short commands below are not a complete
first-install procedure.

```powershell
npm.cmd ci
npm.cmd run tauri dev
```

Configure Ghidra through the setup assistant. Manual extension deployment is
available in [scripts/deploy-ghidra-extension.ps1](scripts/deploy-ghidra-extension.ps1).

### BSim corpus and installers

Downloaded sources, reference binaries and generated databases are not committed.
Build scripts, pinned hashes and license metadata are documented in
[bsim-corpus/README.md](bsim-corpus/README.md).

The Tauri bundle currently expects `bsim-corpus/build/reverse-assistant-seed.mv.db`.
Generate it with the documented pipeline before `npm.cmd run tauri build`.
A clean checkout does not include this generated resource. Verify third-party
redistribution rights before publishing corpus assets or reference binaries.

## Checks

```powershell
npm.cmd run check
cargo check --manifest-path src-tauri/Cargo.toml --all-targets
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
.\scripts\audit-publication.ps1 -IncludeHistory
```

Close a running development app before rebuilding its executable on Windows.
Real Ghidra checks are documented in [tests/ghidra/README.md](tests/ghidra/README.md).
The publication scanner is a read-only heuristic, not a security certification.

## Known limitations

- Cold code display starts Ghidra and can take several seconds; cached loads
  are much faster.
- Imported functions have no local implementation. Only their local relay can
  be displayed when present.
- Corpus coverage is limited; similar matches can remain ambiguous.
- Local models can abstain or return malformed/truncated responses. Review
  diagnostics instead of assuming every function will receive a name.
- Provider keys are stored in local app-data settings, not an encrypted vault.
  Never share those settings.

## License

Application source: [MIT](LICENSE). Tools, models, reference libraries and corpus
artifacts retain their own licenses.
