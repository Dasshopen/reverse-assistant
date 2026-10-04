# Documentation

## Start using the application

| Guide | Read this to… |
| --- | --- |
| [Install on Windows](INSTALLATION_WINDOWS.md) | Download the installer and complete first-time setup. |
| [User guide](USER_GUIDE.md) | Open a binary, understand proposals, rename functions and save work. |
| [Optional AI](AI_SETUP.md) | Connect a local Ollama model or a remote provider. |
| [Help and troubleshooting](TROUBLESHOOTING.md) | Understand missing matches, delays and setup failures. |
| [Privacy and security](../SECURITY.md) | Understand local data, remote AI and safe sample handling. |

Check the [project README](../README.md#get-started) for current download status.
Do not confuse a source archive with a packaged application.

## Develop and maintain the application

- [Build from source](BUILD_FROM_SOURCE.md).
- [Contribution and verification workflow](../CONTRIBUTING.md).
- [Windows release checklist](RELEASE_CHECKLIST.md).
- [Clean Windows VM acceptance test](WINDOWS_VM_TEST.md).
- [Prepared alpha release notes](RELEASE_NOTES_0.1.0_ALPHA.md).
- [Reference corpus tooling](../bsim-corpus/README.md).
- [Ghidra regression checks](../tests/ghidra/README.md).

### Technical background

These notes record specific designs or past reviews. They are not installation
instructions and do not establish the current release's validation status.

- [Local naming agent v3](technical/local-agent-v3.md).
- [Reports and Ghidra round-trip](technical/local-reports-and-ghidra-renames.md).
- [Naming benchmark methodology](technical/naming-benchmark.md).
- [Historical ReVa security review](technical/reva-security-review.md).

## What the repository folders contain

| Folder | Purpose |
| --- | --- |
| `docs/` | User guides and separate developer documentation. |
| `src/` | Desktop interface source code. |
| `src-tauri/` | Rust backend, application configuration and Rust tests. |
| `ghidra-extension/` | Integration with Ghidra analysis and export. |
| `bsim-corpus/` | Reference manifests and scripts for maintainers to build the corpus. |
| `scripts/` | Maintainer setup, packaging and publication checks. |
| `tests/ghidra/` | Ghidra regression scripts, not challenge binaries or required user steps. |
| `static/` | Application web assets. |
| `.vscode/` | Editor settings for development. |

Generated installers, downloaded reference sources, test binaries and personal
settings are not committed to this repository.
