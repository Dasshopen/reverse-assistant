# Reverse Assistant

Understand compiled programs and give unidentified functions meaningful names.

Reverse Assistant is a desktop application that brings Ghidra analysis,
reference-library matching and optional AI assistance into one workspace.
Explore assembly and pseudocode, inspect the evidence behind each suggested
name, and decide which changes to apply.

## Get started

**Windows x64 · Early alpha · AI optional**

1. Download the Windows **`-setup.exe`** from [GitHub Releases](https://github.com/Dasshopen/reverse-assistant/releases).
2. Install and open Reverse Assistant.
3. Complete the guided setup, then open a binary you are authorized to analyze.

**Download status:** a Windows test installer has been built locally. It has
not yet been published in Releases or validated on a clean Windows machine.
If no setup executable is attached to a release, there is no packaged download
available. **The “Source code” ZIP is not an installer.**

The packaged installer includes the reference corpus and Ghidra extension.
First-time setup downloads Java and Ghidra when needed. You do not need to
install development tools or compile the corpus yourself. AI setup is separate.

[Installation guide](docs/INSTALLATION_WINDOWS.md) ·
[Using the application](docs/USER_GUIDE.md) ·
[Help and troubleshooting](docs/TROUBLESHOOTING.md)

## What you can do

- Inspect functions, assembly, pseudocode, strings and imports/exports.
- Explore detected types, call graphs and program comparisons.
- Identify known functions using symbols, RTTI, Function ID and BSim.
- Ask an optional AI provider to examine unresolved or ambiguous functions.
- Compare suggested names with their evidence and review uncertain cases.
- Apply renames to the local Ghidra project, save your work and reopen it.
- Generate local analysis reports.

## How suggested names are produced

| Source | What it contributes |
| --- | --- |
| Existing symbols and RTTI | Names and C++ type information already present in the binary. |
| Function ID (FID) | Function fingerprints compared with available reference databases. |
| BSim | Similarity matches against functions from known reference programs. |
| Optional AI | Context-based proposals and assistance with ambiguous candidates. |

Reference matching comes before AI-generated naming. A close BSim match can
still have several plausible names, and AI can make mistakes. Automatic naming
uses additional checks; other proposals remain available for manual review.
**Confidence scores are not guarantees or calibrated probabilities.**

## Local analysis and optional AI

Ghidra analyzes the binary locally without executing the target program.
AI is not required to explore code or use reference matching.

Use a local Ollama model to keep AI requests on your machine. A configured
remote provider receives the selected analysis context, including pseudocode
and strings. Read [Privacy and security](SECURITY.md) before working with
confidential or untrusted files.

[Configure optional AI](docs/AI_SETUP.md)

## Before you use the alpha

- Analyze only software you are authorized to inspect.
- Corpus coverage is limited: some functions will remain unidentified.
- Imported functions may have no local implementation to display.
- Initial analysis and first code loads can take time; cached loads are faster.
- Local AI models can abstain, time out or return unusable responses.
- The test installer is unsigned; inspect its source and checksum before use.
- Windows is the primary tested platform. Linux ELF analysis from Windows is
  supported by the pipeline; a Linux desktop release is not established here.
- The current application interface is primarily French. This documentation
  is in English; translated control names are explained where needed.

## Documentation

Find all guides in the [documentation index](docs/README.md).

For developers: [Build from source](docs/BUILD_FROM_SOURCE.md) and
[Contributing](CONTRIBUTING.md). The repository folders contain application
source, reference-build tooling and regression tests. End users do not need
to run those tools or tests.

## License

Application source: [MIT](LICENSE). Third-party tools, models and reference
components retain their own licenses. Release packages include third-party notices.
