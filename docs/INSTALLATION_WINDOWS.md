# Get started with Reverse Assistant

## Download

Open [GitHub Releases](https://github.com/Dasshopen/reverse-assistant/releases)
and download the Windows x64 file ending in **`-setup.exe`** from the selected
release. Download the installer, not the “Source code” ZIP.

**Release status:** the first installer is being prepared for testing. If no
setup executable is attached to a release, no packaged download is available
yet. The source archive is not a replacement installer.

Use Windows 10 or 11, 64-bit. Keep an Internet connection available for first
setup. This alpha is an analysis tool, not a sandbox for untrusted files.

## Install

Run the setup executable and follow the installer. Launch **Reverse Assistant**
from the Start menu. You do not need Node.js, Rust, Visual Studio, Gradle or a
terminal to use the packaged application.

The installer checks for WebView2 and downloads its runtime if required.
If Windows displays a security warning, verify the download source and release
checksum before deciding to proceed. Do not disable your security software.
Test installers may be unsigned; this is stated in the release notes.

## Complete first-time setup

The application displays a setup assistant when analysis tools are missing.

1. Review the listed components and licenses.
2. Accept installation in the displayed local directory.
3. Select **Install and configure automatically** (the current French interface
   labels this button **Installer et configurer automatiquement**).
4. Wait for setup to finish. Java and Ghidra are downloaded if needed. The
   extension and prebuilt BSim corpus come with the installer. Nothing is
   compiled on your machine.

Tools are managed in your Windows application-data directory. No system
environment-variable configuration is required. Network failures are reported
in the assistant; restore connectivity and retry.

## Analyze your first binary

Open a small binary you are authorized to inspect. Wait for analysis to finish,
then explore functions, assembly and pseudocode. Inspect names and evidence
before renaming. Save the project to continue later.

The target is analyzed without being executed. Imported functions may have no
local code. Reference matches depend on corpus coverage; not every function
will receive a proposed name.

## Add AI later (optional)

You can use the application without AI. To enable local AI, install
[Ollama](https://ollama.com/download/windows), download a model, and add its
connection in the application's provider settings. See
[local AI configuration](BUILD_FROM_SOURCE.md#5-enable-local-ai-optional).
Ollama and model downloads are not forced during first setup.

Remote AI providers receive submitted analysis context. Read
[SECURITY.md](../SECURITY.md) before analyzing confidential material.

## Need help?

Include the application version, Windows version and complete error message
when reporting a problem. Never share API keys or confidential binaries.
Developers: read [Build from source](BUILD_FROM_SOURCE.md).
