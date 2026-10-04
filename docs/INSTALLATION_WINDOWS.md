# Install and test Reverse Assistant on Windows

This guide covers the alpha release, primarily tested on Windows x64.
The application can analyze Linux ELF binaries from Windows. Installing the
application on Linux has not been validated by this guide.

The repository contains **source code**, not a ready-to-run executable.
The GitHub ZIP does not include dependencies or the generated BSim corpus.
Build the application before running it.

Use these directories throughout this guide:

- Project: `C:\Projects\reverse-assistant`.
- Ghidra: `C:\Tools\ghidra_12.1.2_PUBLIC`.

Keep the project outside OneDrive and synchronized folders. Short paths help
avoid Windows path-length issues during EDK2 builds.

## 1. Install prerequisites

Install from the official websites. Close and reopen the terminal after
installation to load the updated environment variables.

| Tool | Installation instructions |
| --- | --- |
| [Node.js](https://nodejs.org/en/download) | Install Node.js 22 or 24 LTS with npm. |
| [Visual Studio Build Tools 2022](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) | Select **Desktop development with C++**, including MSVC v143 x64/x86 and a Windows SDK. Required for Rust/Tauri and reference corpus builds. |
| [Rust through rustup](https://rustup.rs/) | Install the stable Windows x64 **MSVC** toolchain, not GNU. |
| [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) | Install the Evergreen Runtime if it is not already installed. Tauri uses it to render the interface. |
| [Eclipse Temurin JDK 21](https://adoptium.net/temurin/releases/?version=21) | Select Windows x64 and **JDK**, not JRE. Enable the installer options to set `JAVA_HOME` and add Java to `PATH`. |
| [Ghidra 12.1.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build) | Download `ghidra_12.1.2_PUBLIC_20260605.zip`, not the “Source code” archives. Extract the distribution into `C:\Tools` so that `C:\Tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat` exists. Use this version for the current integration. |
| [Git for Windows](https://git-scm.com/downloads/win) | Install to clone the repository and receive updates. Not required for the ZIP method. |
| [Ollama](https://ollama.com/download/windows) | Install to enable local AI features. Ghidra analysis and deterministic matching do not require an AI model. |

See the [official Tauri prerequisites](https://v2.tauri.app/start/prerequisites/#windows)
for Windows build requirements. Do not install Tauri, Gradle, Python or NASM
globally for this project: npm installs the Tauri CLI, Ghidra provides the
Gradle launcher, and corpus scripts download their required portable tools.

Run these checks in PowerShell:

```powershell
node --version
npm.cmd --version
rustc --version
cargo --version
rustup show active-toolchain
java -version
javac -version
Test-Path 'C:\Tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat'
```

Confirm that the Rust toolchain includes `x86_64-pc-windows-msvc`, Java and
javac report version 21, and the final check returns `True`.
If multiple JDKs are installed, set `JAVA_HOME` to the JDK 21 directory and
place its `bin` directory first among Java entries in `PATH`.

## 2. Download the project

Choose one download method.

### Clone with Git

```powershell
git clone https://github.com/Dasshopen/reverse-assistant.git C:\Projects\reverse-assistant
Set-Location C:\Projects\reverse-assistant
```

The repository is private. Sign in with a GitHub account that has access.
Never paste an access token into a URL, project file or screenshot.

### Download the ZIP

Select **Code → Download ZIP** on GitHub. Extract the entire archive.
Move the extracted `reverse-assistant-main` directory to `C:\Projects` and
rename it to `reverse-assistant`. Confirm that
`C:\Projects\reverse-assistant\package.json` exists. Do not run the project
inside the ZIP or leave an extra nested project directory.

Open PowerShell and enter the project directory:

```powershell
Set-Location C:\Projects\reverse-assistant
```

### Install project dependencies

From the project root, run:

```powershell
npm.cmd ci
```

This installs the versions locked in `package-lock.json`. Do not copy
`node_modules` from another machine.

## 3. Generate the local BSim corpus

**Complete this step before your first full test.** The bundle configuration
expects `bsim-corpus\build\reverse-assistant-seed.mv.db`, which is not included
in Git or the ZIP. An existing installation can hide its absence by reusing
a cached corpus. A clean installation has no such cache.

Close Reverse Assistant and Ghidra. The scripts download sources with pinned
hashes, compile reference binaries with symbols, and analyze them to build the
database. Allow time, disk space and Internet access. Several minutes on a
compilation or analysis step do not, by themselves, indicate a failure.
Monitor the terminal output.

Run the reference build scripts in this order from the project root:

```powershell
$referenceBuildScripts = @(
    'build-sqlite.ps1',
    'build-zlib.ps1',
    'build-lz4.ps1',
    'build-xxhash.ps1',
    'build-zstd.ps1',
    'build-brotli.ps1',
    'build-msvc-runtime.ps1',
    'build-edk2-uefi.ps1',
    'build-pyinstaller.ps1'
)
foreach ($referenceBuildScript in $referenceBuildScripts) {
    & powershell.exe -NoProfile -File (Join-Path '.\bsim-corpus\scripts' $referenceBuildScript)
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $referenceBuildScript. Fix the error before continuing." }
}
```

Generate and verify the database:

```powershell
& powershell.exe -NoProfile -File .\bsim-corpus\scripts\build-corpus-database.ps1 -GhidraInstallDir 'C:\Tools\ghidra_12.1.2_PUBLIC'
if ($LASTEXITCODE -ne 0) { throw 'Corpus generation failed.' }
& powershell.exe -NoProfile -File .\bsim-corpus\scripts\verify-corpus.ps1 -GhidraInstallDir 'C:\Tools\ghidra_12.1.2_PUBLIC'
if ($LASTEXITCODE -ne 0) { throw 'Corpus verification failed.' }
Get-Item .\bsim-corpus\build\reverse-assistant-seed.mv.db
```

Downloads and generated files remain in `bsim-corpus/sources` and
`bsim-corpus/build`, excluded from Git. Read the
[corpus documentation](../bsim-corpus/README.md) for licenses and build details.
BSim and Function ID are separate: this pipeline generates the **BSim**
database, not a universal FID database. FID results depend on the reference
databases available and configured in Ghidra.

If Windows blocks a downloaded script, review its contents and provenance
before unblocking it through its file properties. Where local policy permits,
run a reviewed script with a process-scoped option:
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script> <arguments>`.
Do not disable protections globally or bypass an organization policy.

## 4. Launch and configure the application

From the project root, run:

```powershell
npm.cmd run tauri dev
```

The first Rust build can take several minutes. Keep the terminal open during
the test. Use the native Tauri window: opening `http://localhost:1420` in a
browser alone does not provide the Rust backend.

In the application's setup assistant:

1. Check Java and Ghidra. Select `C:\Tools\ghidra_12.1.2_PUBLIC` as the
   installation directory, not its `support` directory or ZIP archive.
2. Install/configure **Reverse Assistant Exporter** through the assistant.
   Close other Ghidra windows during installation.
3. Confirm that the local BSim corpus is detected.
4. If the assistant offers Java/Ghidra downloads, use them to prepare those
   tools. **They do not replace corpus generation in step 3.**

The extension can be built from the included sources. Its first Gradle build
can download dependencies. For manual deployment, launch Ghidra once and close
it to create its user directory, then run:

```powershell
& powershell.exe -NoProfile -File .\scripts\deploy-ghidra-extension.ps1 -GhidraInstallDir 'C:\Tools\ghidra_12.1.2_PUBLIC'
```

## 5. Enable local AI (optional)

Install and start Ollama, then download the model:

```powershell
ollama pull qwen2.5-coder:7b
ollama list
```

Add an OpenAI-compatible provider in Reverse Assistant's AI provider settings:

- URL: `http://localhost:11434/v1`.
- Model: `qwen2.5-coder:7b`. Use the exact name returned by `ollama list`.
- API key: leave empty for the standard local Ollama server.
- Add the provider and confirm that it is enabled.

Check the local server from PowerShell:

```powershell
Invoke-RestMethod http://localhost:11434/api/tags
```

Run an AI analysis in the application to check the complete request path.
Model downloads and memory requirements are substantial. Analysis speed
depends on CPU/GPU, RAM/VRAM and context size. Increasing context does not
guarantee better names and can slow responses. Keep Ollama local; do not expose
it to the network for this test. A remote provider receives submitted context,
including pseudocode and strings. Read [SECURITY.md](../SECURITY.md) before
sending confidential data.

## 6. Run your first test

Use a small binary you are authorized to analyze. No challenge binaries are
included. Do not execute the target binary to analyze it.

1. Open the binary and wait for Ghidra analysis to finish.
2. Open a **local function** in the Code Browser. Check its assembly and
   pseudocode. Imported functions have no local implementation; their local
   relay, where present, is a separate entry.
3. Inspect FID/BSim proposals. Zero matches can be valid when the corpus does
   not cover the binary's libraries.
4. If AI is enabled, wait for results and review provenance, evidence and
   manual-review suggestions. A proposed name is not a guaranteed recovery
   of the original symbol.
5. Verify a proposal, rename the function, check its name in other views,
   save the project and reopen it.

Use a VM or a separate Windows account to test a clean installation.
Downloading the repository again under your current account can reuse existing
Java, Ghidra, providers, corpus and projects from application data. Do not
delete those data without a backup.

## 7. Build an installer (optional)

After a successful test, with the corpus generated, run:

```powershell
npm.cmd run tauri build
```

Windows packages are generated under `src-tauri\target\release\bundle`, in
format-specific subdirectories. A compiled installer is not necessarily signed.
Check component and corpus redistribution rights before sharing a package.
These steps do not automatically publish a GitHub Release.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `npm.ps1` is blocked | Use `npm.cmd`, as shown in this guide. |
| `cargo`, `node` or `javac` is missing | Reopen the terminal after installation. Check `PATH` and install a JDK, not just a JRE. |
| `link.exe` or MSVC is missing | Add the C++ workload and Windows SDK through Visual Studio Installer. |
| `reverse-assistant-seed.mv.db` is missing | Complete step 3. Do not create an empty file or rename a ZIP to `.mv.db`. |
| BSim database is busy or locked | Close other analyses and Ghidra instances using the database, then retry. |
| Port `1420` is already in use | Stop the previous development terminal with Ctrl+C and run one instance. Do not terminate an unidentified process. |
| An `.exe` or extension `.jar` is locked | Close Reverse Assistant or Ghidra before rebuilding or deploying. |
| Ollama timeout or connection refused | Check that Ollama is running, the model is installed, the URL is correct and sufficient memory is available. |
| No code for an imported function | Its implementation is in an external library, not the analyzed binary. Select the local relay if available. |
| First build or analysis is slow | Monitor the logs. Downloads, compilation and cold Ghidra startup take longer than cached operations. |

When reporting a failure, include the command, full error message, Windows
version and tool versions. Never attach an API key or a confidential binary.
