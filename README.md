# Reverse Assistant

Reverse Assistant is an open-source, local-first reverse engineering assistant built with Rust, Tauri, SvelteKit, and TypeScript.

The project is designed to support reverse engineering workflows without requiring binaries or analysis data to be uploaded to a public server.

## Project principles

- Local-first processing
- Open-source development
- Rust-based analysis engine
- AI is optional and provider-agnostic
- The application must remain usable without AI
- Structured integration with Ghidra
- Minimal and controlled token usage
- Separation between the analysis engine and the user interface

## Current status

Phases 1 to 6 — completed.

The current application provides:

- A working Tauri desktop application (SvelteKit, TypeScript, Rust)
- A versioned JSON contract (schema v1) between Ghidra and the Rust engine
- A Ghidra extension (`ReverseAssistantExporter`) that exports program and function metadata as JSON
- A Rust service that imports, validates, and summarizes a Ghidra export
- A native file dialog and a function explorer showing parameters, calls, referenced strings, and decompiled code

The Ghidra export/import step is still manual: the user runs the extension inside Ghidra, then selects the resulting JSON file in Reverse Assistant. Automating this end-to-end (Ghidra Headless driven by Rust), connecting BSim for known-function recognition, and adding an AI naming agent for the remaining functions are the next phases — see the roadmap below.

## Architecture

```text
SvelteKit / TypeScript interface
              |
              | Tauri commands
              v
        Tauri Rust adapter
              |
              v
   Independent Rust analysis core
              |
              v
       Ghidra JSON exchange
              |
              v
 Optional AI provider adapters

The long-term objective is to keep the Rust analysis engine independent from Tauri and from any specific AI provider.

Technology stack
Rust
Tauri 2
SvelteKit
Svelte 5
TypeScript
Vite
npm
Serde and serde_json
Prerequisites

For Windows development:

Git
Node.js and npm
Rust with the stable MSVC toolchain
Microsoft C++ Build Tools
Windows SDK
Microsoft Edge WebView2
Visual Studio Code, recommended
Installation

Clone the repository and enter the project directory:

git clone <repository-url>
cd reverse-assistant

Install the frontend dependencies:

npm install

Launch the desktop application in development mode:

npm run tauri dev
Quality checks

Check the Svelte and TypeScript code:

npm run check

Check the Rust code:

cargo check --manifest-path src-tauri/Cargo.toml

Audit npm dependencies:

npm audit
Roadmap
Phase 1: Tauri application skeleton and TypeScript-to-Rust communication — completed
Phase 2: Stable JSON contract — completed
Phase 3: Ghidra export integration — completed
Phase 4: Ghidra export import, validation, and summary in Rust — completed
Phase 5: Tauri import command and import interface — completed
Phase 6: Native file dialog and function explorer — completed
Phase 7: Ghidra Headless automation driven by Rust (no manual export/import step)
Phase 8: BSim integration for known-function recognition
Phase 9: AI naming agent and validated rename back into Ghidra
Security

Reverse Assistant is intended to process reverse engineering data locally.

The project follows these principles:

No mandatory upload to a public server
No mandatory AI provider
Explicit Tauri capabilities
Minimal plugin usage
Audited npm dependencies
Locked dependency versions
No secrets committed to Git

Security controls will be expanded as the application gains file access, Ghidra integration, and optional external-provider communication.