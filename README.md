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

Phase 1 — Application skeleton: completed.

The current application provides:

- A working Tauri desktop application
- A SvelteKit and TypeScript frontend
- A Rust backend
- A verified TypeScript-to-Rust command
- A minimal Reverse Assistant interface
- Dependency auditing and controlled install-script permissions
- A reduced Tauri permission set

The reverse engineering engine and Ghidra integration are not implemented yet.

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
Phase 1: Tauri application skeleton and TypeScript-to-Rust communication
Phase 2: Stable JSON contract
Phase 3: Ghidra export integration
Phase 4: Independent Rust analysis engine
Phase 5: MVP user interface
Phase 6: Return structured results to Ghidra
Phase 7: Optional AI provider adapters
Phase 8: Packaging and open-source publication
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