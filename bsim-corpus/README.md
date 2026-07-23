# BSim seed corpus

Ghidra's BSim (binary similarity) database ships **empty** — nothing matches
until reference binaries are analyzed and their signatures ingested. This
directory holds the reproducible pipeline that builds a small seed corpus,
used to validate BSim end to end before deciding whether/how to scale it.

## What's in here

- `manifest.json` — one entry per reference library: version, official
  source URL, SHA-256, license, and the date it was pinned. Nothing is
  fetched from an unverified source.
- `scripts/build-sqlite.ps1`, `scripts/build-zlib.ps1` — download the
  official source (skipped if already present), verify its hash against
  `manifest.json`, and compile it as an x64 DLL **with debugging symbols
  kept** using the locally installed Visual Studio Build Tools.
- `scripts/build-corpus-database.ps1` — analyzes each compiled DLL with a
  full (not speed-optimized) Ghidra headless pass, then creates a BSim
  database and generates+commits signatures for each library via Ghidra's
  `bsim` CLI tool.
- `scripts/VerifyBsimQuery.java` — a one-time validation script (not part of
  the shipped Ghidra extension) that queries every function of an analyzed
  reference project back against the built database, to prove the whole
  generate → ingest → query pipeline actually works.
- `sources/`, `build/` — gitignored. Downloaded archives, compiled
  DLLs/PDBs, Ghidra projects, and the resulting `.mv.db` all live here,
  regenerated locally by the scripts above. Nothing under these two
  directories is committed.

## Why compile from source instead of using precompiled DLLs

BSim has no separate "library name" concept the way Ghidra's FunctionID
feature does — a BSim signature just carries whatever name the analyzed
Ghidra program had for that function. Compiling the reference libraries
ourselves, with symbols kept, means Ghidra's own PDB analyzer assigns the
real function names during analysis, and those correct names flow through
automatically into the BSim database. Precompiled, stripped DLLs would give
working hashes but weak or absent names.

## Reproducing the corpus locally

```powershell
# 1. Compile the reference libraries (downloads + verifies sources first)
.\scripts\build-sqlite.ps1
.\scripts\build-zlib.ps1

# 2. Analyze them and build the BSim database
.\scripts\build-corpus-database.ps1 -GhidraInstallDir "C:\path\to\ghidra_12.x_PUBLIC"
```

This produces `build\reverse-assistant-seed.mv.db`.

## Current scope (deliberately narrow)

One architecture (x64) and one compile profile (optimized, symbols kept),
two libraries (SQLite 3.53.3, zlib 1.3.2). This was validated end to end
(`VerifyBsimQuery.java` confirmed real function names matching correctly)
before any decision to expand to more libraries, architectures, or compile
profiles — expand only after checking the pipeline still holds.

**Not yet done:**
- Publishing the built `.mv.db` as a GitHub Release asset (a public action
  requiring explicit sign-off, not automated by these scripts).
- Wiring BSim queries into the actual app (the Rust `services::bsim_corpus`
  module currently only knows how to download/verify/cache a published
  corpus asset — no query command is wired to the UI yet, mirroring how
  FunctionID was built in a previous phase).

## Adding more libraries later

Add an entry to `manifest.json` (name, version, official source URL,
license), write a `build-<name>.ps1` following the same
download → verify → compile-with-symbols pattern as `build-sqlite.ps1`, and
add it to the `$libraries` array in `build-corpus-database.ps1`.
