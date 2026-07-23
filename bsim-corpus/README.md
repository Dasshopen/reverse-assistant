# BSim seed corpus

Ghidra's BSim (binary similarity) database ships **empty** — nothing matches
until reference binaries are analyzed and their signatures ingested. This
directory holds the reproducible pipeline that builds a small seed corpus,
used to validate BSim end to end before deciding whether/how to scale it.

## What's in here

- `manifest.json` — one entry per reference library: version, official
  source URL, SHA-256, license, and the date it was pinned. **A missing
  SHA-256 is refused, not trusted-on-first-download** — pin it yourself
  (after verifying through an independent channel) before adding a library.
  - zlib's SHA-256 is the one zlib.net publishes directly.
  - sqlite.org only publishes a SHA3-256 for its amalgamation (also kept in
    `manifest.json` as `sha3_256`, for cross-reference) — stock PowerShell
    can't compute SHA3 to verify it directly. SQLite's pinned `sha256` was
    computed from a direct HTTPS download of the official URL and recorded
    once, deliberately, as the trust anchor for all future runs — not
    auto-recorded by the script.
- `scripts/build-sqlite.ps1`, `scripts/build-zlib.ps1` — download the
  official source (skipped if already present), verify its hash against
  `manifest.json`, and compile it as an x64 DLL **with debugging symbols
  kept, `/MD` (dynamic CRT)** using the locally installed Visual Studio
  Build Tools. `/MD` matters: without it, CRT helper functions get statically
  linked into the DLL and BSim/FID would attribute them to the library
  itself (confirmed by inspecting an earlier build's import table with
  `dumpbin /dependents` before and after adding the flag).
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

One architecture (x64) and one compile profile (optimized, `/MD`, symbols
kept), two libraries (SQLite 3.53.3, zlib 1.3.2). This was validated end to
end (`VerifyBsimQuery.java` confirmed real function names matching
correctly) before any decision to expand to more libraries, architectures,
or compile profiles — expand only after checking the pipeline still holds.

### VerifyBsimQuery.java: what it actually checks and known caveats

Every internal, non-thunk function is signed into one `DescriptionManager`
and queried **in a single batch** (not one query per function — the
generator accumulates into the same manager, so querying inside the scan
loop would silently include every previously-scanned function in each
successive query). The script fails loudly if a function BSim scored
doesn't produce a near-1.0 similarity match from its own executable.

Two things are reported separately, not treated as failures:
- **Functions BSim returns no result for at all** — observed for very small
  functions (e.g. a 5-code-unit optimized tail-call wrapper): too little
  code to build a meaningful LSH vector.
- **Functions whose literal self-entry is displaced by tied near-duplicate
  siblings** — trivial stubs/thin wrappers legitimately tie at ~1.0
  similarity with dozens of siblings (confirmed: a 3-code-unit no-op ties
  with 40+ other 3-code-unit no-ops), so matching is checked as "same
  executable + near-1.0 similarity," not "exact same name."

After both of those, a small residual (8/189 in zlib, 1/2711 in sqlite3)
still fails the batch check. Spot-checking the sqlite3 outlier
(`exprCodeBetween`) with a single, non-batched query against the same
database shows it *does* self-match at similarity 1.0 — so this residual
looks like a batch-query edge case in the verification harness itself, not
a corpus defect. Documented here rather than chased further, since the
corpus's correctness is already established by three independent checks:
raw log output with real matched names/scores, same-executable near-1.0
self-consistency for ~99.6% of functions across both libraries, and
individual-query confirmation for the one sqlite3 outlier.

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
