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
- `scripts/build-sqlite.ps1`, `scripts/build-zlib.ps1`,
  `scripts/build-lz4.ps1`, `scripts/build-xxhash.ps1`,
  `scripts/build-zstd.ps1`, `scripts/build-brotli.ps1` — download the
  official source (skipped if already present), verify its hash against
  `manifest.json`, and compile it as an x64 DLL **with debugging symbols
  kept, `/MD` (dynamic CRT)** using the locally installed Visual Studio
  Build Tools. `/MD` matters: without it, CRT helper functions get statically
  linked into the DLL and BSim/FID would attribute them to the library
  itself (confirmed by inspecting an earlier build's import table with
  `dumpbin /dependents` before and after adding the flag).
- `scripts/build-edk2-uefi.ps1` — builds the official EDK2 X64 UEFI Shell
  plus nine production ShellPkg applications/dynamic commands from the
  pinned stable tag, with their PDB/map symbols. Python, NASM and the
  EDK2 submodules actually required by the build are portable downloads
  with pinned hashes; nothing is installed system-wide.
- `scripts/build-corpus-database.ps1` — analyzes each compiled DLL with a
  full (not speed-optimized) Ghidra headless pass, then creates a BSim
  database and generates+commits signatures for each library via Ghidra's
  `bsim` CLI tool.
- `scripts/VerifyBsimQuery.java` — a one-time validation script (not part of
  the shipped Ghidra extension) that queries every function of an analyzed
  reference project back against the built database, to prove the whole
  generate → ingest → query pipeline actually works.
- `scripts/verify-corpus.ps1` — runs that validator against every reference
  project and checks an explicit success marker. This is necessary because
  `analyzeHeadless` can return exit code 0 even when a post-script fails.
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
.\scripts\build-lz4.ps1
.\scripts\build-xxhash.ps1
.\scripts\build-zstd.ps1
.\scripts\build-brotli.ps1
.\scripts\build-msvc-runtime.ps1
.\scripts\build-edk2-uefi.ps1

# 2. Analyze them and build the BSim database
.\scripts\build-corpus-database.ps1 -GhidraInstallDir "C:\path\to\ghidra_12.x_PUBLIC"

# 3. Verify every reference function against the resulting database
.\scripts\verify-corpus.ps1 -GhidraInstallDir "C:\path\to\ghidra_12.x_PUBLIC"
```

This produces `build\reverse-assistant-seed.mv.db`.

## Current scope (deliberately narrow)

One architecture (x64) and one compile profile (optimized, `/MD`, symbols
kept), six high-value libraries (SQLite 3.53.3, zlib 1.3.2, LZ4 1.10.0,
xxHash 0.8.3, Zstandard 1.5.7, Brotli 1.2.0), one MSVC runtime reference,
and an official EDK2 UEFI ShellPkg stable202605 set. The original four were
validated end to end (`VerifyBsimQuery.java` confirmed real function names
matching correctly) before any decision to expand to more libraries,
architectures, or compile profiles; zstd and brotli were added the same way
and validated the same way — expand further only after checking the
pipeline still holds.

The EDK2 target covers common firmware code from `MdePkg`, `MdeModulePkg`,
`NetworkPkg`, and `ShellPkg`, including BaseLib, BaseMemoryLib, SafeInt,
printing, device paths, UEFI services, and shell command helpers. Keeping
several linked images gives shared routines more chances to retain a real PDB
name instead of a `FUN_...` placeholder. It remains a focused x64/VS2022
reference rather than a claim to cover every vendor firmware or compiler
profile.

The expanded corpus was also checked through the application's real bulk-query
path against the Catbert `0.efi` test image. Of its 729 unnamed functions, 45
received at least one usable BSim candidate; 39 had an EDK2 candidate and 22
top candidates had both similarity >= 0.90 and significance >= 10. Examples
include `StrCatS`, `StrnCatS`, `CopyGuid`, `CompareGuid`, and
`AsciiStrToUnicodeStrS`. These remain suggestions rather than automatic proof:
compiler options and small shared helpers can still produce ambiguous matches.

The same application path was checked against the real `serpentine.exe` test
binary: 270 of 342 unnamed functions received a BSim candidate, including 162
top candidates with similarity >= 0.90 and significance >= 10. No Ghidra
placeholder or MSVC string-literal symbol survived the corpus/query filters.

Before signatures are generated, `RemoveUnusableBsimFunctions.java` removes
functions whose only name is a Ghidra default placeholder (`FUN_...`,
`sub_...`, `LAB_...`) as well as MSVC string-literal symbols (`??_C@...`).
Those functions may have valid machine-code signatures, but they cannot teach
the application a meaningful name and would otherwise crowd useful candidates
out of BSim's bounded result window. The application repeats the name filter at
query time so older locally generated databases remain safe to display.

The local `build-msvc-runtime.ps1` target is intentionally different. It
builds a local, `/MT`, symbol-rich reference executable from a small harness
covering common CRT/STL families. This teaches BSim the exact MSVC/UCRT version
installed on the user's machine, which is more useful for current Windows
binaries than pretending those statically linked helpers belong to SQLite or
zlib. Neither the generated executable nor its PDB is distributed; the local
`toolchain.txt` records compiler provenance. Wrapper functions are prefixed
`ra_reference_` so a match can never be mistaken for a Microsoft symbol.

Brotli's hash-chain implementation is macro-templated into families of a
dozen-plus near-identical functions per hash size (`HashTypeLengthH2`..
`H68`, `StoreLookaheadH2`..`H68`, ...), which pushed enough same-executable
near-duplicates into the ranking that `VerifyBsimQuery.java`'s match window
(100) started crowding a function's own database record out entirely
(confirmed: 70/1030 functions affected). Widened to 300 — see the comment
by `MATCHES_PER_FUNC` in `VerifyBsimQuery.java`.

### VerifyBsimQuery.java: what it actually checks and known caveats

Every internal, non-thunk function is queried in a **bounded batch**. Each
batch uses a fresh signature generator and `DescriptionManager`: signatures
therefore cannot accumulate across successive queries, and a large program
does not depend on one oversized BSim response. Query functions are tracked
by entry-point address rather than name because names are not guaranteed to
be unique in Ghidra. The script fails loudly if a function BSim scored
produces neither its exact database record (same executable and address) nor
a near-1.0 equivalent from its own executable.

Two things are reported separately, not treated as failures:
- **Functions BSim returns no result for at all** — observed for very small
  functions (e.g. a 5-code-unit optimized tail-call wrapper): too little
  code to build a meaningful LSH vector.
- **Functions whose literal self-entry is displaced by tied near-duplicate
  siblings** — trivial stubs/thin wrappers legitimately tie at ~1.0
  similarity with dozens of siblings (confirmed: a 3-code-unit no-op ties
  with 40+ other 3-code-unit no-ops), so matching is checked as "same
  executable + near-1.0 similarity," not "exact same name."
- **Low-information signatures whose best result has significance below
  10** — real EDK2 functions can collapse onto hundreds of identical CRT or
  firmware stubs at that information level. If their own record falls outside
  the validation top-300, the verifier reports the ambiguity explicitly but
  does not call it a corpus loss. A missing self-match at significance 10 or
  above remains a hard failure unless all 300 returned slots are saturated by
  perfect-score ties. That saturation is itself proof that BSim cannot
  distinguish the function from the tied stubs; it is reported as ambiguity,
  never accepted as an identification.

The exact executable/address pair is accepted even if its regenerated score
is below 1.0. This is intentional: `sqlite3JournalOpen` consistently returns
its exact database record at similarity 0.873, while every other identity
field matches. Requiring 1.0 there would reject a valid round trip because of
minor signature-generation variance rather than detect a corpus error.

Earlier versions sent every function in one oversized request. That caused
intermittently incomplete batch responses (observed for 8/189 zlib functions
and `exprCodeBetween` in sqlite3 even though an individual query self-matched
at similarity 1.0). Bounded, isolated batches remove that harness artifact;
any remaining scored function without either its exact database record or a
same-executable near-1.0 equivalent is a real validation failure.

**Not yet done:**
- Publishing the built `.mv.db` as a GitHub Release asset (a public action
  requiring explicit sign-off, not automated by these scripts).

The app integration queries BSim on demand in the same Ghidra launch used to
decompile the selected function, then shows the candidate name, reference
executable, similarity, and significance without renaming anything. During
development it discovers this locally generated database under `build/`;
release builds will use the verified app-data cache after the database is
published.

## Adding more libraries later

Add an entry to `manifest.json` (name, version, official source URL,
license), write a `build-<name>.ps1` following the same
download → verify → compile-with-symbols pattern as `build-sqlite.ps1`, and
add it to the `$libraries` array in `build-corpus-database.ps1`.
