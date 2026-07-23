# Local reports and Ghidra round-trip

## PDF reports

Reports are generated entirely locally from the canonical analysis already loaded by the Rust
backend. No Ghidra process, network service, browser or AI provider is involved. The first report
format is intentionally bounded: it includes the complete overview/import list and up to 250
functions, 150 strings and 150 detected types, with explicit omission counts for larger programs.
This prevents a large statically linked binary from unexpectedly producing thousands of pages.

The PDF writer uses a standard built-in PDF font and transliterates unsupported Unicode characters
instead of embedding an externally licensed font. The original analysis data is never modified.

## Applying function names to Ghidra

Only a live project created and managed by Reverse Assistant can be modified. Snapshot-only imports
remain read-only. A rename is always explicitly entered and confirmed by the user; FunctionID, BSim
and future AI suggestions are never applied automatically.

The Rust backend validates the project path, active session, addresses and names, then serializes the
request through the same exclusive Ghidra queue used by on-demand decompilation. The Ghidra script:

1. opens one program transaction;
2. validates every function and rejects external functions;
3. applies every rename as `SourceType.USER_DEFINED`;
4. exports refreshed metadata while the transaction remains open;
5. commits only when the entire batch and both output files succeed.

Any failure rolls back the whole Ghidra transaction. After success, Rust reparses and validates the
fresh export, replaces the in-memory analysis and durable local snapshot, and clears stale
decompilation cache entries. The feature changes function names only; prototype/type editing remains
outside this first safe round-trip scope.
