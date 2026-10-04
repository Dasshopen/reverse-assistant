# Runtime strings regression

After building and deploying `ReverseAssistantExporter`, run Ghidra headless on
an existing project with `-process <program> -readOnly -noanalysis`, add this
directory with `-scriptPath`, and run:

```text
-postScript VerifyRuntimeStrings.java 3
-postScript ExportReverseAssistantJson.java <new-export.json>
```

The optional number is the minimum count of referenced non-loaded strings the
fixture must contain (use `3` for `chall3`, or `0` for other programs).
The check compares the exported strings with referenced loaded-memory data,
ensures runtime strings and their references are retained, and checks uniqueness.
It does not execute the program or change the saved Ghidra project.

Validate the same export through the application's strict Rust importer:

```text
cargo run --bin ghidra-export-check -- <new-export.json>
```

Non-loaded ELF debug/comment strings must not be flattened into runtime virtual
addresses. Do not deduplicate by numeric offset or relax the Rust uniqueness check:
different address spaces can contain genuinely different data at the same offset.
