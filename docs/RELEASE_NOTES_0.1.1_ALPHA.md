# Reverse Assistant 0.1.1 Alpha

Windows x64 test build. Unsigned; clean Windows acceptance testing is still
in progress. This file does not establish whether a GitHub asset was uploaded.

## Fixed

- First-time Java installation no longer attempts to append `.sha256.txt` to
  an expiring GitHub CDN URL. The versioned archive URL and SHA-256 are resolved
  together from official Adoptium metadata before downloading.
- Missing or invalid checksums, unsupported packages and ambiguous metadata
  fail closed. Archive integrity verification remains mandatory.
- Download buffers are heap allocated, and downloaded files are closed before
  replacing cached archives on Windows.

## Retest on Windows

Install `Reverse Assistant_0.1.1_x64-setup.exe` and select automatic setup again.
The corrected downloader discards a previous incomplete archive when starting
a new download. No manual cache deletion or security-setting changes are needed.

Download the installer together with the matching `SHA256SUMS.txt` and
`THIRD_PARTY_NOTICES.txt`. Do not use the 0.1.0 installer to test this fix.
Internet access is required for Java and Ghidra downloads. AI remains optional.

Follow the [VM acceptance test](WINDOWS_VM_TEST.md). Full VM setup, upgrade and
project round-trip checks remain pending until actually performed.
