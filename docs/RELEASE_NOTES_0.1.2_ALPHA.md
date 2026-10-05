# Reverse Assistant 0.1.2 Alpha

Unsigned Windows x64 test build. This document does not mean that an installer
has been published to GitHub Releases.

## Fixed

Background helpers use a shared Windows process launcher that requests no
console window. This covers Ghidra analysis, BSim, code browsing, decompilation,
disassembly, renaming, Java detection, development extension builds and the
optional local Ollama server. Output capture and failure reporting are retained.
No analysis features or naming safeguards have been removed.

The Java checksum-download fix from 0.1.1 is included.

## Validation status

The previous version's VM analysis was reported successful by the tester.
That does not validate all installation, rename, save/reopen, upgrade or
uninstall checks. The console-window change still needs an application-level
VM retest; automated process checks are not a substitute for this.

## Retest

Close Reverse Assistant before installing the 0.1.2 test build. Download its
matching `SHA256SUMS.txt` and `THIRD_PARTY_NOTICES.txt` alongside the installer.
Keep Windows security protections enabled.

Analyze the same small authorized binary, then open assembly and pseudocode,
rename one function and save/reopen the project. Check that no helper terminal
appears and that progress, errors and results remain visible in the app.

Follow the [full VM acceptance procedure](WINDOWS_VM_TEST.md) before calling
the release ready for general use. AI is optional.
