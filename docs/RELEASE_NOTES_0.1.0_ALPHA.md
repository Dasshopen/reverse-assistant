# Reverse Assistant 0.1.0 — Windows alpha candidate

Prepared release notes. This document does not mean a GitHub Release exists.
Keep the Release as a draft until the acceptance checks and redistribution
review pass. Select **pre-release**, not a stable release.

## Included

- Windows x64 installer with the application, precompiled Ghidra extension and
  prebuilt BSim reference corpus.
- Guided first-time setup for Java and Ghidra; no development toolchain needed.
- Assembly, pseudocode and function exploration, reference-based naming,
  manual review and optional AI assistance.
- Local Ghidra-project renames and saved analysis projects.

## Before installing

- Windows 10 or 11 x64 and Internet access for first-time setup are required.
- The installer is **unsigned**. Verify its SHA-256 against `SHA256SUMS.txt`.
- Clean-Windows VM acceptance testing is **pending**.
- Third-party redistribution review is **pending**. Collected notices alone
  do not establish redistribution rights.
- AI is optional and configured separately. Remote AI providers receive the
  selected analysis context.
- The current interface is primarily French; user documentation is English.
- Reference coverage is limited and confidence scores are not guarantees.
- Analyze only software you are authorized to inspect. The app does not
  execute the target binary and is not a security sandbox.

## Files to attach

1. `Reverse Assistant_0.1.0_x64-setup.exe`
2. `SHA256SUMS.txt`
3. `THIRD_PARTY_NOTICES.txt`

Do not upload development caches, sample binaries, debug logs or the original
development corpus. The automatically generated source ZIP is not an installer.

Read the [Windows installation guide](INSTALLATION_WINDOWS.md),
[user guide](USER_GUIDE.md), and [VM test procedure](WINDOWS_VM_TEST.md).
