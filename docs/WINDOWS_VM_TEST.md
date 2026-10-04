# First Windows VM test

This is an acceptance test for the packaged application, not a source build.
Record actual results. A successful developer-machine build does not mean this
test has passed.

## Prepare a clean environment

1. Create a Windows 10 or 11 x64 VM with Internet access.
2. Use a standard Windows user account. Do not install Java, Ghidra, Node.js,
   Rust, Visual Studio, Gradle or Ollama in advance.
3. Take a snapshot before installing Reverse Assistant.
4. Transfer these three files from the same build: the `-setup.exe`,
   `SHA256SUMS.txt`, and `THIRD_PARTY_NOTICES.txt`.
5. In PowerShell, run `Get-FileHash -LiteralPath '.\Reverse Assistant_0.1.0_x64-setup.exe' -Algorithm SHA256`
   from the download folder. Compare the hash with `SHA256SUMS.txt`.
   Do not run the installer if they differ.

The current candidate is unsigned. Do not disable antivirus or other Windows
security protections. Record any warning or blocked installation.

## Run the acceptance checks

Use a small executable you own or are authorized to analyze. Do not execute the
target binary; import it into Reverse Assistant only. Start without AI.

| Check | Expected result | Actual result |
| --- | --- | --- |
| Install as a standard user | Installer completes; Start menu shortcut works. | Not tested |
| WebView2 | App opens, including when the runtime needs installation. | Not tested |
| First launch | Setup assistant clearly explains missing tools and licenses. | Not tested |
| Automatic setup | Java and Ghidra install after consent; no developer tools or compilation required. | Not tested |
| Restart after setup | Tools remain detected and the corpus loads without errors. | Not tested |
| Import a small binary | Analysis completes and the function list appears. | Not tested |
| Inspect local code | Assembly and pseudocode appear; switching functions remains responsive. | Not tested |
| Inspect an import | Missing external implementation is explained without a stuck loading indicator. | Not tested |
| Reference matching | Available matches have source/evidence; missing matches are not treated as failures. | Not tested |
| Review controls | Review tabs, prudence levels and selection controls respond consistently. | Not tested |
| Rename one function | Name updates across views; the apply action finishes. | Not tested |
| Save, close, reopen | Rename and project data persist. | Not tested |
| Optional AI disabled | Core analysis and renaming remain usable. | Not tested |
| Uninstall | App uninstalls; saved user projects are not deleted. | Not tested |

Restore the clean snapshot for a separate interrupted-download test: interrupt
first-time tool setup, restore connectivity, retry and restart the application.
Verify setup recovers without manual cache edits. Test upgrade separately once
a second installer is available. Test AI only after the non-AI cycle passes.

## Record and report

Record Windows version, installer SHA-256, date, elapsed setup/analysis times,
and the result of each check. For failures, capture the visible error and exact
steps. Redact usernames, private paths, target code and credentials before
sharing logs or screenshots.

When a GitHub prerelease is available, repeat the checksum check using files
downloaded from its Assets section. A local transfer does not validate the
GitHub download flow.

Do not mark the installer ready for general use until blocking failures are
fixed and [release gates](RELEASE_CHECKLIST.md) are satisfied.
