# Help and troubleshooting

## I downloaded a ZIP, but cannot find the application

GitHub's “Source code” ZIP contains a development project. It is not an installer.
Download the Windows `-setup.exe` from [Releases](https://github.com/Dasshopen/reverse-assistant/releases)
when one is published. Check the [README](../README.md#get-started) for availability.
Developers can follow [Build from source](BUILD_FROM_SOURCE.md).

## First-time setup cannot finish

Read the error in the setup assistant. Check your Internet connection and
available disk space, then retry. Do not manually delete the managed tool
directory or disable security software to make an error disappear.
If you already have Ghidra, select its extracted installation directory,
not a ZIP or its `support` subdirectory.

## Windows warns about the installer

The current test installer is unsigned. Verify its origin and compare its
SHA-256 checksum with the release's `SHA256SUMS.txt` before deciding to run it.
For a published download, this optional PowerShell command displays the hash:

```powershell
Get-FileHash -LiteralPath 'C:\Downloads\Reverse Assistant_0.1.0_x64-setup.exe' -Algorithm SHA256
```

Use the actual path and filename of your downloaded installer. Do not proceed
if the checksum does not match. A matching checksum alone is not a security
certification; trust the publication source as well.

## Analysis or code loading is slow

Initial analysis starts Ghidra and examines the program. The first assembly
or pseudocode load can also start Ghidra; repeated cached loads are faster.
Large functions, large binaries and background AI work add time.
Check the progress and error messages. If the UI stops responding rather than
merely showing progress, report the sequence of actions and how long it lasted.

## A function has no assembly or pseudocode

An external import does not contain the library implementation. Select its
local relay where available. For a local function, inspect any reported
decompilation error; missing output is not automatically evidence of a corrupt file.

## FID or BSim found no matches

Check that the reference corpus is available in settings. A working corpus
still cannot cover every library, architecture, compiler or optimization profile.
No match is not the same as “analysis did not run.” Inspect the code and other
available evidence instead of assuming the nearest name must be correct.

## Manual mode shows more names than automatic mode

Manual review includes alternatives and weak hypotheses. The automatic batch
contains only proposals passing the active profile and additional safety checks.
See [Review modes](USER_GUIDE.md#4-choose-manual-or-automatic-review).

## AI times out, fails, or proposes very few names

Confirm that the provider is active, its address and model are correct, and
the local model is installed. For Ollama, check `ollama list` and the server
response described in [AI setup](AI_SETUP.md). Inspect the journal: historical
failures can remain recorded even after later retries succeed.

Some functions do not have enough evidence for a defensible name. Do not
disable checks solely to increase the number of automatic proposals.

## BSim reports a locked database

Close another analysis or Ghidra instance using that database and retry.
Do not delete the database while it is in use.

## Report a problem safely

Use the repository's Issues page if enabled, or the private channel provided
by the maintainer. Include:

- Application and Windows versions.
- The view and actions that triggered the problem.
- The complete error message and relevant analysis status.
- A redacted screenshot when useful.

Do not attach API keys, personal settings, confidential binaries or unredacted
project data. Report sensitive security details privately; read [SECURITY.md](../SECURITY.md).
