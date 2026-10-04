# Using Reverse Assistant

[Install first](INSTALLATION_WINDOWS.md) · [Get help](TROUBLESHOOTING.md)

The current interface is primarily French. This guide explains the workflow
in English and includes French control labels where they help you find a feature.

## 1. Open a binary

Open a file that you are authorized to inspect and start its analysis.
Use a small program for your first test. The application delegates analysis
to Ghidra; it does not execute the target binary.

Wait for analysis to finish. The number of functions and the complexity of
the program affect the time required. Reading an executable from another
operating system does not require running that executable.

## 2. Explore the results

| View | What to look for |
| --- | --- |
| Overview (`Aperçu`) | General information about the analyzed program. |
| Code Browser | Assembly and pseudocode for the selected local function. |
| Functions (`Fonctions`) | Function names and addresses. |
| Strings (`Chaînes`) | Text that can help explain behavior. |
| Structures | Detected type information. |
| Imports / Exports | External dependencies and exported symbols. |
| Graphs (`Graphes`) | Relationships between functions. |
| Identification | Naming proposals, evidence and review controls. |
| Reports (`Rapports`) | Local analysis reporting. |

An imported function is implemented outside the analyzed binary. It can have
a local relay entry, but that relay is not the library's complete implementation.
Missing pseudocode for an external entry is therefore normal.

## 3. Understand a naming proposal

Read the source of the proposal before deciding whether to trust it:

- **Symbols / RTTI:** information recovered from the binary itself.
- **FID:** a fingerprint match against an available reference database.
- **BSim:** similarity with known reference functions. Several candidates can
  match the same shape, especially for small helpers or compiler-generated code.
- **AI arbitration:** an attempt to choose between provided reference candidates.
- **AI-generated or semantic suggestion:** a proposed description based on
  code and context, not proof of the original symbol.

Compare the name with the pseudocode, strings, callers and callees. Treat the
confidence score as one signal, not the probability that a name is correct.
Multiple supporting observations can come from the same underlying evidence.

## 4. Choose manual or automatic review

### Manual review

Inspect one function at a time. Select a proposal or enter a name after checking
the evidence, then rename the function. Ignore a function for now if no name
is defensible. You do not have to name every function.

### Automatic batch

Enable automatic choice (`Choix automatique`). Select a prudence profile and
inspect the prepared batch before applying it.

| Profile | Minimum numeric threshold |
| --- | --- |
| Exploratory (`Exploratoire`) | 30% |
| Balanced (`Équilibré`) | 45% |
| Strict | 70% |
| Almost certain (`Quasi certain`) | 90% |

These are acceptance thresholds, **not accuracy guarantees**. Numerical
confidence is not the only condition: evidence, ambiguity, verification and
structural name protections can exclude a proposal even above the threshold.
Changing a profile does not improve the underlying analysis.

Manual mode can show more proposals than the automatic batch because it also
shows alternatives and hypotheses that did not pass automatic checks.

## 5. Review the remaining cases

Open **Review required** (`Révision nécessaire`). Cases can have several
plausible candidates, insufficient evidence, or no usable naming lead.

“Include anyway” (`Inclure quand même`) adds eligible but unvalidated proposals
to the prepared batch after a warning. It does not turn them into verified
results. The batch still needs to be applied. Structural exclusions and
unresolved choices remain excluded; this is not a way to force every function
to receive a name.

Inspect each uncertain function before overriding the normal checks. An
incorrect name can make subsequent code interpretation misleading.

## 6. Apply and save

Apply only the selected proposals you intend to keep. Renaming changes the
local Ghidra project's function labels, **not the executable's machine code**.
Check the updated names in other views, save the project and reopen it to
confirm that your work is preserved.

Reports and saved projects can contain pseudocode, strings and private target
information. Review them before sharing them.

## Optional AI

You can complete the steps above without configuring AI. To add it later,
follow [AI setup](AI_SETUP.md). AI analysis may continue in the background;
inspect its status and diagnostics rather than assuming every request succeeded.
