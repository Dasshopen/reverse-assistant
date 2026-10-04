# Security and publication checklist

Reverse Assistant is an early-alpha analysis tool, not a hardened sandbox.

## Data boundaries

- Ghidra parses binaries locally without executing the target. Parsers can still
  contain vulnerabilities: isolate untrusted samples and keep tools updated.
- A remote AI provider receives selected analysis context, including pseudocode
  and strings. Do not send confidential code without authorization.
- AI keys are stored in local app-data JSON, not an encrypted credential vault.
  The provider-list UI does not return their values, but protect the files.
- Projects, reports and diagnostics can contain private data from the target.
- Suggested names remain hypotheses, even after automatic checks.

## Before publishing

1. Run `scripts/audit-publication.ps1 -IncludeHistory`.
2. Review `git status --short`, `git diff --cached --stat` and
   `git diff --cached`. Add explicit paths rather than blindly adding everything.
3. Keep personal settings, samples, credentials and generated databases out of
   Git. `.gitignore` does not untrack existing commits.
4. If a credential has entered Git, revoke/rotate it first. Removing the current
   file does not remove history. Agree on history rewrites before performing
   them; never force-push a shared repository unilaterally.
5. Verify licenses and provenance before distributing reference binaries or
   corpus assets. The application's MIT license does not cover third-party data.
6. Git commits include author identity. Choose what you intend to publish;
   changing future commits does not alter historical author metadata.

The included scanner is heuristic: it detects common token signatures and
private-key markers, not every secret, confidential detail or licensing issue.
It prints paths and line numbers, not the matched secret values.

## Reporting vulnerabilities

Do not put credentials, private binaries or exploitable details in public issues.
Use a private repository reporting channel if available, or contact the
maintainer privately. There is no dedicated security response SLA for this alpha.
