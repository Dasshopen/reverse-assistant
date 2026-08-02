# Naming benchmark

The naming benchmark deliberately separates coverage from correctness. A new
pipeline is not considered better merely because it proposes more names.

Each JSON case contains the original symbol (plus optional, explicitly
approved aliases), the agent suggestion, whether the UI would have applied it
automatically, elapsed time and model-call count. The evaluator reports:

- proposal coverage;
- proposal precision;
- automatic-rename precision;
- unsafe automatic names;
- exact-symbol recovery and optional human-reviewed semantic usefulness as
  two separate measurements;
- abstentions;
- elapsed time and model calls.

Run it locally with:

```text
cargo run --manifest-path src-tauri/Cargo.toml --bin naming-benchmark -- suite.json
```

Minimal suite shape:

```json
{
  "name": "my-symbolized-corpus",
  "cases": [{
    "entry_address": "0x401000",
    "expected_names": ["validate_credentials", "authenticate"],
    "suggested_name": "authenticate",
    "confidence": 80,
    "automatically_applied": true,
    "elapsed_ms": 1250,
    "model_calls": 1,
    "semantic_review": "useful"
  }]
}
```

Names are compared after case and separator normalization only. Semantic
equivalence is never guessed by the evaluator: an acceptable alternative must
be written explicitly in `expected_names`. This keeps the quality gate strict
and reproducible.

## First real run: fauxware, names hidden

`tests/fixtures/real-fauxware-hidden-names-export-v2.json` is the real
`01-fauxware.elf` export (`tests/fixtures/real-fauxware-export-v2.json`) with
real Ghidra decompilations attached for `authenticate`, `accepted`, `rejected`
and `main` (captured with a fresh, current headless decompile -- the
committed fixture never had `decompiled_code` populated), then the three
target functions renamed to their real `FUN_<address>` placeholder in every
place their real name could otherwise leak: the function's own `name`, every
caller's `calls[].target_name`, the exported-entry-point list, **and** every
occurrence of the identifier inside any function's `decompiled_code` text
(Ghidra prints a callee by name in its caller's pseudocode, so masking only
the metadata field would hand the answer to the agent through `main`'s own
listing). A generation script asserts no real name survives in the
serialized fixture before writing it.

`cargo run --manifest-path src-tauri/Cargo.toml --bin fauxware-benchmark`
replays the exact pipeline `generate_identification_suggestion` uses --
single pass, at most one read-only tool follow-up, then
one contradictory name-verification pass and deterministic Rust validation
-- against a local Ollama endpoint (qwen2.5-coder:7b) and reports the resulting
suite.

First real result (qwen2.5-coder:7b, 2026-07-27):

| address | expected | suggested | confidence | auto-applied? | correct? |
|---|---|---|---|---|---|
| 0x400664 | `authenticate` | `check_sneaky_or_file_content` | 95% | yes | no |
| 0x4006ed | `accepted` | `display_admin_welcome_message` | 95% | yes | no |
| 0x4006fd | `rejected` | `terminate_and_notify` | 95% | yes | no |

Coverage 100%, exact-match precision 0%, automatic precision 0% (3/3 unsafe
automatic names under the default "Equilibre" 45% threshold).

Two distinct things are visible in this one run and should not be conflated:

1. Every suggestion is a semantically reasonable paraphrase of the real
   behavior -- not a hallucination. The 0% precision figure is partly an
   artifact of exact-identifier matching (by design: the evaluator never
   guesses synonyms, see above).
2. More seriously, `calibrate_confidence` returned 95% for all three by
   counting generic context richness (resolved imports, referenced strings,
   a named neighbor, being an entry point) as "independent confirmed
   evidence" -- none of which actually verifies the *specific* suggested
   name over an equally plausible alternative. All three would have been
   silently auto-applied, wrong, under the app's own default prudence
   profile. This is the concrete failure mode the confidence-calibration
   rule ("AI confidence is a signal, not ground truth") exists to prevent,
   and this first run shows it is not yet doing so for pure open generation
   (as opposed to arbitration's closed-set case, which this run does not
   exercise).

## Contradictory-verifier result

The open-generation pipeline now keeps the proposed name, but no longer lets
generic context richness certify its wording. A second, adversarial model pass
must map each meaningful name token to a concrete citation. Rust then checks
that every cited string, import, caller/callee, pseudocode fragment, constant,
global or callsite value actually exists in the deterministic context. A
fabricated citation is discarded. If the verifier fails or does not justify
the full name, the suggestion remains visible for manual review but cannot
reach the default 65% automatic threshold.

Real rerun on 2026-07-28 (local qwen2.5-coder:7b; model wording can vary):

| address | expected | suggested | calibrated confidence | auto-applied? |
|---|---|---|---|---|
| 0x400664 | `authenticate` | `check_sneaky_or_file_content` | 55% | no |
| 0x4006ed | `accepted` | `display_admin_welcome_message` | 60% | no |
| 0x4006fd | `rejected` | `terminate_and_notify` | 30% | no |

Coverage stayed at 100%, while unsafe automatic renames fell from 3/3 to 0/3.
The run also exposed why deterministic validation is necessary: the local
verifier sometimes put a complete identifier in a single `name_token`, cited
an invented sentence, used the wrong evidence kind, or contradicted an actual
`exit` import. None of those model mistakes raised confidence. Exact-symbol
precision remains 0% for these paraphrases; semantic usefulness is recorded
only when a human explicitly sets `semantic_review`, never guessed by the
evaluator.

## Evidence-catalog result

Protocol v8 gives every deterministic fact a stable identifier and adds a
small Rust-derived behavior vocabulary for exact API patterns. The generator
is asked to reuse that vocabulary; the contradictory verifier cites catalogue
IDs instead of reconstructing facts as prose. A deterministic fallback applies
the same token checks when the small local model returns malformed verifier
JSON.

Real fauxware rerun on 2026-07-28 (one complete run; local model output remains
non-deterministic even at temperature zero):

| address | approved semantic names include | suggested | confidence | auto-applied? |
|---|---|---|---|---|
| 0x400664 | `authenticate`, `verify_password` | `verify_password` | 45% | no |
| 0x4006ed | `accepted`, `display_admin_welcome_message` | `display_admin_welcome_message` | 85% | yes |
| 0x4006fd | `rejected`, `terminate_and_notify` | `terminate_and_notify` | 50% | no |

The evaluator therefore measured 3/3 human-approved semantic proposals, one
automatic rename and zero unsafe automatic renames. The password hypothesis
correctly remains manual: `SOSNEAKY` and `strcmp` make it plausible, but do not
prove that the compared secret is literally a password.

The offline `naming-evidence-audit` replay against the saved `serpentine.exe`
analysis provides a second measurement without rerunning 278 model calls. The
strict deterministic fallback initially verified 16 stored names at the 65%
threshold. Stable catalogue IDs, audited API semantics and derived behavior
labels raise that evidence-backed ceiling to 40 while keeping generic wrappers
such as `FunctionLoader` and `CleanupFunction` below the automatic threshold.
