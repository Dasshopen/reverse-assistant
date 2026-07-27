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
    "model_calls": 1
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
`calibrate_confidence` -- against a local Ollama endpoint (qwen2.5-coder:7b)
and reports the resulting suite.

First real result (qwen2.5-coder:7b, 2026-07-27):

| address | expected | suggested | confidence | auto-applied? | correct? |
|---|---|---|---|---|---|
| 0x400664 | `authenticate` | `check_sneaky_or_file_content` | 95% | yes | no |
| 0x4006ed | `accepted` | `display_admin_welcome_message` | 95% | yes | no |
| 0x4006fd | `rejected` | `terminate_and_notify` | 95% | yes | no |

Coverage 100%, exact-match precision 0%, automatic precision 0% (3/3 unsafe
automatic names under the default "Equilibre" 65% threshold).

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
   exercise). Not fixed here -- flagged for a deliberate decision before any
   further generation-agent work.
