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
