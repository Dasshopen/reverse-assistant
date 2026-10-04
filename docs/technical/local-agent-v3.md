# Local naming agent v3

Technical design note. For current user workflows, read the
[user guide](../USER_GUIDE.md). This note is not a release validation report.

The v3 agent keeps Ghidra, RTTI, FunctionID and BSim as authoritative evidence.
It changes only the reasoning layer used for functions that remain unnamed or
ambiguous.

## Design sources

The implementation is clean-room and combines publicly documented ideas:

- small, guided analysis tools and bounded context (ReVa);
- hierarchical semantic memory and call-graph propagation (GhidrAssist);
- persistent findings and staged orchestration (Rikugan);
- corpus-first similarity matching and explicit thresholds (RevEng.AI);
- typed, paginated and error-tolerant tool calls (IDA/Ghidra MCP projects).

No proprietary model, corpus or source code is copied into this repository.

The ReVa-inspired layer is implemented in-process as bounded, read-only Rust
queries (`function_overview`, cross-references, callers/callees, call graph,
strings, types and behaviour signals). Reverse Assistant does not embed ReVa's
HTTP/MCP server, arbitrary Python scripting, file-editing tools or network
surface. The upstream review is recorded in `docs/reva-security-review.md`.

## Pipeline

1. Build deterministic fact sheets for every function.
2. Rank anchors (entry points, meaningful names, strings, imports, RTTI).
3. Reuse accepted/generated names as provisional semantic anchors for later
   batches; final outcomes and their evidence remain persisted in the project.
4. Propagate those names and deterministic facts through bounded call-graph
   neighbourhoods. Contextual refinement is scheduled only for a direct
   neighbour of an anchor at 80% or more; without a new strong anchor, the
   first-pass result is retained instead of spending a redundant model call.
5. Let the local model request a small number of read-only investigations.
6. Produce an observable role before proposing a symbol name.
7. Require observable evidence and an explicit uncertainty in the final answer.
8. Calibrate with the deterministic Rust catalogue first. Run the contradictory
   verifier only for hypotheses that remain genuinely ambiguous (35-79%). It
   must bind each meaningful word in the proposed identifier to an observable
   citation.
9. Validate every verifier citation against the deterministic Rust fact sheet;
   missing or invented facts cannot raise confidence.
10. Derive a small, audited behavior vocabulary from exact APIs and literals
    (for example `GetEnvironmentStringsW` -> `environment_variables_get_set`)
    so local-model synonyms can be checked without trusting its prose.
11. Keep UI acceptance thresholds independent from model self-confidence.

Every verifier source now has a stable catalogue identifier (`import:0`,
`string:2`, `behavior:1`, etc.). The model cites that identifier and Rust
resolves it back to the original fact; a free-form or stale citation cannot
raise confidence. Imports, callees, callsites, constants and derived behavior
labels remain one machine-code evidence family, so two views of the same API
call are never counted as two independent confirmations.

The deterministic evidence index additionally records bounded constants,
global identifiers, outgoing calls with their arguments and arguments observed
in decompiled callers. The index is cached in memory and fingerprinted: it is
rebuilt after a new decompilation, prototype change, project switch or confirmed
rename, but reused across normal generation batches. These pseudocode-derived
observations improve hypotheses without being counted as several independent
proofs.

## Budgets

- no more than two read-only tools and one follow-up for one function;
- four compact, graph-independent functions at most in an initial-generation
  batch; complex functions remain isolated;
- three graph-independent functions at most in a contextual batch. A failed
  batch is retried per function so one malformed answer cannot discard its
  neighbours;
- every provider request has an explicit output budget. Truncation or a stopped
  Ollama runner is journalled, then retried once with a much smaller context;
- generation outcomes are versioned independently (protocol version 10), cached in the local
  project archive and invalidated when the agent protocol changes;
- failed or interrupted work remains resumable through the existing
  per-address project cache;
- a malformed single-function refinement receives one explicit correction
  request containing the rejected answer and validation reason; a second
  invalid answer fails closed and is never retried in a loop;
- functions without executable evidence are marked as such without repeated LLM
  calls.

## Benchmark gate

Every change to the reasoning pipeline must be evaluated on symbolized binaries
whose names are hidden from the agent. Measurements include semantic naming
accuracy, unsafe names, abstentions, elapsed time and generated-token count.
Coverage alone is not a success metric.
The reproducible evaluator and its JSON format are documented in
`docs/naming-benchmark.md`.

## Local protocol probe

The protocol was exercised against the installed `qwen2.5-coder:7b` Ollama
model. It proposed `open_file` from a `CreateFileA` call and requested
`two_hop_graph` rather than inventing a role for an opaque forwarding wrapper.
The response parser accepts both the requested `{ "results": [...] }` envelope
and the bare JSON array this model can emit in practice, while still validating
every address and identifier.
