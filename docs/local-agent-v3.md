# Local naming agent v3

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
   neighbourhoods.
5. Let the local model request a small number of read-only investigations.
6. Produce an observable role before proposing a symbol name.
7. Require observable evidence and an explicit uncertainty in the final answer.
8. Keep UI acceptance thresholds independent from model self-confidence.

## Budgets

- no more than two read-only tools and one follow-up for one function;
- three functions at most per local-model batch, ordered by semantic anchors;
- generation outcomes are versioned independently (v3), cached in the local
  project archive and invalidated when the agent protocol changes;
- failed or interrupted work remains resumable through the existing
  per-address project cache;
- functions without executable evidence are marked as such without repeated LLM
  calls.

## Benchmark gate

Every change to the reasoning pipeline must be evaluated on symbolized binaries
whose names are hidden from the agent. Measurements include semantic naming
accuracy, unsafe names, abstentions, elapsed time and generated-token count.
Coverage alone is not a success metric.

## Local protocol probe

The protocol was exercised against the installed `qwen2.5-coder:7b` Ollama
model. It proposed `open_file` from a `CreateFileA` call and requested
`two_hop_graph` rather than inventing a role for an opaque forwarding wrapper.
The response parser accepts both the requested `{ "results": [...] }` envelope
and the bare JSON array this model can emit in practice, while still validating
every address and identifier.
