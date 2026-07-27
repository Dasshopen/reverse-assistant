# ReVa security review

Review date: 2026-07-27

Upstream reviewed: `cyberkaida/reverse-engineering-assistant`, commit
`1e9671384992b3439f5562e3c023d6e279924699`. The source was cloned without
submodules and inspected without building or running it.

## Result

No hidden malware, telemetry, credential collection or production subprocess
execution was found. A Microsoft Defender custom scan of the checked-out source
reported zero detections. This is positive evidence, not a mathematical proof
that any future release or dependency is safe.

## Intended high-risk capabilities

ReVa is an MCP server embedded in Ghidra. Its scripting tool can intentionally
execute arbitrary PyGhidra Python and manage script files. Tool groups,
including scripting, are enabled by default. The server defaults to localhost;
non-local unauthenticated use is guarded and upstream documentation warns about
the arbitrary-code risk. Request/response body logging can also be enabled.

The reviewed code includes path-containment and symlink checks for script file
operations and redacts authorization headers in logs. The server has an idle
timeout, but no obvious global request-size limit was found. API-key comparison
uses ordinary string equality.

## Supply-chain notes

The Python lock file pins package hashes and release automation signs artifacts
with Sigstore. The Gradle build uses fixed versions but has no dependency
verification metadata and includes milestone/snapshot repositories. For that
reason Reverse Assistant does not consume a prebuilt ReVa extension or add its
dependency graph.

## Integration decision

Reverse Assistant adopts only the useful read-only investigation pattern:

- function overview;
- callers, callees and bounded call graph;
- cross-references;
- strings and detected types;
- deterministic behavioural signals extracted from pseudocode.

These tools run inside the existing Rust/Ghidra boundary. There is no new MCP
listener, arbitrary script execution, dynamic plugin loading, telemetry or
network access. The only mutation remains the existing explicit function rename
confirmed by the user. The implementation is clean-room; no ReVa source code is
copied. ReVa is Apache-2.0 licensed.
