# Ghidra Export Contract v2

Status: Draft
Schema version: `2`

## Purpose

This contract defines the JSON data exported by Ghidra and imported by Reverse Assistant.

The export represents one analyzed program, the functions discovered inside it, and every
string constant that is actually referenced somewhere in the program.

This supersedes [v1](ghidra-export-v1.md), whose own docs flagged "complete cross-reference
lists" as intentionally excluded and deferred to a future version. Reverse Assistant's Ghidra
exporter only ever produces v2 from now on; the Rust importer still accepts v1 files (so an
old manual JSON export doesn't stop working), but v1-sourced data has no string
cross-reference data at all, since v1 never captured string addresses.

## General rules

- The file must contain valid UTF-8 encoded JSON.
- The root value must be a JSON object.
- `schema_version` must be the integer `2`.
- Every address must be a hexadecimal string beginning with `0x`.
- SHA-256 values must contain exactly 64 lowercase hexadecimal characters.
- Required arrays must exist even when they are empty.
- Unknown properties are not accepted in version 2.
- JSON property order has no meaning.
- Functions are sorted by ascending entry address; strings and external entry points are
  sorted by ascending address.
- Duplicate function entry addresses are not accepted; duplicate string addresses are not
  accepted; duplicate external entry point addresses are not accepted.

## Root object

| Property | Type | Required | Description |
|---|---|---:|---|
| `schema_version` | integer | Yes | Version of this JSON contract. Must equal `2`. |
| `program` | object | Yes | Metadata identifying the analyzed program. |
| `functions` | array | Yes | Functions discovered by Ghidra. May be empty. |
| `strings` | array | Yes | Every string constant with at least one reference. May be empty. |

## Program object

| Property | Type | Required | Description |
|---|---|---:|---|
| `name` | string | Yes | Name of the analyzed binary. Must not be empty. |
| `sha256` | string | Yes | SHA-256 fingerprint of the exact binary. |
| `format` | string | Yes | Executable format, such as `PE` or `ELF`. |
| `architecture` | string | Yes | Processor architecture, such as `x86_64` or `ARM64`. |
| `endianness` | string | Yes | Byte order. Must be `little` or `big`. |
| `image_base` | string | Yes | Base address of the loaded program image. |
| `external_entry_points` | array | Yes | Every address Ghidra considers reachable from outside the analyzed code. May be empty. |
| `required_libraries` | array of strings | Yes | Libraries this program depends on, by name (e.g. `KERNEL32.DLL`, `libc.so.6`). May be empty. Descriptive only — never used to attribute a specific import to a specific library (see `library` below). |

Unlike v1's `entry_points` (a bare address list), `external_entry_points` is not renamed for
cosmetic reasons: Ghidra genuinely does not distinguish "where this program's execution
starts" from "what this program exposes to external callers" — both live in the same
underlying concept. On a real shared library/DLL this is a clean, meaningful export table
(e.g. `sqlite3_open`, `sqlite3_close`, ...). On a plain executable it is **much broader and
noisier** — closer to "every globally-visible symbol" (the true entry point, `main`, compiler
scaffolding like `__libc_csu_init`, and even data addresses with no associated function) than
a curated list of exports. This isn't a bug to filter away in the backend; it's an accurate
reflection of what the binary actually exposes.

## External entry point object

| Property | Type | Required | Nullable | Description |
|---|---|---:|---:|---|
| `address` | string | Yes | No | The address itself. |
| `name` | string or null | Yes | Yes | Resolved name (function name, or a data symbol's name), or `null` when nothing names this address. |
| `kind` | string | Yes | No | `function`, `data`, or `unknown`. |

## Function object

| Property | Type | Required | Nullable | Description |
|---|---|---:|---:|---|
| `entry_address` | string | Yes | No | Address of the function's first instruction. |
| `name` | string | Yes | No | Function name known by Ghidra. |
| `return_type` | string | Yes | No | Return type reported by Ghidra. |
| `parameters` | array | Yes | No | Function parameters. May be empty. |
| `is_external` | boolean | Yes | No | Whether the function comes from outside the analyzed binary. |
| `is_thunk` | boolean | Yes | No | Whether the function mainly redirects to another function. |
| `decompiled_code` | string or null | Yes | Yes | Pseudocode produced by Ghidra for this function, or `null` when no pseudocode is available yet. |
| `calls` | array | Yes | No | Functions called by this function. May be empty. |
| `library` | string or null | Yes | Yes | For an external (imported) function: the real source library name when Ghidra can attribute it (reliable for PE), or `null` when it can't (always `null` for ELF imports — never guessed). Always `null` for non-external functions. |

Unlike v1, a function object has **no `strings` field**. Which strings a function
references is derivable from the root `strings` table's `references` (see below) — the
contract does not duplicate that data on both sides.

## Parameter object and Call object

Unchanged from v1 — see [v1's Parameter object](ghidra-export-v1.md#parameter-object) and
[Call object](ghidra-export-v1.md#call-object).

## Global string object

| Property | Type | Required | Description |
|---|---|---:|---|
| `address` | string | Yes | Address of the string data itself. |
| `value` | string | Yes | The string's content. |
| `references` | array | Yes | Every real reference to this string. May be empty only in theory — a string with zero references is not exported at all (see below). |

Two identical string values at different addresses are two distinct entries, each keyed by
its own address — never deduplicated by content.

Only strings with at least one reference are included: this is a table of strings *used*
somewhere in the program, not every string constant Ghidra can see.

## String reference object

| Property | Type | Required | Nullable | Description |
|---|---|---:|---:|---|
| `instruction_address` | string | Yes | No | Address of the instruction that references the string. |
| `function_address` | string or null | Yes | Yes | Address of the function containing that instruction, or `null` when the reference isn't inside any function. |

A reference outside any function is kept, not dropped — a global string's true reference
count (see below) must equal the number of entries in `references`, however they resolve.

There is no separate `reference_count` field: the count is simply `references.length`. A
single function can appear multiple times in a string's `references` if it references that
string from more than one instruction (e.g. the same check duplicated across a few
branches) — this is expected, and is exactly why the count isn't the same thing as the
number of distinct referencing functions.

## Decompilation is on-demand

Unchanged from v1 — see [v1's note](ghidra-export-v1.md#decompilation-is-on-demand).

## Null and empty values

Unchanged from v1 — see [v1's note](ghidra-export-v1.md#null-and-empty-values), with `strings`
added as a root-level array that follows the same "empty array, not a missing property" rule.

## Data intentionally excluded from version 2

The following data is still not part of the contract:

- complete raw assembly instructions;
- control-flow graphs and basic blocks (the call graph is derived separately, in Rust, from
  `calls` — not part of this contract);
- local variables;
- local filesystem paths;
- AI prompts and AI responses;
- function rename history;
- interface state.

## Example

A complete valid example is available in `ghidra-export-v2.example.json`.
