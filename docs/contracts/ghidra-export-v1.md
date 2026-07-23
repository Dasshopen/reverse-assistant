# Ghidra Export Contract v1

Status: Superseded by [v2](ghidra-export-v2.md) — kept for Rust import compatibility only.
Schema version: `1`

## Purpose

This contract defines the JSON data exported by Ghidra and imported by Reverse Assistant.

The export represents one analyzed program and the functions discovered inside that program.

**The Ghidra exporter no longer produces v1** (it only ever writes v2 now). This document
stays as a reference for the still-supported *read* path: the Rust importer accepts v1 files
so an old manual JSON export doesn't stop working, but v1-sourced data has no string
cross-reference data (see v2's `strings` root array) since v1 never captured string
addresses at all.

## General rules

- The file must contain valid UTF-8 encoded JSON.
- The root value must be a JSON object.
- `schema_version` must be the integer `1`.
- Every address must be a hexadecimal string beginning with `0x`.
- SHA-256 values must contain exactly 64 lowercase hexadecimal characters.
- Required arrays must exist even when they are empty.
- Unknown properties are not accepted in version 1.
- JSON property order has no meaning.
- Functions should be sorted by ascending entry address.
- Duplicate function entry addresses are not accepted.

## Root object

| Property | Type | Required | Description |
|---|---|---:|---|
| `schema_version` | integer | Yes | Version of this JSON contract. Must equal `1`. |
| `program` | object | Yes | Metadata identifying the analyzed program. |
| `functions` | array | Yes | Functions discovered by Ghidra. May be empty. |

## Program object

| Property | Type | Required | Description |
|---|---|---:|---|
| `name` | string | Yes | Name of the analyzed binary. Must not be empty. |
| `sha256` | string | Yes | SHA-256 fingerprint of the exact binary. |
| `format` | string | Yes | Executable format, such as `PE` or `ELF`. |
| `architecture` | string | Yes | Processor architecture, such as `x86_64` or `ARM64`. |
| `endianness` | string | Yes | Byte order. Must be `little` or `big`. |
| `image_base` | string | Yes | Base address of the loaded program image. |
| `entry_points` | array of strings | Yes | Program entry-point addresses. May be empty. |

The local path of the binary must not be exported.

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
| `strings` | array of strings | Yes | No | Unique string values referenced by the function. May be empty. |

## Parameter object

| Property | Type | Required | Description |
|---|---|---:|---|
| `name` | string | Yes | Parameter name reported by Ghidra. |
| `data_type` | string | Yes | Parameter type reported by Ghidra. |

## Call object

| Property | Type | Required | Nullable | Description |
|---|---|---:|---:|---|
| `target_address` | string or null | Yes | Yes | Address of the called function, or `null` when unavailable. |
| `target_name` | string | Yes | No | Name of the called function known by Ghidra. |

Each target should appear only once in the `calls` array of a function.

## Decompilation is on-demand

Decompiling every function in a program during a bulk export was, by far, the dominant cost of headless analysis, even though most functions are never inspected by a user. Reverse Assistant therefore decompiles on demand: bulk program exports normally leave every non-external function's `decompiled_code` as `null`, and pseudocode is populated later, one function at a time, only when explicitly requested (outside the scope of this export contract). A `null` value never distinguishes "not yet decompiled" from "decompilation failed" — both cases are represented identically.

## Null and empty values

A required property must always be present.

Use an empty array when a collection contains no elements:

```json
{
  "parameters": [],
  "calls": [],
  "strings": []
}

Use null only when the contract explicitly permits it:

{
  "decompiled_code": null
}

A missing property and a property containing null do not mean the same thing.

Data intentionally excluded from version 1

The following data is not part of the first MVP contract:

complete raw assembly instructions;
control-flow graphs and basic blocks;
local variables;
complete cross-reference lists;
local filesystem paths;
AI prompts and AI responses;
function rename history;
interface state.

These elements may be introduced in a future contract version if the MVP proves that they are necessary.

Example

A complete valid example is available in:

ghidra-export-v1.example.json