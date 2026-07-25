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
  accepted; duplicate external entry point addresses are not accepted; a duplicate
  `(category, name)` pair across `types` is not accepted.

## Root object

| Property | Type | Required | Description |
|---|---|---:|---|
| `schema_version` | integer | Yes | Version of this JSON contract. Must equal `2`. |
| `program` | object | Yes | Metadata identifying the analyzed program. |
| `functions` | array | Yes | Functions discovered by Ghidra. May be empty. |
| `strings` | array | Yes | Every string constant with at least one reference. May be empty. |
| `types` | array | Yes | Structures, unions, enums and typedefs relevant to the program (see below). May be empty. |

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
| `thunk_target_address` | string or null | Yes | Yes | When `is_thunk` is true: the immediate (one hop, not fully resolved) address this function redirects to, or `null` if Ghidra can't resolve it. Always `null` when `is_thunk` is false. |
| `namespace` | string or null | Yes for new exports | Yes | Fully qualified parent namespace (e.g. a C++ class, or a compilation unit's static-linkage namespace). `null` for the global namespace and for Ghidra's generic `<EXTERNAL>` placeholder. For a PE import this is generally the same real DLL name as `library`; for an ELF import it is `null`, same as `library`. Older v2 exports created before this field was introduced are accepted as if it were `null`, so saved local projects remain compatible. |
| `rtti_class_names` | array of strings | Yes for new exports | No | Real C++ class name(s) recovered from the binary's own MSVC RTTI metadata (vtable → `RTTICompleteObjectLocator` → `TypeDescriptor`), for functions a class's vtable references. Empty when the function has no vtable reference or the binary has no RTTI (non-MSVC, or RTTI disabled). More than one name means the compiler/linker folded multiple classes' byte-identical trivial destructors into this one function — a verified fact from the binary, never a guess. Older v2 exports created before this field was introduced are accepted as an empty array. |

A thunk's body is typically a jump instruction rather than a call, so its own `calls` array is
usually empty even though it genuinely redirects somewhere — `thunk_target_address` is the only
place that redirection is captured. It may itself point at another thunk (PE and ELF both
commonly chain two or more thunks, e.g. a PLT stub redirecting to a GOT-resolved stub that
redirects to the real external function); resolving the final non-thunk target means following
this field repeatedly, which this contract deliberately leaves to consumers rather than
collapsing in the export.

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

## Detected type object

A program's full `DataTypeManager` is mostly noise: compiler/runtime internals (RTTI helpers,
CRT scaffolding), and library headers pulled in by debug info but never actually touched by
this particular binary's own code. `types` is not a dump of that whole manager -- it starts
from every structure, union, enum or typedef directly used by a function's parameter/return
type or by a defined global data item (a "usage", see below), then recursively includes
whatever those types themselves reference: a struct's field types, a nested union, a typedef's
target. A type only reached this second way (e.g. a struct field's type) has an empty
`usages` -- that relationship is already visible through the referencing type's own
`fields`/`target_type_name`, so it is not fabricated as a usage in its own right.

Local variables inside a function body are not a source of usages here, by the same
reasoning `decompiled_code` is on-demand rather than bulk: discovering their types would
require decompiling every function during export, reintroducing the cost this contract
already avoids elsewhere.

| Property | Type | Required | Nullable | Description |
|---|---|---:|---:|---|
| `name` | string | Yes | No | Type name as known by Ghidra. May be a compiler-generated placeholder (see `is_anonymous`). |
| `kind` | string | Yes | No | `struct`, `union`, `enum`, or `typedef`. |
| `category` | string | Yes | No | Ghidra's category path for this type (e.g. `/sqlite3.pdb`), useful for telling program-local types apart from imported archive types. |
| `size` | integer or null | Yes | Yes | Size in bytes, or `null` when Ghidra has no concrete length for it, or when `is_opaque` is true. An opaque/not-yet-defined type gets a minimal placeholder length from Ghidra (commonly `1`) that is not a real measurement, so it is never presented as a reliable size. |
| `is_opaque` | boolean | Yes | No | Declared but with no known layout (a forward declaration Ghidra never resolved to a body). `fields`/`enum_values` are empty in this case, not fabricated. |
| `is_anonymous` | boolean | Yes | No | Ghidra assigned a placeholder name (observed as `<unnamed-tag_...>`/`<unnamed-enum-...>`) because no real symbol name was available -- common for compiler-generated anonymous structs/unions in real debug info. |
| `fields` | array | Yes | No | Populated for `struct`/`union` kinds; empty otherwise. See Type field object below. |
| `enum_values` | array | Yes | No | Populated for the `enum` kind; empty otherwise. See Enum value object below. |
| `target_type_name` | string or null | Yes | Yes | Populated for the `typedef` kind: the immediate aliased type's raw display name (not stripped of pointer/array layers). `null` otherwise. |
| `usages` | array | Yes | No | Every direct use of this type by a function signature or global data item. May be empty (see above). |

## Type field object

| Property | Type | Required | Nullable | Description |
|---|---|---:|---:|---|
| `name` | string or null | Yes | Yes | Field name, or `null` when Ghidra never assigned one (e.g. an anonymous nested union). |
| `data_type` | string | Yes | No | Raw Ghidra display name of the field's type (may include `*`/`[]`), same convention as a function parameter's `data_type` -- not pre-resolved against another `types` entry. |
| `offset` | integer | Yes | No | Byte offset of this field within the struct/union. |

## Enum value object

| Property | Type | Required | Description |
|---|---|---:|---|
| `name` | string | Yes | Member name. |
| `value` | integer | Yes | Member's numeric value (signed 64-bit). |

## Type usage object

| Property | Type | Required | Nullable | Description |
|---|---|---:|---:|---|
| `kind` | string | Yes | No | `function_parameter`, `function_return`, or `global_data`. |
| `function_address` | string or null | Yes | Yes | Populated for `function_parameter`/`function_return`; `null` for `global_data`. |
| `function_name` | string or null | Yes | Yes | Populated for `function_parameter`/`function_return`; `null` for `global_data`. |
| `parameter_name` | string or null | Yes | Yes | Populated for `function_parameter` only; `null` otherwise. |
| `data_address` | string or null | Yes | Yes | Populated for `global_data`; `null` for `function_parameter`/`function_return`. |
| `data_label` | string or null | Yes | Yes | Populated for `global_data` when Ghidra has a label for the address; `null` otherwise (including for the other two kinds). |

## Decompilation is on-demand

Unchanged from v1 — see [v1's note](ghidra-export-v1.md#decompilation-is-on-demand).

## Null and empty values

Unchanged from v1 — see [v1's note](ghidra-export-v1.md#null-and-empty-values), with `strings`
and `types` added as root-level arrays that follow the same "empty array, not a missing
property" rule.

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
