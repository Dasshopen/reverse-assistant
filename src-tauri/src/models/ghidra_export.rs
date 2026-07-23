use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// Schema 1 exports are still accepted on import (e.g. an old manual JSON
// export lying around) so existing analyses don't break, but the Ghidra
// exporter itself only ever produces schema 2 from now on: v1 never
// captured string addresses, so cross-references are simply unavailable
// for v1-sourced data rather than approximated.
pub const SUPPORTED_SCHEMA_VERSIONS: [u32; 2] = [1, 2];

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// The canonical, version-independent shape used by the rest of the app.
// `parse_and_validate` is the only place that needs to know two wire
// versions exist -- everything downstream (services, Tauri commands,
// Svelte) works against this shape regardless of which version a given
// export file was written in.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GhidraExport {
    pub schema_version: u32,
    pub program: ProgramMetadata,
    pub functions: Vec<GhidraFunction>,
    // Whole-program string cross-reference table. Always empty for
    // v1-sourced data (v1 never captured string addresses).
    pub strings: Vec<GlobalString>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GlobalString {
    pub address: String,
    pub value: String,
    pub references: Vec<StringReference>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StringReference {
    pub instruction_address: String,
    pub function_address: Option<String>,
}

impl GhidraExport {
    pub fn parse_and_validate(json: &str) -> Result<Self, String> {
        let probe: SchemaVersionProbe = serde_json::from_str(json)
            .map_err(|error| format!("invalid Ghidra export JSON: {error}"))?;

        let export = match probe.schema_version {
            1 => {
                let raw: RawExportV1 = serde_json::from_str(json)
                    .map_err(|error| format!("invalid Ghidra export JSON: {error}"))?;
                GhidraExport::from(raw)
            }
            2 => {
                let raw: RawExportV2 = serde_json::from_str(json)
                    .map_err(|error| format!("invalid Ghidra export JSON: {error}"))?;
                GhidraExport::from(raw)
            }
            other => {
                return Err(format!(
                    "unsupported schema version: {other}; supported versions: {}",
                    SUPPORTED_SCHEMA_VERSIONS
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        };

        export.validate()?;

        Ok(export)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.program.name.trim().is_empty() {
            return Err(String::from("program.name must not be empty"));
        }

        if !is_valid_sha256(&self.program.sha256) {
            return Err(String::from(
                "program sha256 must contain exactly 64 lowercase hexadecimal characters",
            ));
        }

        validate_address(&self.program.image_base, "program.image_base")?;

        for (index, entry_point) in self.program.entry_points.iter().enumerate() {
            let field_name = format!("program.entry_points[{index}]");
            validate_address(entry_point, &field_name)?;
        }

        let mut function_addresses = HashSet::new();
        for (function_index, function) in self.functions.iter().enumerate() {
            let function_field = format!("functions[{function_index}].entry_address");
            validate_address(&function.entry_address, &function_field)?;

            if !function_addresses.insert(function.entry_address.as_str()) {
                return Err(format!(
                    "duplicate function entry address: {}",
                    function.entry_address
                ));
            }

            for (call_index, call) in function.calls.iter().enumerate() {
                if let Some(target_address) = &call.target_address {
                    let call_field =
                        format!("functions[{function_index}].calls[{call_index}].target_address");

                    validate_address(target_address, &call_field)?;
                }
            }
        }

        let mut string_addresses = HashSet::new();
        for (string_index, string) in self.strings.iter().enumerate() {
            let address_field = format!("strings[{string_index}].address");
            validate_address(&string.address, &address_field)?;

            if !string_addresses.insert(string.address.as_str()) {
                return Err(format!("duplicate string address: {}", string.address));
            }

            for (reference_index, reference) in string.references.iter().enumerate() {
                let instruction_field = format!(
                    "strings[{string_index}].references[{reference_index}].instruction_address"
                );
                validate_address(&reference.instruction_address, &instruction_field)?;

                if let Some(function_address) = &reference.function_address {
                    let function_field = format!(
                        "strings[{string_index}].references[{reference_index}].function_address"
                    );
                    validate_address(function_address, &function_field)?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Deserialize)]
struct SchemaVersionProbe {
    schema_version: u32,
}

// Schema v1 wire format. `GhidraFunction` already matches v1's exact
// per-function shape (including its literal `strings: Vec<String>`), so no
// separate raw function type is needed for this version.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawExportV1 {
    schema_version: u32,
    program: ProgramMetadata,
    functions: Vec<GhidraFunction>,
}

impl From<RawExportV1> for GhidraExport {
    fn from(raw: RawExportV1) -> Self {
        GhidraExport {
            schema_version: raw.schema_version,
            program: raw.program,
            functions: raw.functions,
            strings: Vec::new(),
        }
    }
}

// Schema v2 wire format: functions no longer carry their own `strings`
// array (redundant with the global table below); a whole-program `strings`
// table normalizes address, value, and every real reference to it.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawExportV2 {
    schema_version: u32,
    program: ProgramMetadata,
    functions: Vec<RawFunctionV2>,
    strings: Vec<RawGlobalString>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawFunctionV2 {
    entry_address: String,
    name: String,
    return_type: String,
    parameters: Vec<FunctionParameter>,
    is_external: bool,
    is_thunk: bool,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    decompiled_code: Option<String>,
    calls: Vec<FunctionCall>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawGlobalString {
    address: String,
    value: String,
    references: Vec<RawStringReference>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawStringReference {
    instruction_address: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    function_address: Option<String>,
}

impl From<RawExportV2> for GhidraExport {
    fn from(raw: RawExportV2) -> Self {
        // Built once from the global table, reused for every function: which
        // string values does a given function reference (deduplicated),
        // keeping the existing per-function "Referenced strings" display
        // working the same way it did for v1, without the wire format
        // itself ever duplicating this data.
        let mut strings_by_function: HashMap<String, Vec<String>> = HashMap::new();

        for global_string in &raw.strings {
            for reference in &global_string.references {
                if let Some(function_address) = &reference.function_address {
                    strings_by_function
                        .entry(function_address.clone())
                        .or_default()
                        .push(global_string.value.clone());
                }
            }
        }

        for values in strings_by_function.values_mut() {
            values.sort();
            values.dedup();
        }

        let functions = raw
            .functions
            .into_iter()
            .map(|raw_function| {
                let strings = strings_by_function
                    .remove(&raw_function.entry_address)
                    .unwrap_or_default();

                GhidraFunction {
                    entry_address: raw_function.entry_address,
                    name: raw_function.name,
                    return_type: raw_function.return_type,
                    parameters: raw_function.parameters,
                    is_external: raw_function.is_external,
                    is_thunk: raw_function.is_thunk,
                    decompiled_code: raw_function.decompiled_code,
                    calls: raw_function.calls,
                    strings,
                }
            })
            .collect();

        let strings = raw
            .strings
            .into_iter()
            .map(|raw_global_string| GlobalString {
                address: raw_global_string.address,
                value: raw_global_string.value,
                references: raw_global_string
                    .references
                    .into_iter()
                    .map(|raw_reference| StringReference {
                        instruction_address: raw_reference.instruction_address,
                        function_address: raw_reference.function_address,
                    })
                    .collect(),
            })
            .collect();

        GhidraExport {
            schema_version: raw.schema_version,
            program: raw.program,
            functions,
            strings,
        }
    }
}

fn is_valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

fn validate_address(value: &str, field_name: &str) -> Result<(), String> {
    if !is_valid_address(value) {
        return Err(format!(
            "{field_name} must be a lowercase hexadecimal string beginning with 0x"
        ));
    }

    Ok(())
}

pub(crate) fn is_valid_address(value: &str) -> bool {
    let Some(hexadecimal_part) = value.strip_prefix("0x") else {
        return false;
    };

    !hexadecimal_part.is_empty()
        && hexadecimal_part
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProgramMetadata {
    pub name: String,
    pub sha256: String,
    pub format: String,
    pub architecture: String,
    pub endianness: Endianness,
    pub image_base: String,
    pub entry_points: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GhidraFunction {
    pub entry_address: String,
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<FunctionParameter>,
    pub is_external: bool,
    pub is_thunk: bool,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub decompiled_code: Option<String>,
    pub calls: Vec<FunctionCall>,
    pub strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FunctionParameter {
    pub name: String,
    pub data_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FunctionCall {
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub target_address: Option<String>,
    pub target_name: String,
}
