use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GhidraExport {
    pub schema_version: u32,
    pub program: ProgramMetadata,
    pub functions: Vec<GhidraFunction>,
}

impl GhidraExport {
    pub fn parse_and_validate(json: &str) -> Result<Self, String> {
        let export: Self = serde_json::from_str(json)
            .map_err(|error| format!("invalid Ghidra export JSON: {error}"))?;

        export.validate()?;

        Ok(export)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema version: {}; supported version: {}",
                self.schema_version, SUPPORTED_SCHEMA_VERSION
            ));
        }

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

        Ok(())
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

fn is_valid_address(value: &str) -> bool {
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
