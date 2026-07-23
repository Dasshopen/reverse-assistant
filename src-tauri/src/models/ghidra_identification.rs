use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionIdentification {
    pub entry_address: String,
    pub candidates: Vec<FidCandidate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FidCandidate {
    pub name: String,
    pub library_family: String,
    pub library_version: String,
    pub library_variant: String,
    pub overall_score: f64,
    pub match_mode: String,
}

pub fn parse_identifications(json: &str) -> Result<Vec<FunctionIdentification>, String> {
    serde_json::from_str(json)
        .map_err(|error| format!("invalid FunctionID identification JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_identification_array() {
        let json = r#"[
            {
                "entry_address": "0x140001000",
                "candidates": [
                    {
                        "name": "memcpy",
                        "library_family": "visual studio",
                        "library_version": "2019",
                        "library_variant": "x64",
                        "overall_score": 42.5,
                        "match_mode": "FULL"
                    }
                ]
            }
        ]"#;

        let identifications = parse_identifications(json).expect("valid JSON should parse");

        assert_eq!(identifications.len(), 1);
        assert_eq!(identifications[0].entry_address, "0x140001000");
        assert_eq!(identifications[0].candidates.len(), 1);
        assert_eq!(identifications[0].candidates[0].name, "memcpy");
        assert_eq!(identifications[0].candidates[0].overall_score, 42.5);
    }

    #[test]
    fn parses_an_empty_array() {
        let identifications = parse_identifications("[]").expect("an empty array should parse");

        assert!(identifications.is_empty());
    }

    #[test]
    fn rejects_invalid_json() {
        let error = parse_identifications("not json").expect_err("invalid JSON should be rejected");

        assert!(error.contains("invalid FunctionID identification JSON"));
    }
}
