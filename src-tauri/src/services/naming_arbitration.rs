// The lightweight arbitration agent: given a *closed* set of already-known
// candidate names (FunctionID/BSim ties, e.g. the 39 tied C++ exception
// copy-constructor names, or the 5-way tied CRT helpers found on
// serpentine.exe) plus the function's real context, picks the most
// plausible one -- or says the tie is still unresolved. This is
// deliberately a selection task, not open-ended generation: the model is
// never allowed to invent a name outside the given candidate list, which
// keeps this agent cheap (small model, closed set) and safe (no
// fabricated evidence).

use std::collections::HashMap;

use serde::Deserialize;

use crate::models::ghidra_export::{GhidraExport, GhidraFunction};
use crate::services::ai_provider::{ChatCompletionRequest, ChatCompletionResponse, ChatMessage};
use crate::services::call_graph;

#[derive(Debug, Clone, PartialEq)]
pub struct ArbitrationCandidate {
    pub name: String,
    /// e.g. "FunctionID" or "BSim (sqlite3.dll)" -- shown to the model and
    /// kept for provenance, never used to bias the selection mechanically.
    pub source_label: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ArbitrationContext {
    pub current_name: String,
    pub decompiled_code: Option<String>,
    pub caller_names: Vec<String>,
    pub callee_names: Vec<String>,
    pub referenced_strings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArbitrationRequest {
    pub candidates: Vec<ArbitrationCandidate>,
    pub context: ArbitrationContext,
}

/// Assembles the real context already available for a function from the
/// loaded export -- no new Ghidra query needed: callers/callees/strings
/// are already part of every analysis, and decompiled code is whatever
/// has already been fetched on demand (absent is stated explicitly to the
/// agent rather than silently treated as "nothing to say").
pub fn build_context_for_function(
    export: &GhidraExport,
    entry_address: &str,
) -> Result<ArbitrationContext, String> {
    let function_index: HashMap<&str, &GhidraFunction> = export
        .functions
        .iter()
        .map(|function| (function.entry_address.as_str(), function))
        .collect();

    let function = function_index
        .get(entry_address)
        .ok_or_else(|| format!("no function exists at address '{entry_address}'"))?;

    let caller_index = call_graph::build_caller_index(export);
    let caller_names =
        call_graph::resolve_calling_functions(&caller_index, &function_index, entry_address)
            .into_iter()
            .filter_map(|address| function_index.get(address))
            .map(|caller| caller.name.clone())
            .collect();

    let callee_names = function
        .calls
        .iter()
        .map(|call| call.target_name.clone())
        .collect();

    Ok(ArbitrationContext {
        current_name: function.name.clone(),
        decompiled_code: function.decompiled_code.clone(),
        caller_names,
        callee_names,
        referenced_strings: function.strings.clone(),
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArbitrationResult {
    /// `None` means the agent itself could not break the tie -- this must
    /// be surfaced to the user as still ambiguous, never guessed.
    pub chosen_name: Option<String>,
    pub reasoning: String,
}

const SYSTEM_PROMPT: &str = "Tu es un agent d'arbitrage pour un outil de reverse engineering. \
On te donne une liste FERMEE de noms de fonction candidats, deja proposes par des outils \
d'analyse (FunctionID, BSim) qui n'ont pas pu departager lequel est le bon. Ta seule tache est \
de choisir, PARMI CETTE LISTE UNIQUEMENT, celui qui correspond le mieux au contexte reel fourni \
(pseudocode, appelants, fonctions appelees, chaines referencees). Tu ne dois JAMAIS proposer un \
nom qui n'est pas dans la liste fournie. Si le contexte ne permet pas de departager avec \
confiance, dis-le explicitement plutot que de choisir au hasard. Reponds UNIQUEMENT avec un \
objet JSON de la forme exacte : {\"chosen_name\": \"<un nom de la liste>\" ou null, \"reasoning\": \
\"<explication courte en francais, citant les elements de contexte utilises>\"}.";

fn format_context(context: &ArbitrationContext) -> String {
    let mut sections = vec![format!("Nom actuel (generique) : {}", context.current_name)];

    sections.push(match &context.decompiled_code {
        Some(code) => format!("Pseudocode decompile :\n{code}"),
        None => "Pseudocode decompile : indisponible pour cette fonction.".to_owned(),
    });

    sections.push(if context.caller_names.is_empty() {
        "Fonctions appelantes : aucune.".to_owned()
    } else {
        format!("Fonctions appelantes : {}", context.caller_names.join(", "))
    });

    sections.push(if context.callee_names.is_empty() {
        "Fonctions appelees : aucune.".to_owned()
    } else {
        format!("Fonctions appelees : {}", context.callee_names.join(", "))
    });

    sections.push(if context.referenced_strings.is_empty() {
        "Chaines referencees : aucune.".to_owned()
    } else {
        format!(
            "Chaines referencees : {}",
            context
                .referenced_strings
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    });

    sections.join("\n\n")
}

pub fn build_arbitration_request(
    request: &ArbitrationRequest,
    model: &str,
) -> ChatCompletionRequest {
    let candidate_list = request
        .candidates
        .iter()
        .map(|candidate| format!("- {} (source : {})", candidate.name, candidate.source_label))
        .collect::<Vec<_>>()
        .join("\n");

    let user_prompt = format!(
        "Liste fermee de candidats :\n{candidate_list}\n\nContexte de la fonction :\n{}",
        format_context(&request.context)
    );

    ChatCompletionRequest {
        model: model.to_owned(),
        messages: vec![
            ChatMessage {
                role: "system".to_owned(),
                content: SYSTEM_PROMPT.to_owned(),
            },
            ChatMessage {
                role: "user".to_owned(),
                content: user_prompt,
            },
        ],
        temperature: Some(0.0),
    }
}

#[derive(Deserialize)]
struct ArbitrationResponseJson {
    chosen_name: Option<String>,
    reasoning: String,
}

/// Parses the model's response and enforces the closed-set guarantee: a
/// `chosen_name` that is not one of the original candidates is treated as
/// an unresolved tie, never accepted as-is. This is what keeps the agent
/// safe even if the model does not follow instructions perfectly.
pub fn parse_arbitration_response(
    response: &ChatCompletionResponse,
    candidates: &[ArbitrationCandidate],
) -> Result<ArbitrationResult, String> {
    let parsed: ArbitrationResponseJson = serde_json::from_str(&response.content)
        .map_err(|error| format!("invalid arbitration response JSON: {error}"))?;

    let chosen_name = match parsed.chosen_name {
        Some(name) if candidates.iter().any(|candidate| candidate.name == name) => Some(name),
        Some(name) => {
            return Err(format!(
                "the model chose '{name}', which is not one of the provided candidates"
            ))
        }
        None => None,
    };

    Ok(ArbitrationResult {
        chosen_name,
        reasoning: parsed.reasoning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_export::{
        Endianness, FunctionCall, FunctionParameter, ProgramMetadata,
    };

    fn function(
        entry_address: &str,
        name: &str,
        calls: &[(&str, &str)],
        strings: &[&str],
        decompiled_code: Option<&str>,
    ) -> GhidraFunction {
        GhidraFunction {
            entry_address: entry_address.to_owned(),
            name: name.to_owned(),
            return_type: "void".to_owned(),
            parameters: Vec::<FunctionParameter>::new(),
            is_external: false,
            is_thunk: false,
            decompiled_code: decompiled_code.map(|code| code.to_owned()),
            calls: calls
                .iter()
                .map(|(target_address, target_name)| FunctionCall {
                    target_address: Some((*target_address).to_owned()),
                    target_name: (*target_name).to_owned(),
                })
                .collect(),
            strings: strings.iter().map(|value| (*value).to_owned()).collect(),
            library: None,
            thunk_target_address: None,
            namespace: None,
            rtti_class_names: Vec::new(),
        }
    }

    fn export(functions: Vec<GhidraFunction>) -> GhidraExport {
        GhidraExport {
            schema_version: 1,
            program: ProgramMetadata {
                name: "fixture.exe".to_owned(),
                sha256: "0".repeat(64),
                format: "PE".to_owned(),
                architecture: "x86_64".to_owned(),
                endianness: Endianness::Little,
                image_base: "0x140000000".to_owned(),
                external_entry_points: Vec::new(),
                required_libraries: Vec::new(),
            },
            functions,
            strings: Vec::new(),
            types: Vec::new(),
        }
    }

    #[test]
    fn context_includes_real_callers_callees_strings_and_decompiled_code() {
        let data = export(vec![
            function("0x1", "main", &[("0x2", "FUN_2")], &[], None),
            function(
                "0x2",
                "FUN_2",
                &[("0x3", "strlen")],
                &["out of range"],
                Some("void FUN_2(void) { throw std::out_of_range(\"out of range\"); }"),
            ),
        ]);

        let context = build_context_for_function(&data, "0x2")
            .expect("a function that exists should produce a context");

        assert_eq!(context.current_name, "FUN_2");
        assert_eq!(context.caller_names, vec!["main".to_owned()]);
        assert_eq!(context.callee_names, vec!["strlen".to_owned()]);
        assert_eq!(context.referenced_strings, vec!["out of range".to_owned()]);
        assert!(context.decompiled_code.unwrap().contains("out_of_range"));
    }

    #[test]
    fn a_function_never_decompiled_yet_has_no_code_but_still_has_other_context() {
        let data = export(vec![
            function("0x1", "main", &[("0x2", "FUN_2")], &[], None),
            function("0x2", "FUN_2", &[], &[], None),
        ]);

        let context = build_context_for_function(&data, "0x2")
            .expect("a function that exists should produce a context");

        assert_eq!(context.decompiled_code, None);
        assert_eq!(context.caller_names, vec!["main".to_owned()]);
    }

    #[test]
    fn an_unknown_address_is_rejected() {
        let data = export(vec![function("0x1", "main", &[], &[], None)]);

        let error = build_context_for_function(&data, "0xdeadbeef")
            .expect_err("an address with no function should be rejected");

        assert!(error.contains("0xdeadbeef"));
    }

    fn sample_candidates() -> Vec<ArbitrationCandidate> {
        vec![
            ArbitrationCandidate {
                name: "std::bad_alloc::bad_alloc".to_owned(),
                source_label: "FunctionID".to_owned(),
            },
            ArbitrationCandidate {
                name: "std::out_of_range::out_of_range".to_owned(),
                source_label: "FunctionID".to_owned(),
            },
        ]
    }

    #[test]
    fn the_candidate_list_and_context_appear_in_the_prompt() {
        let request = ArbitrationRequest {
            candidates: sample_candidates(),
            context: ArbitrationContext {
                current_name: "FUN_140001a28".to_owned(),
                decompiled_code: Some("void FUN_140001a28(char *msg) { ... }".to_owned()),
                caller_names: vec!["main".to_owned()],
                callee_names: vec![],
                referenced_strings: vec!["out of range".to_owned()],
            },
        };

        let chat_request = build_arbitration_request(&request, "llama3.1");

        assert_eq!(chat_request.model, "llama3.1");
        assert_eq!(chat_request.messages.len(), 2);
        let user_message = &chat_request.messages[1].content;
        assert!(user_message.contains("std::bad_alloc::bad_alloc"));
        assert!(user_message.contains("std::out_of_range::out_of_range"));
        assert!(user_message.contains("FUN_140001a28"));
        assert!(user_message.contains("main"));
        assert!(user_message.contains("out of range"));
    }

    #[test]
    fn a_missing_decompiled_code_is_stated_explicitly_rather_than_omitted() {
        let request = ArbitrationRequest {
            candidates: sample_candidates(),
            context: ArbitrationContext {
                current_name: "FUN_1".to_owned(),
                decompiled_code: None,
                caller_names: vec![],
                callee_names: vec![],
                referenced_strings: vec![],
            },
        };

        let chat_request = build_arbitration_request(&request, "llama3.1");

        assert!(chat_request.messages[1].content.contains("indisponible"));
    }

    #[test]
    fn a_valid_choice_within_the_candidate_list_is_accepted() {
        let candidates = sample_candidates();
        let response = ChatCompletionResponse {
            content: r#"{"chosen_name": "std::out_of_range::out_of_range", "reasoning": "La chaine \"out of range\" correspond directement."}"#.to_owned(),
        };

        let result = parse_arbitration_response(&response, &candidates)
            .expect("a valid closed-set choice should parse");

        assert_eq!(
            result.chosen_name,
            Some("std::out_of_range::out_of_range".to_owned())
        );
        assert!(result.reasoning.contains("out of range"));
    }

    #[test]
    fn an_explicit_null_choice_means_still_ambiguous() {
        let candidates = sample_candidates();
        let response = ChatCompletionResponse {
            content: r#"{"chosen_name": null, "reasoning": "Aucun element du contexte ne permet de trancher."}"#.to_owned(),
        };

        let result = parse_arbitration_response(&response, &candidates)
            .expect("an explicit null choice should parse");

        assert_eq!(result.chosen_name, None);
    }

    #[test]
    fn a_name_outside_the_candidate_list_is_rejected_not_trusted() {
        let candidates = sample_candidates();
        let response = ChatCompletionResponse {
            content: r#"{"chosen_name": "some_invented_name", "reasoning": "..."}"#.to_owned(),
        };

        let error = parse_arbitration_response(&response, &candidates)
            .expect_err("a name outside the closed set must never be accepted");

        assert!(error.contains("some_invented_name"));
        assert!(error.contains("not one of the provided candidates"));
    }

    #[test]
    fn malformed_response_json_is_rejected() {
        let candidates = sample_candidates();
        let response = ChatCompletionResponse {
            content: "not json".to_owned(),
        };

        let error = parse_arbitration_response(&response, &candidates)
            .expect_err("malformed JSON should be rejected");

        assert!(error.contains("invalid arbitration response JSON"));
    }
}
