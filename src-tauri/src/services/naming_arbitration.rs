// The lightweight arbitration agent: given a *closed* set of already-known
// candidate names (FunctionID/BSim ties, e.g. the 39 tied C++ exception
// copy-constructor names, or the 5-way tied CRT helpers found on
// serpentine.exe) plus the function's real context, picks the most
// plausible one -- or says the tie is still unresolved. This is
// deliberately a selection task, not open-ended generation: the model is
// never allowed to invent a name outside the given candidate list, which
// keeps this agent cheap (small model, closed set) and safe (no
// fabricated evidence).

use serde::Deserialize;

use crate::services::ai_provider::{ChatCompletionRequest, ChatCompletionResponse, ChatMessage};

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

pub fn build_arbitration_request(request: &ArbitrationRequest, model: &str) -> ChatCompletionRequest {
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
