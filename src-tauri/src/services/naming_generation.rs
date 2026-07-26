// The generative naming agent: for functions FunctionID and BSim found
// *zero* candidates for at all (no closed set to select from, unlike
// naming_arbitration's tied-candidate case), asks the model to propose a
// real name from scratch, using only the function's real context
// (pseudocode, callers, callees, referenced strings). This is a
// fundamentally riskier task than arbitration's closed-set selection --
// there is nothing to check the answer against except the shape of the
// name itself -- so a suggestion here is never auto-applied in bulk the
// way RTTI/FunctionID/BSim/arbitration choices are: it always needs an
// explicit human click, and is persisted as a "suggestion", never framed
// as a verified fact.

use serde::{Deserialize, Serialize};

use crate::services::ai_provider::{ChatCompletionRequest, ChatCompletionResponse, ChatMessage};

pub use crate::services::naming_arbitration::{build_context_for_function, ArbitrationContext};

/// A generative naming answer, persisted alongside the project so it
/// survives an app restart -- same rationale as
/// naming_arbitration::StoredArbitrationOutcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredGenerationOutcome {
    pub entry_address: String,
    pub suggested_name: Option<String>,
    pub reasoning: String,
    pub provider_label: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GenerationResult {
    /// `None` means the agent itself found too little signal to suggest
    /// anything -- this must be surfaced to the user as "no suggestion",
    /// never a guessed placeholder.
    pub suggested_name: Option<String>,
    pub reasoning: String,
}

const SYSTEM_PROMPT: &str = "Tu es un agent de suggestion de noms pour un outil de reverse \
engineering. Cette fonction n'a ete reconnue par AUCUN outil d'analyse (FunctionID, BSim) -- il \
n'y a donc AUCUNE liste de candidats a departager, contrairement a une tache d'arbitrage. Ta \
tache est de proposer, si et seulement si le contexte fourni (pseudocode, appelants, fonctions \
appelees, chaines referencees) donne un signal reel sur ce que fait cette fonction, un seul nom \
d'identifiant C/C++ valide qui refleterait son role reel. Si le contexte est trop generique, trop \
court, ou ne permet pas de deviner un role precis avec un minimum de confiance, tu dois \
explicitement ne rien proposer plutot que d'inventer un nom generique ou plausible au hasard -- \
un nom errone est pire qu'aucun nom. Le nom propose doit etre un identifiant valide : lettres, \
chiffres, underscores uniquement, commencant par une lettre ou un underscore, en \
snake_case ou lowerCamelCase, jamais de namespace ni de ponctuation. Reponds UNIQUEMENT avec un \
objet JSON de la forme exacte : {\"suggested_name\": \"<identifiant>\" ou null, \"reasoning\": \
\"<explication courte en francais, citant les elements de contexte utilises, ou expliquant \
pourquoi aucun nom n'est propose>\"}.";

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

pub fn build_generation_request(
    context: &ArbitrationContext,
    model: &str,
) -> ChatCompletionRequest {
    ChatCompletionRequest {
        model: model.to_owned(),
        messages: vec![
            ChatMessage {
                role: "system".to_owned(),
                content: SYSTEM_PROMPT.to_owned(),
            },
            ChatMessage {
                role: "user".to_owned(),
                content: format_context(context),
            },
        ],
        temperature: Some(0.0),
    }
}

fn is_plausible_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let starts_ok = chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_');
    starts_ok
        && name.len() <= 200
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[derive(Deserialize)]
struct GenerationResponseJson {
    suggested_name: Option<String>,
    reasoning: String,
}

/// Parses the model's response and enforces the only safety net available
/// for an open-ended suggestion (there is no closed candidate list to
/// check against here): the name must at least have the shape of a real
/// identifier. A malformed shape is rejected outright rather than passed
/// through, exactly like naming_arbitration rejects an out-of-list choice.
pub fn parse_generation_response(
    response: &ChatCompletionResponse,
) -> Result<GenerationResult, String> {
    let parsed: GenerationResponseJson = serde_json::from_str(&response.content)
        .map_err(|error| format!("invalid generation response JSON: {error}"))?;

    let suggested_name = match parsed.suggested_name {
        Some(name) if is_plausible_identifier(&name) => Some(name),
        Some(name) => {
            return Err(format!(
                "the model suggested '{name}', which is not a valid identifier shape"
            ))
        }
        None => None,
    };

    Ok(GenerationResult {
        suggested_name,
        reasoning: parsed.reasoning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context() -> ArbitrationContext {
        ArbitrationContext {
            current_name: "FUN_140009a10".to_owned(),
            decompiled_code: Some(
                "int FUN_140009a10(char *path) { return CreateFileA(path, ...); }".to_owned(),
            ),
            caller_names: vec!["main".to_owned()],
            callee_names: vec!["CreateFileA".to_owned()],
            referenced_strings: vec!["rb".to_owned()],
        }
    }

    #[test]
    fn the_context_appears_in_the_prompt_with_no_candidate_list() {
        let chat_request = build_generation_request(&sample_context(), "qwen2.5-coder:7b");

        assert_eq!(chat_request.model, "qwen2.5-coder:7b");
        assert_eq!(chat_request.messages.len(), 2);
        let user_message = &chat_request.messages[1].content;
        assert!(user_message.contains("FUN_140009a10"));
        assert!(user_message.contains("CreateFileA"));
        assert!(user_message.contains("main"));
        // Unlike arbitration, there is no closed candidate list to render.
        assert!(!user_message.contains("Liste fermee"));
    }

    #[test]
    fn a_missing_decompiled_code_is_stated_explicitly_rather_than_omitted() {
        let context = ArbitrationContext {
            current_name: "FUN_1".to_owned(),
            decompiled_code: None,
            caller_names: vec![],
            callee_names: vec![],
            referenced_strings: vec![],
        };

        let chat_request = build_generation_request(&context, "qwen2.5-coder:7b");

        assert!(chat_request.messages[1].content.contains("indisponible"));
    }

    #[test]
    fn a_plausible_identifier_suggestion_is_accepted() {
        let response = ChatCompletionResponse {
            content: r#"{"suggested_name": "open_config_file", "reasoning": "Appelle CreateFileA avec un mode lecture (\"rb\")."}"#.to_owned(),
        };

        let result = parse_generation_response(&response)
            .expect("a plausible identifier suggestion should parse");

        assert_eq!(result.suggested_name, Some("open_config_file".to_owned()));
        assert!(result.reasoning.contains("CreateFileA"));
    }

    #[test]
    fn an_explicit_null_suggestion_means_no_real_signal() {
        let response = ChatCompletionResponse {
            content: r#"{"suggested_name": null, "reasoning": "Aucun element du contexte ne permet de deviner un role precis."}"#.to_owned(),
        };

        let result = parse_generation_response(&response)
            .expect("an explicit null suggestion should parse");

        assert_eq!(result.suggested_name, None);
    }

    #[test]
    fn a_namespaced_name_is_rejected_as_not_a_bare_identifier() {
        let response = ChatCompletionResponse {
            content: r#"{"suggested_name": "std::open_config_file", "reasoning": "..."}"#
                .to_owned(),
        };

        let error = parse_generation_response(&response)
            .expect_err("a namespaced name is not a bare identifier shape");

        assert!(error.contains("std::open_config_file"));
        assert!(error.contains("not a valid identifier shape"));
    }

    #[test]
    fn a_name_with_punctuation_is_rejected() {
        let response = ChatCompletionResponse {
            content: r#"{"suggested_name": "open-config-file!", "reasoning": "..."}"#.to_owned(),
        };

        let error = parse_generation_response(&response)
            .expect_err("punctuation is not a valid identifier shape");

        assert!(error.contains("not a valid identifier shape"));
    }

    #[test]
    fn a_name_starting_with_a_digit_is_rejected() {
        let response = ChatCompletionResponse {
            content: r#"{"suggested_name": "1_open_file", "reasoning": "..."}"#.to_owned(),
        };

        let error = parse_generation_response(&response)
            .expect_err("an identifier cannot start with a digit");

        assert!(error.contains("not a valid identifier shape"));
    }

    #[test]
    fn malformed_response_json_is_rejected() {
        let response = ChatCompletionResponse {
            content: "not json".to_owned(),
        };

        let error = parse_generation_response(&response)
            .expect_err("malformed JSON should be rejected");

        assert!(error.contains("invalid generation response JSON"));
    }
}
