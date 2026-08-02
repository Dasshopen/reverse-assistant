// Generates a naming-benchmark suite from a real symbolized binary
// (fauxware) whose real names have been hidden from the agent (see
// tests/fixtures/real-fauxware-hidden-names-export-v2.json and
// docs/naming-benchmark.md for how the fixture was built). Runs the exact
// same generation pipeline the app's `generate_identification_suggestion`
// Tauri command uses -- single-pass, then at most one read-only tool
// follow-up, then confidence calibration -- against a locally running
// Ollama endpoint, and prints a NamingBenchmarkReport.
use std::time::Instant;

use reverse_assistant_lib::models::ghidra_export::GhidraExport;
use reverse_assistant_lib::services::ai_provider::{
    ChatCompletionProvider, OpenAiCompatibleProvider,
};
use reverse_assistant_lib::services::naming_benchmark::{
    evaluate_suite, NamingBenchmarkCase, NamingBenchmarkSuite,
};
use reverse_assistant_lib::services::naming_generation;
use reverse_assistant_lib::services::semantic_memory;

const FIXTURE: &str =
    include_str!("../../tests/fixtures/real-fauxware-hidden-names-export-v2.json");
const MODEL: &str = "qwen2.5-coder:7b";
const BASE_URL: &str = "http://localhost:11434/v1";
// The app's default prudence profile ("Equilibre") auto-applies from 45%.
const AUTOMATIC_THRESHOLD: u8 = 45;

struct Target {
    entry_address: &'static str,
    expected_names: &'static [&'static str],
}

const TARGETS: &[Target] = &[
    Target {
        entry_address: "0x400664",
        expected_names: &[
            "authenticate",
            "verify_password",
            "check_password",
            "validate_credentials",
            "check_sneaky_or_file_content",
        ],
    },
    Target {
        entry_address: "0x4006ed",
        expected_names: &[
            "accepted",
            "display_admin_welcome_message",
            "show_admin_welcome",
            "print_admin_welcome_message",
        ],
    },
    Target {
        entry_address: "0x4006fd",
        expected_names: &[
            "rejected",
            "terminate_and_notify",
            "print_rejection_and_exit",
            "display_rejection_message_and_exit",
        ],
    },
];

fn run_one(
    export: &GhidraExport,
    semantic_index: &std::collections::HashMap<String, semantic_memory::FunctionSemanticFacts>,
    provider: &OpenAiCompatibleProvider,
    target: &Target,
) -> Result<NamingBenchmarkCase, String> {
    let started = Instant::now();
    let context = naming_generation::build_context_for_function_from_index(
        export,
        semantic_index,
        target.entry_address,
    )?;

    let request = naming_generation::build_generation_request(&context, MODEL);
    let mut result = provider
        .complete(&request)
        .and_then(|response| naming_generation::parse_generation_response(&response))?;
    let mut model_calls = 1;

    if !result.requested_tools.is_empty() {
        let findings = semantic_memory::execute_investigation_tools(
            export,
            target.entry_address,
            &result.requested_tools,
        )?;
        let followup_contexts = vec![(target.entry_address.to_owned(), context.clone(), findings)];
        let followup_request =
            naming_generation::build_generation_followup_batch_request(&followup_contexts, MODEL);
        model_calls += 1;
        let mut followups = provider.complete(&followup_request).and_then(|response| {
            naming_generation::parse_generation_batch_response(
                &response,
                std::slice::from_ref(&target.entry_address.to_owned()),
            )
        })?;
        if let Some(followup) = followups.pop() {
            if followup.result.suggested_name.is_some() || result.suggested_name.is_none() {
                result = followup.result;
            }
        }
    }

    let verification_candidates = vec![(
        target.entry_address.to_owned(),
        context.clone(),
        result.clone(),
    )];
    let verification_request =
        naming_generation::build_name_verification_batch_request(&verification_candidates, MODEL);
    model_calls += 1;
    match provider
        .complete(&verification_request)
        .and_then(|response| {
            naming_generation::parse_name_verification_batch_response(
                &response,
                std::slice::from_ref(&target.entry_address.to_owned()),
            )
        }) {
        Ok(verifications) => {
            println!(
                "  verification brute: {}",
                serde_json::to_string(&verifications[0])
                    .expect("a verification result must serialize")
            );
            naming_generation::calibrate_confidence_with_verification(
                &context,
                &mut result,
                &verifications[0],
            )
        }
        Err(error) => {
            eprintln!(
                "{}: contradictory verifier failed ({error}); using conservative confidence",
                target.entry_address
            );
            naming_generation::calibrate_confidence_with_deterministic_evidence(
                &context,
                &mut result,
            );
        }
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;

    println!(
        "{} (attendu: {}) -> {:?} (confiance {}%, {} appel(s), {} ms)\n  raison: {}",
        target.entry_address,
        target.expected_names[0],
        result.suggested_name,
        result.confidence,
        model_calls,
        elapsed_ms,
        result.reasoning
    );

    Ok(NamingBenchmarkCase {
        entry_address: target.entry_address.to_owned(),
        expected_names: target
            .expected_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        suggested_name: result.suggested_name.clone(),
        confidence: result.confidence,
        automatically_applied: result.suggested_name.is_some()
            && result.confidence >= AUTOMATIC_THRESHOLD,
        elapsed_ms,
        model_calls,
        semantic_review: None,
    })
}

fn main() {
    let export = GhidraExport::parse_and_validate(FIXTURE)
        .expect("the committed masked fauxware fixture must stay valid");
    let semantic_index = semantic_memory::build_semantic_index(&export);
    let provider = OpenAiCompatibleProvider {
        base_url: BASE_URL.to_owned(),
        api_key: None,
    };

    let mut cases = Vec::new();
    for target in TARGETS {
        match run_one(&export, &semantic_index, &provider, target) {
            Ok(case) => cases.push(case),
            Err(error) => {
                eprintln!("{}: {error}", target.entry_address);
                std::process::exit(1);
            }
        }
    }

    let suite = NamingBenchmarkSuite {
        name: "fauxware-hidden-names".to_owned(),
        cases,
    };
    let report = evaluate_suite(&suite).expect("a suite built from valid cases must evaluate");
    println!(
        "\n{}",
        serde_json::to_string_pretty(&suite).expect("the suite must serialize")
    );
    println!(
        "\n{}",
        serde_json::to_string_pretty(&report).expect("the report must serialize")
    );
}
