use std::fs::File;
use std::io::Read;

use reverse_assistant_lib::models::ghidra_export::GhidraExport;
use reverse_assistant_lib::services::naming_generation::{
    self, GenerationResult, StoredGenerationOutcome,
};
use reverse_assistant_lib::services::semantic_memory;
use zip::ZipArchive;

fn read_entry(archive: &mut ZipArchive<File>, name: &str) -> Result<String, String> {
    let mut entry = archive
        .by_name(name)
        .map_err(|error| format!("archive has no '{name}': {error}"))?;
    let mut value = String::new();
    entry
        .read_to_string(&mut value)
        .map_err(|error| format!("failed to read '{name}': {error}"))?;
    Ok(value)
}

fn main() -> Result<(), String> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| "usage: naming-evidence-audit <analysis.zip>".to_owned())?;
    let file = File::open(&path).map_err(|error| format!("failed to open '{path}': {error}"))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| format!("invalid project archive '{path}': {error}"))?;
    let export: GhidraExport = serde_json::from_str(&read_entry(&mut archive, "export.json")?)
        .map_err(|error| format!("invalid canonical export: {error}"))?;
    let outcomes: Vec<StoredGenerationOutcome> =
        serde_json::from_str(&read_entry(&mut archive, "generation-results.json")?)
            .map_err(|error| format!("invalid generation outcomes: {error}"))?;
    export.validate()?;
    let index = semantic_memory::build_semantic_index(&export);
    let mut buckets = [0usize; 101];
    let mut examples = Vec::new();
    let mut partial_examples = Vec::new();
    for outcome in outcomes {
        let Some(name) = outcome.suggested_name.clone() else {
            continue;
        };
        let context = naming_generation::build_context_for_function_from_index(
            &export,
            &index,
            &outcome.entry_address,
        )?;
        let mut result = GenerationResult {
            suggested_name: Some(name.clone()),
            reasoning: outcome.reasoning,
            // Measure the evidence ceiling independently of the old model's
            // already-calibrated score stored in the project.
            confidence: 100,
            evidence: outcome.evidence,
            requested_tools: Vec::new(),
        };
        naming_generation::calibrate_confidence_with_deterministic_evidence(&context, &mut result);
        buckets[result.confidence as usize] += 1;
        if result.confidence >= 65 && examples.len() < 20 {
            examples.push((outcome.entry_address, name, result.confidence));
        } else if result.confidence == 60 && partial_examples.len() < 100 {
            let summary = result
                .evidence
                .iter()
                .rev()
                .find(|item| item.starts_with("Verification contradictoire"))
                .cloned()
                .unwrap_or_else(|| "<missing verification summary>".to_owned());
            partial_examples.push((
                outcome.entry_address,
                name,
                summary,
                context.semantic_facts.imported_symbols.clone(),
                context.semantic_facts.referenced_strings.clone(),
                context
                    .semantic_facts
                    .callees
                    .iter()
                    .map(|callee| callee.name.clone())
                    .collect::<Vec<_>>(),
            ));
        }
    }
    let automatic: usize = buckets[65..].iter().sum();
    let manual: usize = buckets[..65].iter().sum();
    println!("deterministic evidence ceiling: {automatic} automatic, {manual} manual");
    for (confidence, count) in buckets.iter().enumerate().rev() {
        if *count > 0 {
            println!("  {confidence}%: {count}");
        }
    }
    println!("examples reaching 65%:");
    for (address, name, confidence) in examples {
        println!("  {address} -> {name} ({confidence}%)");
    }
    println!("examples blocked at 60%:");
    for (address, name, summary, imports, strings, callees) in partial_examples {
        println!(
            "  {address} -> {name} | {summary} | imports={imports:?} strings={strings:?} callees={callees:?}"
        );
    }
    Ok(())
}
