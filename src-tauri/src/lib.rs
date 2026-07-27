// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use tauri::AppHandle;

use models::ghidra_export::GhidraExport;
use models::ghidra_identification::FunctionIdentification;
use models::ghidra_installation::GhidraInstallation;
use models::ghidra_session::AnalysisSession;
use models::project::ProjectMetadata;
use services::ai_provider::ChatCompletionProvider;
use services::ai_providers::{self, AiProviderSummary};
use services::bsim_corpus::{self, BsimCorpusSummary};
use services::call_graph::{self, CallGraphDirection, CallGraphNeighborhood};
use services::comparison::{self, ProjectComparison};
use services::ghidra_bsim_scan;
use services::ghidra_decompile::{self, DecompiledFunctionDetails, PreparedFunctionContext};
use services::ghidra_disassemble::{self, FunctionDisassembly};
use services::ghidra_edits::{self, ApplyRenamesResult, FunctionRename};
use services::ghidra_headless;
use services::ghidra_import::{import_ghidra_export, GhidraImportSummary, ImportedGhidraExport};
use services::ghidra_installation::{self, GhidraInstallationStatus};
use services::global_strings::{self, GlobalStringView};
use services::identification_corroboration;
use services::imports_exports::{self, ImportView};
use services::naming_arbitration;
use services::naming_generation;
use services::program_overview::{self, ProgramOverview};
use services::project_storage::{self, ProjectSummary};
use services::report::{self, PdfReportResult};
use services::setup::{self, SetupInstallPlan, SetupOverview};

#[derive(Debug, Clone, Serialize)]
struct AutomaticAnalysisResult {
    imported: ImportedGhidraExport,
    identifications: Vec<FunctionIdentification>,
    saved_project: Option<ProjectMetadata>,
}

#[derive(Debug, Clone, Serialize)]
struct LoadedProject {
    export: GhidraExport,
    identifications: Option<Vec<FunctionIdentification>>,
    project: ProjectSummary,
}

// Best-effort: a failure to persist a project as a local project must not
// fail the analysis/import the user is actively waiting on -- the data is
// still fully usable for the rest of this session either way, it just
// won't be reloadable in a future one.
fn auto_save_project(
    app: &AppHandle,
    export: &GhidraExport,
    session: Option<AnalysisSession>,
    identifications: Option<&[FunctionIdentification]>,
) -> Option<ProjectMetadata> {
    let result = if let Some(identifications) = identifications {
        project_storage::save_project_with_identifications(
            app,
            &export.program.name,
            export,
            session,
            identifications,
        )
    } else {
        project_storage::save_project(app, &export.program.name, export, session)
    };
    match result {
        Ok(project) => Some(project),
        Err(error) => {
            eprintln!("failed to save this analysis as a local project: {error}");
            None
        }
    }
}

pub mod models;
pub mod services;

#[derive(Default)]
struct DecompileCoordinator(Mutex<()>);

impl DecompileCoordinator {
    fn run_exclusive<T>(&self, operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _guard = self
            .0
            .lock()
            .map_err(|_| "the Ghidra decompilation queue lock was poisoned".to_owned())?;

        operation()
    }
}

#[tauri::command]
fn get_backend_status() -> String {
    String::from("Reverse Assistant Rust backend ready")
}

#[tauri::command]
fn import_ghidra_export_summary(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    path: String,
) -> Result<GhidraImportSummary, String> {
    let imported = import_ghidra_export(Path::new(&path))?;
    store_export(&export_state, imported.export.clone())?;
    // A manual JSON import has no live Ghidra project behind it -- it can
    // only ever be a snapshot project.
    let _ = auto_save_project(&app, &imported.export, None, None);

    Ok(imported.summary)
}

#[tauri::command]
fn import_ghidra_export_details(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    path: String,
) -> Result<ImportedGhidraExport, String> {
    let imported = import_ghidra_export(Path::new(&path))?;
    store_export(&export_state, imported.export.clone())?;
    let _ = auto_save_project(&app, &imported.export, None, None);

    Ok(imported)
}

fn store_export(
    export_state: &tauri::State<'_, Mutex<Option<GhidraExport>>>,
    export: GhidraExport,
) -> Result<(), String> {
    *export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())? = Some(export);

    Ok(())
}

#[tauri::command]
fn configure_ghidra_installation(
    app: AppHandle,
    install_dir: String,
) -> Result<GhidraInstallation, String> {
    ghidra_installation::configure_and_persist(&app, Path::new(&install_dir))
}

#[tauri::command]
fn get_ghidra_installation_status(app: AppHandle) -> Result<GhidraInstallationStatus, String> {
    ghidra_installation::current_installation_status(&app)
}

#[tauri::command]
fn get_setup_overview(app: AppHandle) -> Result<SetupOverview, String> {
    setup::inspect_setup(&app)
}

#[tauri::command]
fn list_bsim_corpora(app: AppHandle) -> Result<Vec<BsimCorpusSummary>, String> {
    bsim_corpus::list_corpora(&app)
}

#[tauri::command]
fn import_bsim_corpus(app: AppHandle, path: String) -> Result<BsimCorpusSummary, String> {
    bsim_corpus::import_custom_corpus(&app, Path::new(&path))
}

#[tauri::command(async)]
fn add_bsim_reference_library(
    app: AppHandle,
    coordinator: tauri::State<'_, DecompileCoordinator>,
    path: String,
) -> Result<BsimCorpusSummary, String> {
    coordinator.run_exclusive(|| bsim_corpus::build_corpus_from_library(&app, Path::new(&path)))
}

#[tauri::command]
fn set_bsim_corpus_enabled(app: AppHandle, id: String, enabled: bool) -> Result<(), String> {
    bsim_corpus::set_corpus_enabled(&app, &id, enabled)
}

#[tauri::command]
fn remove_bsim_corpus(app: AppHandle, id: String) -> Result<(), String> {
    bsim_corpus::remove_custom_corpus(&app, &id)
}

#[tauri::command]
fn list_ai_providers(app: AppHandle) -> Result<Vec<AiProviderSummary>, String> {
    ai_providers::list_providers_for_app(&app)
}

#[tauri::command]
fn add_ai_provider(
    app: AppHandle,
    label: String,
    base_url: String,
    api_key: Option<String>,
    model: String,
) -> Result<AiProviderSummary, String> {
    ai_providers::add_provider_for_app(&app, &label, &base_url, api_key, &model)
}

#[tauri::command]
fn set_ai_provider_enabled(app: AppHandle, id: String, enabled: bool) -> Result<(), String> {
    ai_providers::set_provider_enabled_for_app(&app, &id, enabled)
}

#[tauri::command]
fn remove_ai_provider(app: AppHandle, id: String) -> Result<(), String> {
    ai_providers::remove_provider_for_app(&app, &id)
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ArbitrationCandidateInput {
    name: String,
    source_label: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct ArbitrationOutcome {
    chosen_name: Option<String>,
    reasoning: String,
    provider_label: String,
    confidence: u8,
    evidence: Vec<String>,
}

fn synthesize_arbitration_answers(
    answers: &[(String, naming_arbitration::ArbitrationResult)],
) -> ArbitrationOutcome {
    let mut votes = std::collections::HashMap::<String, u32>::new();
    for (_, answer) in answers {
        if let Some(name) = &answer.chosen_name {
            *votes.entry(name.clone()).or_default() += u32::from(answer.confidence.max(1));
        }
    }
    let chosen_name = votes
        .into_iter()
        .max_by_key(|(_, weighted_confidence)| *weighted_confidence)
        .map(|(name, _)| name);
    let agreeing: Vec<_> = answers
        .iter()
        .filter(|(_, answer)| answer.chosen_name == chosen_name)
        .collect();
    let confidence = if chosen_name.is_some() && !agreeing.is_empty() {
        let average = (agreeing
            .iter()
            .map(|(_, answer)| u16::from(answer.confidence))
            .sum::<u16>()
            / agreeing.len() as u16) as f64;
        (average * (0.75 + 0.25 * agreeing.len() as f64 / answers.len() as f64)).round() as u8
    } else {
        0
    };
    let evidence = agreeing
        .iter()
        .flat_map(|(_, answer)| answer.evidence.clone())
        .take(12)
        .collect();
    let reasoning = if chosen_name.is_some() {
        let consensus = agreeing
            .iter()
            .map(|(label, answer)| format!("{label}: {}", answer.reasoning))
            .collect::<Vec<_>>()
            .join(" | ");
        if agreeing.len() == answers.len() {
            consensus
        } else {
            format!("{consensus} | D'autres agents ont divergé; la confiance a été réduite.")
        }
    } else {
        "Les agents activés manquent de contexte exploitable; validation manuelle requise."
            .to_owned()
    };
    ArbitrationOutcome {
        chosen_name,
        reasoning,
        provider_label: answers
            .iter()
            .map(|(label, _)| label.as_str())
            .collect::<Vec<_>>()
            .join(" + "),
        confidence,
        evidence,
    }
}

#[tauri::command(async)]
fn arbitrate_identification_tie(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    entry_address: String,
    candidates: Vec<ArbitrationCandidateInput>,
) -> Result<ArbitrationOutcome, String> {
    if candidates.is_empty() {
        return Err("no candidates were provided to arbitrate between".to_owned());
    }

    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| "no analysis is currently loaded".to_owned())?;

    let arbitration_candidates: Vec<naming_arbitration::ArbitrationCandidate> = candidates
        .into_iter()
        .map(|candidate| naming_arbitration::ArbitrationCandidate {
            name: candidate.name,
            source_label: candidate.source_label,
        })
        .collect();

    let context = naming_arbitration::build_context_for_function(&export, &entry_address)?;

    let enabled = ai_providers::enabled_providers_for_app(&app)?;
    if enabled.is_empty() {
        return Err("no AI provider is enabled. Configure one under Réglages first.".to_owned());
    }

    let mut answers = Vec::new();
    let mut errors = Vec::new();
    for secrets in enabled {
        let provider = services::ai_provider::OpenAiCompatibleProvider {
            base_url: secrets.base_url,
            api_key: secrets.api_key,
        };
        let request = naming_arbitration::build_arbitration_request(
            &naming_arbitration::ArbitrationRequest {
                candidates: arbitration_candidates.clone(),
                context: context.clone(),
            },
            &secrets.model,
        );
        match provider.complete(&request).and_then(|response| {
            naming_arbitration::parse_arbitration_response(&response, &arbitration_candidates)
        }) {
            Ok(result) => answers.push((secrets.label, result)),
            Err(error) => errors.push(format!("{}: {error}", secrets.label)),
        }
    }
    if answers.is_empty() {
        return Err(format!(
            "all enabled AI providers failed: {}",
            errors.join("; ")
        ));
    }

    Ok(synthesize_arbitration_answers(&answers))
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ArbitrationBatchInput {
    entry_address: String,
    candidates: Vec<ArbitrationCandidateInput>,
}

#[derive(Debug, Clone, Serialize)]
struct ArbitrationBatchOutcome {
    entry_address: String,
    chosen_name: Option<String>,
    reasoning: String,
    provider_label: String,
    confidence: u8,
    evidence: Vec<String>,
}

#[tauri::command(async)]
fn arbitrate_identification_ties(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    items: Vec<ArbitrationBatchInput>,
) -> Result<Vec<ArbitrationBatchOutcome>, String> {
    if items.is_empty() || items.len() > 6 {
        return Err("an arbitration batch must contain between 1 and 6 functions".to_owned());
    }
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| "no analysis is currently loaded".to_owned())?;
    let requests = items
        .iter()
        .map(|item| {
            if item.candidates.is_empty() {
                return Err(format!(
                    "no candidates were provided for '{}'",
                    item.entry_address
                ));
            }
            let candidates = item
                .candidates
                .iter()
                .map(|candidate| naming_arbitration::ArbitrationCandidate {
                    name: candidate.name.clone(),
                    source_label: candidate.source_label.clone(),
                })
                .collect();
            let context =
                naming_arbitration::build_context_for_function(&export, &item.entry_address)?;
            Ok((
                item.entry_address.clone(),
                naming_arbitration::ArbitrationRequest {
                    candidates,
                    context,
                },
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let enabled = ai_providers::enabled_providers_for_app(&app)?;
    if enabled.is_empty() {
        return Err("no AI provider is enabled. Configure one under Réglages first.".to_owned());
    }
    let mut by_address = std::collections::HashMap::<
        String,
        Vec<(String, naming_arbitration::ArbitrationResult)>,
    >::new();
    let mut errors = Vec::new();
    for secrets in enabled {
        let provider = services::ai_provider::OpenAiCompatibleProvider {
            base_url: secrets.base_url,
            api_key: secrets.api_key,
        };
        let request =
            naming_arbitration::build_arbitration_batch_request(&requests, &secrets.model);
        match provider.complete(&request).and_then(|response| {
            naming_arbitration::parse_arbitration_batch_response(&response, &requests)
        }) {
            Ok(results) => {
                for (address, result) in results {
                    by_address
                        .entry(address)
                        .or_default()
                        .push((secrets.label.clone(), result));
                }
            }
            Err(error) => errors.push(format!("{}: {error}", secrets.label)),
        }
    }
    if by_address.is_empty() {
        return Err(format!(
            "all enabled AI providers failed: {}",
            errors.join("; ")
        ));
    }
    requests
        .iter()
        .map(|(address, _)| {
            let answers = by_address
                .get(address)
                .ok_or_else(|| format!("no provider returned an arbitration for '{address}'"))?;
            let result = synthesize_arbitration_answers(answers);
            Ok(ArbitrationBatchOutcome {
                entry_address: address.clone(),
                chosen_name: result.chosen_name,
                reasoning: result.reasoning,
                provider_label: result.provider_label,
                confidence: result.confidence,
                evidence: result.evidence,
            })
        })
        .collect()
}

// Persisted alongside the project (see StoredArbitrationOutcome) so a real
// AI answer is never re-spent on a reopen: without this, every restart
// would re-run every pending tied function through the arbitration agent
// again from scratch.
#[tauri::command]
fn save_arbitration_result(
    app: AppHandle,
    project_id: String,
    entry_address: String,
    outcome: ArbitrationOutcome,
) -> Result<(), String> {
    let mut results = project_storage::load_project_arbitration(&app, &project_id)?;
    let stored = naming_arbitration::StoredArbitrationOutcome {
        entry_address: entry_address.clone(),
        chosen_name: outcome.chosen_name,
        reasoning: outcome.reasoning,
        provider_label: outcome.provider_label,
        confidence: outcome.confidence,
        evidence: outcome.evidence,
        context_complete: true,
        agent_version: naming_arbitration::NAMING_PIPELINE_VERSION,
    };
    match results
        .iter_mut()
        .find(|existing| existing.entry_address == entry_address)
    {
        Some(existing) => *existing = stored,
        None => results.push(stored),
    }
    project_storage::replace_project_arbitration(&app, &project_id, &results)
}

#[tauri::command]
fn get_arbitration_results(
    app: AppHandle,
    project_id: String,
) -> Result<Vec<naming_arbitration::StoredArbitrationOutcome>, String> {
    project_storage::load_project_arbitration(&app, &project_id)
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct GenerationOutcome {
    suggested_name: Option<String>,
    reasoning: String,
    provider_label: String,
    confidence: u8,
    evidence: Vec<String>,
    #[serde(default)]
    analysis_pass: u8,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct GenerationBatchOutcome {
    entry_address: String,
    suggested_name: Option<String>,
    reasoning: String,
    provider_label: String,
    confidence: u8,
    evidence: Vec<String>,
    analysis_pass: u8,
}

fn synthesize_generation_answers(
    entry_address: &str,
    answers: &[(String, naming_generation::GenerationResult)],
    analysis_pass: u8,
) -> GenerationBatchOutcome {
    let named: Vec<_> = answers
        .iter()
        .filter(|(_, answer)| answer.suggested_name.is_some())
        .collect();
    let best = named.iter().max_by(|(_, left), (_, right)| {
        let left_name = left.suggested_name.as_deref().unwrap_or_default();
        let right_name = right.suggested_name.as_deref().unwrap_or_default();
        let left_support: f64 = named
            .iter()
            .map(|(_, other)| {
                naming_generation::semantic_name_similarity(
                    left_name,
                    other.suggested_name.as_deref().unwrap_or_default(),
                ) * f64::from(other.confidence.max(1))
            })
            .sum();
        let right_support: f64 = named
            .iter()
            .map(|(_, other)| {
                naming_generation::semantic_name_similarity(
                    right_name,
                    other.suggested_name.as_deref().unwrap_or_default(),
                ) * f64::from(other.confidence.max(1))
            })
            .sum();
        left_support.total_cmp(&right_support)
    });

    let (suggested_name, confidence, evidence, reasoning) = if let Some((_, winner)) = best {
        let winner_name = winner.suggested_name.as_deref().unwrap_or_default();
        let agreeing: Vec<_> = named
            .iter()
            .filter(|(_, answer)| {
                naming_generation::semantic_name_similarity(
                    winner_name,
                    answer.suggested_name.as_deref().unwrap_or_default(),
                ) >= 0.34
            })
            .collect();
        let base_confidence = agreeing
            .iter()
            .map(|(_, answer)| u16::from(answer.confidence))
            .sum::<u16>()
            / agreeing.len().max(1) as u16;
        let agreement_factor = 0.75 + 0.25 * agreeing.len() as f64 / named.len().max(1) as f64;
        let confidence = (f64::from(base_confidence) * agreement_factor).round() as u8;
        let evidence = agreeing
            .iter()
            .flat_map(|(_, answer)| answer.evidence.clone())
            .take(12)
            .collect();
        let reasoning = agreeing
            .iter()
            .map(|(label, answer)| format!("{label}: {}", answer.reasoning))
            .collect::<Vec<_>>()
            .join(" | ");
        (
            winner.suggested_name.clone(),
            confidence,
            evidence,
            reasoning,
        )
    } else {
        (
            None,
            0,
            Vec::new(),
            answers
                .iter()
                .map(|(label, answer)| format!("{label}: {}", answer.reasoning))
                .collect::<Vec<_>>()
                .join(" | "),
        )
    };
    GenerationBatchOutcome {
        entry_address: entry_address.to_owned(),
        suggested_name,
        reasoning,
        provider_label: answers
            .iter()
            .map(|(label, _)| label.as_str())
            .collect::<Vec<_>>()
            .join(" + "),
        confidence,
        evidence,
        analysis_pass,
    }
}

#[tauri::command(async)]
fn generate_identification_suggestions(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    semantic_index_cache: tauri::State<'_, services::semantic_memory::SemanticIndexCache>,
    entry_addresses: Vec<String>,
    provisional_names: Vec<naming_generation::ProvisionalFunctionName>,
) -> Result<Vec<GenerationBatchOutcome>, String> {
    if entry_addresses.is_empty() || entry_addresses.len() > 6 {
        return Err("a generation batch must contain between 1 and 6 functions".to_owned());
    }
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| "no analysis is currently loaded".to_owned())?;
    // Building caller/thunk/string evidence is whole-program work. Reuse one
    // immutable index for the complete batch instead of rebuilding it once
    // per function (six times for a normal background-agent request).
    let semantic_index = semantic_index_cache.get_or_build(&export)?;
    let contexts = entry_addresses
        .iter()
        .map(|address| {
            naming_generation::build_context_for_function_with_index_and_provisional_names(
                &export,
                &semantic_index,
                address,
                &provisional_names,
            )
            .map(|context| (address.clone(), context))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let enabled = ai_providers::enabled_providers_for_app(&app)?;
    if enabled.is_empty() {
        return Err("no AI provider is enabled. Configure one under Réglages first.".to_owned());
    }

    let mut by_address = std::collections::HashMap::<
        String,
        Vec<(String, naming_generation::GenerationResult)>,
    >::new();
    let mut errors = Vec::new();
    for secrets in enabled {
        let provider = services::ai_provider::OpenAiCompatibleProvider {
            base_url: secrets.base_url,
            api_key: secrets.api_key,
        };
        let request = naming_generation::build_generation_batch_request(&contexts, &secrets.model);
        let expected = entry_addresses.clone();
        match provider.complete(&request).and_then(|response| {
            naming_generation::parse_generation_batch_response(&response, &expected)
        }) {
            Ok(mut results) => {
                let followup_contexts = results
                    .iter()
                    .filter(|item| !item.result.requested_tools.is_empty())
                    .filter_map(|item| {
                        let context = contexts
                            .iter()
                            .find(|(address, _)| address == &item.entry_address)?
                            .1
                            .clone();
                        match services::semantic_memory::execute_investigation_tools(
                            &export,
                            &item.entry_address,
                            &item.result.requested_tools,
                        ) {
                            Ok(findings) => {
                                Some(Ok((item.entry_address.clone(), context, findings)))
                            }
                            Err(error) => Some(Err(error)),
                        }
                    })
                    .collect::<Result<Vec<_>, String>>();

                match followup_contexts {
                    Ok(followup_contexts) if !followup_contexts.is_empty() => {
                        let followup_expected = followup_contexts
                            .iter()
                            .map(|(address, _, _)| address.clone())
                            .collect::<Vec<_>>();
                        let followup_request =
                            naming_generation::build_generation_followup_batch_request(
                                &followup_contexts,
                                &secrets.model,
                            );
                        match provider.complete(&followup_request).and_then(|response| {
                            naming_generation::parse_generation_batch_response(
                                &response,
                                &followup_expected,
                            )
                        }) {
                            Ok(followups) => {
                                for followup in followups {
                                    if let Some(initial) = results
                                        .iter_mut()
                                        .find(|item| item.entry_address == followup.entry_address)
                                    {
                                        // A failed final hypothesis must never erase a usable
                                        // provisional one returned before the investigation.
                                        if followup.result.suggested_name.is_some()
                                            || initial.result.suggested_name.is_none()
                                        {
                                            initial.result = followup.result;
                                        }
                                    }
                                }
                            }
                            Err(error) => errors.push(format!(
                                "{} (investigation follow-up): {error}",
                                secrets.label
                            )),
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        errors.push(format!("{} (investigation tools): {error}", secrets.label))
                    }
                }
                for item in results {
                    let mut result = item.result;
                    if let Some((_, context)) = contexts
                        .iter()
                        .find(|(address, _)| address == &item.entry_address)
                    {
                        naming_generation::calibrate_confidence(context, &mut result);
                    }
                    by_address
                        .entry(item.entry_address)
                        .or_default()
                        .push((secrets.label.clone(), result));
                }
            }
            Err(error) => errors.push(format!("{}: {error}", secrets.label)),
        }
    }
    if by_address.is_empty() {
        return Err(format!(
            "all enabled AI providers failed: {}",
            errors.join("; ")
        ));
    }
    entry_addresses
        .iter()
        .map(|address| {
            by_address
                .get(address)
                .map(|answers| synthesize_generation_answers(address, answers, 1))
                .ok_or_else(|| format!("no provider returned a result for '{address}'"))
        })
        .collect()
}

/// Revisits only weak first-pass hypotheses after stronger neighbouring names
/// are available. This deliberately uses a single enabled provider, one
/// compact request and no model-driven tool loop; the bounded graph inquiry is
/// executed locally before the request, making it substantially cheaper than
/// repeating the full first pass.
#[tauri::command(async)]
fn refine_identification_suggestions(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    semantic_index_cache: tauri::State<'_, services::semantic_memory::SemanticIndexCache>,
    seeds: Vec<naming_generation::RefinementSeed>,
    provisional_names: Vec<naming_generation::ProvisionalFunctionName>,
) -> Result<Vec<GenerationBatchOutcome>, String> {
    if seeds.is_empty() || seeds.len() > 6 {
        return Err("a refinement batch must contain between 1 and 6 functions".to_owned());
    }
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| "no analysis is currently loaded".to_owned())?;
    let semantic_index = semantic_index_cache.get_or_build(&export)?;
    let contexts = seeds
        .iter()
        .map(|seed| {
            let context =
                naming_generation::build_context_for_function_with_index_and_provisional_names(
                    &export,
                    &semantic_index,
                    &seed.entry_address,
                    &provisional_names,
                )?;
            let tools = naming_generation::recommended_refinement_tools(&context);
            let findings = services::semantic_memory::execute_investigation_tools(
                &export,
                &seed.entry_address,
                &tools,
            )?;
            Ok((seed.entry_address.clone(), context, findings))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let provider_secrets = ai_providers::enabled_providers_for_app(&app)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            "no AI provider is enabled. Configure one under Réglages first.".to_owned()
        })?;
    let provider = services::ai_provider::OpenAiCompatibleProvider {
        base_url: provider_secrets.base_url,
        api_key: provider_secrets.api_key,
    };
    let request = naming_generation::build_refinement_batch_request(
        &contexts,
        &seeds,
        &provider_secrets.model,
    );
    let expected = seeds
        .iter()
        .map(|seed| seed.entry_address.clone())
        .collect::<Vec<_>>();
    let response = provider.complete(&request)?;
    let results = naming_generation::parse_generation_batch_response(&response, &expected)?;
    results
        .into_iter()
        .map(|item| {
            let context = contexts
                .iter()
                .find(|(address, _, _)| address == &item.entry_address)
                .map(|(_, context, _)| context)
                .ok_or_else(|| {
                    format!("no refinement context exists for '{}'", item.entry_address)
                })?;
            let mut result = item.result;
            naming_generation::calibrate_confidence(context, &mut result);
            Ok(GenerationBatchOutcome {
                entry_address: item.entry_address,
                suggested_name: result.suggested_name,
                reasoning: result.reasoning,
                provider_label: format!("{} · passe contextuelle", provider_secrets.label),
                confidence: result.confidence,
                evidence: result.evidence,
                analysis_pass: 2,
            })
        })
        .collect()
}

// Unlike arbitrate_identification_tie, this function has *no* FunctionID/
// BSim candidates at all -- there is nothing to select between, only real
// context to reason from. See naming_generation.rs for why this makes the
// answer inherently less safe than a closed-set arbitration choice. It
// carries confidence/evidence so the frontend can enforce the user's
// prudence threshold rather than presenting it as a verified fact.
#[tauri::command(async)]
fn generate_identification_suggestion(
    app: AppHandle,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    semantic_index_cache: tauri::State<'_, services::semantic_memory::SemanticIndexCache>,
    entry_address: String,
) -> Result<GenerationOutcome, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| "no analysis is currently loaded".to_owned())?;

    let semantic_index = semantic_index_cache.get_or_build(&export)?;
    let context = naming_generation::build_context_for_function_from_index(
        &export,
        &semantic_index,
        &entry_address,
    )?;

    let enabled = ai_providers::enabled_providers_for_app(&app)?;
    if enabled.is_empty() {
        return Err("no AI provider is enabled. Configure one under Réglages first.".to_owned());
    }

    let mut answers = Vec::new();
    let mut errors = Vec::new();
    for secrets in enabled {
        let provider = services::ai_provider::OpenAiCompatibleProvider {
            base_url: secrets.base_url,
            api_key: secrets.api_key,
        };
        let request = naming_generation::build_generation_request(&context, &secrets.model);
        match provider
            .complete(&request)
            .and_then(|response| naming_generation::parse_generation_response(&response))
        {
            Ok(mut result) => {
                if !result.requested_tools.is_empty() {
                    match services::semantic_memory::execute_investigation_tools(
                        &export,
                        &entry_address,
                        &result.requested_tools,
                    ) {
                        Ok(findings) => {
                            let followup_contexts =
                                vec![(entry_address.clone(), context.clone(), findings)];
                            let followup_request =
                                naming_generation::build_generation_followup_batch_request(
                                    &followup_contexts,
                                    &secrets.model,
                                );
                            match provider.complete(&followup_request).and_then(|response| {
                                naming_generation::parse_generation_batch_response(
                                    &response,
                                    std::slice::from_ref(&entry_address),
                                )
                            }) {
                                Ok(mut followups) => {
                                    if let Some(followup) = followups.pop() {
                                        if followup.result.suggested_name.is_some()
                                            || result.suggested_name.is_none()
                                        {
                                            result = followup.result;
                                        }
                                    }
                                }
                                Err(error) => errors.push(format!(
                                    "{} (investigation follow-up): {error}",
                                    secrets.label
                                )),
                            }
                        }
                        Err(error) => {
                            errors.push(format!("{} (investigation tools): {error}", secrets.label))
                        }
                    }
                }
                naming_generation::calibrate_confidence(&context, &mut result);
                answers.push((secrets.label, result));
            }
            Err(error) => errors.push(format!("{}: {error}", secrets.label)),
        }
    }
    if answers.is_empty() {
        return Err(format!(
            "all enabled AI providers failed: {}",
            errors.join("; ")
        ));
    }

    let synthesized = synthesize_generation_answers(&entry_address, &answers, 1);
    Ok(GenerationOutcome {
        suggested_name: synthesized.suggested_name,
        reasoning: synthesized.reasoning,
        provider_label: synthesized.provider_label,
        confidence: synthesized.confidence,
        evidence: synthesized.evidence,
        analysis_pass: 1,
    })
}

/// Returns a deterministic, evidence-first queue for the local agent.  The
/// frontend used to rank functions with a small UI-only heuristic; keeping
/// the scheduler in Rust lets it use the real thunk-aware graph, entry points,
/// imports and RTTI facts shared with the prompt builder.
#[tauri::command]
fn get_semantic_analysis_order(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<String>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| "no analysis is currently loaded".to_owned())?;
    Ok(services::semantic_memory::rank_for_semantic_analysis(
        &export,
    ))
}

// Persisted alongside the project (see StoredGenerationOutcome), same
// rationale as save_arbitration_result: a real AI answer must never be
// re-spent on a reopen.
#[tauri::command]
fn save_generation_result(
    app: AppHandle,
    project_id: String,
    entry_address: String,
    outcome: GenerationOutcome,
) -> Result<(), String> {
    let mut results = project_storage::load_project_generation(&app, &project_id)?;
    let stored = naming_generation::StoredGenerationOutcome {
        entry_address: entry_address.clone(),
        suggested_name: outcome.suggested_name,
        reasoning: outcome.reasoning,
        provider_label: outcome.provider_label,
        confidence: outcome.confidence,
        evidence: outcome.evidence,
        context_complete: true,
        agent_version: naming_generation::NAMING_GENERATION_VERSION,
        analysis_pass: outcome.analysis_pass.max(1),
    };
    match results
        .iter_mut()
        .find(|existing| existing.entry_address == entry_address)
    {
        Some(existing) => *existing = stored,
        None => results.push(stored),
    }
    project_storage::replace_project_generation(&app, &project_id, &results)
}

#[tauri::command]
fn save_generation_results(
    app: AppHandle,
    project_id: String,
    outcomes: Vec<GenerationBatchOutcome>,
) -> Result<(), String> {
    if outcomes.is_empty() {
        return Ok(());
    }
    let mut results = project_storage::load_project_generation(&app, &project_id)?;
    for outcome in outcomes {
        let stored = naming_generation::StoredGenerationOutcome {
            entry_address: outcome.entry_address.clone(),
            suggested_name: outcome.suggested_name,
            reasoning: outcome.reasoning,
            provider_label: outcome.provider_label,
            confidence: outcome.confidence,
            evidence: outcome.evidence,
            context_complete: true,
            agent_version: naming_generation::NAMING_GENERATION_VERSION,
            analysis_pass: outcome.analysis_pass.max(1),
        };
        match results
            .iter_mut()
            .find(|existing| existing.entry_address == outcome.entry_address)
        {
            Some(existing) => *existing = stored,
            None => results.push(stored),
        }
    }
    project_storage::replace_project_generation(&app, &project_id, &results)
}

#[tauri::command]
fn get_generation_results(
    app: AppHandle,
    project_id: String,
) -> Result<Vec<naming_generation::StoredGenerationOutcome>, String> {
    project_storage::load_project_generation(&app, &project_id)
}

#[tauri::command]
fn get_managed_setup_plan(app: AppHandle) -> Result<SetupInstallPlan, String> {
    setup::managed_install_plan(&app)
}

#[tauri::command(async)]
fn install_managed_setup(
    app: AppHandle,
    coordinator: tauri::State<'_, DecompileCoordinator>,
    licenses_accepted: bool,
) -> Result<SetupOverview, String> {
    coordinator.run_exclusive(|| setup::install_managed_setup(&app, licenses_accepted))
}

#[tauri::command(async)]
fn adopt_existing_ghidra(
    app: AppHandle,
    coordinator: tauri::State<'_, DecompileCoordinator>,
    install_dir: String,
) -> Result<SetupOverview, String> {
    coordinator.run_exclusive(|| setup::adopt_existing_ghidra(&app, Path::new(&install_dir)))
}

#[tauri::command(async)]
fn analyze_binary_with_ghidra(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    binary_path: String,
) -> Result<AutomaticAnalysisResult, String> {
    let (imported, identifications, session) =
        ghidra_headless::analyze_binary(&app, Path::new(&binary_path))?;

    *session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())? = Some(session.clone());

    store_export(&export_state, imported.export.clone())?;
    ghidra_headless::emit_analysis_progress(
        &app,
        "save",
        "Sauvegarde du projet et de ses résultats en local…",
        Some(96),
    );
    let saved_project = auto_save_project(
        &app,
        &imported.export,
        Some(session),
        Some(&identifications),
    );

    ghidra_headless::emit_analysis_progress(
        &app,
        "complete",
        "Analyse terminée. Le projet est prêt.",
        Some(100),
    );

    Ok(AutomaticAnalysisResult {
        imported,
        identifications,
        saved_project,
    })
}

#[tauri::command(async)]
fn scan_project_with_bsim(
    app: AppHandle,
    coordinator: tauri::State<'_, DecompileCoordinator>,
    project_id: String,
) -> Result<Vec<FunctionIdentification>, String> {
    let (_, existing, project) =
        project_storage::load_project_with_identifications(&app, &project_id)?;
    let session = project
        .metadata
        .session
        .as_ref()
        .ok_or_else(|| "BSim background scanning requires a live Ghidra project".to_owned())?;
    if !project.session_available {
        return Err("the saved Ghidra project is currently unavailable".to_owned());
    }
    project_storage::require_managed_session(&app, session)?;
    let install_dir = ghidra_installation::load_persisted_install_dir(&app)?
        .ok_or_else(|| "No Ghidra installation is configured.".to_owned())?;
    let installation = ghidra_installation::validate_installation(&app, &install_dir)?;

    ghidra_headless::emit_analysis_progress(
        &app,
        "bsim",
        "BSim compare les fonctions non nommées aux corpus actifs en arrière-plan…",
        None,
    );
    let scanned = coordinator
        .run_exclusive(|| ghidra_bsim_scan::scan_unnamed_functions(&app, &installation, session))?;
    let merged = ghidra_bsim_scan::merge_results(existing.unwrap_or_default(), scanned);
    project_storage::replace_project_identifications(&app, &project_id, &merged)?;
    ghidra_headless::emit_analysis_progress(
        &app,
        "bsim_complete",
        "Balayage BSim terminé. Les preuves ont été enregistrées dans le projet.",
        Some(100),
    );
    Ok(merged)
}

#[tauri::command]
fn compute_bsim_repetition_corroboration(
    identifications: Vec<FunctionIdentification>,
) -> std::collections::HashMap<String, usize> {
    identification_corroboration::count_bsim_repetitions(&identifications)
}

#[tauri::command]
fn get_call_graph(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    entry_address: String,
    direction: CallGraphDirection,
    max_depth: u32,
) -> Result<CallGraphNeighborhood, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its call graph."
            .to_owned()
    })?;

    call_graph::compute_neighborhood(export, &entry_address, direction, max_depth)
}

#[tauri::command]
fn get_global_strings(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<GlobalStringView>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its strings."
            .to_owned()
    })?;

    Ok(global_strings::build_global_strings_view(export))
}

#[tauri::command]
fn get_imports(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<ImportView>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its imports."
            .to_owned()
    })?;

    Ok(imports_exports::list_imports(export))
}

#[tauri::command]
fn get_external_entry_points(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<models::ghidra_export::ExternalEntryPoint>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its external entry points."
            .to_owned()
    })?;

    Ok(export.program.external_entry_points.clone())
}

#[tauri::command]
fn get_detected_types(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<Vec<models::ghidra_export::DetectedType>, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its detected types."
            .to_owned()
    })?;

    Ok(export.types.clone())
}

#[tauri::command]
fn get_program_overview(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
) -> Result<ProgramOverview, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or import a binary before requesting its overview."
            .to_owned()
    })?;

    Ok(program_overview::compute_overview(export))
}

#[tauri::command]
fn export_pdf_report(
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    destination_path: String,
) -> Result<PdfReportResult, String> {
    let export = export_state
        .lock()
        .map_err(|_| "the analysis export lock was poisoned".to_owned())?;
    let export = export.as_ref().ok_or_else(|| {
        "No analysis is loaded. Analyze or open a project before exporting a report.".to_owned()
    })?;

    report::export_pdf(export, Path::new(&destination_path))
}

#[tauri::command]
fn list_projects(app: AppHandle) -> Result<Vec<ProjectSummary>, String> {
    project_storage::list_projects(&app)
}

#[tauri::command]
fn open_project(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    id: String,
) -> Result<LoadedProject, String> {
    let (export, identifications, project) =
        project_storage::load_project_with_identifications(&app, &id)?;

    // Availability is re-tested fresh by `load_project` on every call, so
    // this never restores a session for Ghidra project files that aren't
    // actually there right now -- and never permanently forgets the
    // reference either, since `project.metadata.session` itself is left
    // untouched on disk.
    let session_to_restore = if project.session_available {
        project.metadata.session.clone()
    } else {
        None
    };

    *session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())? = session_to_restore;

    store_export(&export_state, export.clone())?;

    Ok(LoadedProject {
        export,
        identifications,
        project,
    })
}

#[tauri::command]
fn delete_project(app: AppHandle, id: String) -> Result<(), String> {
    project_storage::delete_project(&app, &id)
}

#[tauri::command]
fn rename_project(app: AppHandle, id: String, new_name: String) -> Result<ProjectMetadata, String> {
    project_storage::rename_project(&app, &id, &new_name)
}

#[tauri::command]
fn compare_projects(
    app: AppHandle,
    project_a_id: String,
    project_b_id: String,
) -> Result<ProjectComparison, String> {
    if project_a_id == project_b_id {
        return Err("Select two different saved projects to compare.".to_owned());
    }

    // Comparison is deliberately read-only: loading either side here must
    // not replace the analysis currently open in the explorer.
    let (project_a, _) = project_storage::load_project(&app, &project_a_id)?;
    let (project_b, _) = project_storage::load_project(&app, &project_b_id)?;

    Ok(comparison::compare_projects(&project_a, &project_b))
}

#[tauri::command(async)]
fn apply_function_renames(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    decompile_coordinator: tauri::State<'_, DecompileCoordinator>,
    project_id: String,
    renames: Vec<FunctionRename>,
) -> Result<ApplyRenamesResult, String> {
    let session = session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| "A live Ghidra project must be open before applying renames.".to_owned())?;

    project_storage::require_managed_session(&app, &session)?;
    let (_, saved_project) = project_storage::load_project(&app, &project_id)?;
    if !saved_project.session_available || saved_project.metadata.session.as_ref() != Some(&session)
    {
        return Err(
            "The selected saved project does not match the active Ghidra session.".to_owned(),
        );
    }

    let install_dir = ghidra_installation::load_persisted_install_dir(&app)?
        .ok_or_else(|| "No Ghidra installation is configured.".to_owned())?;
    let installation = ghidra_installation::validate_installation(&app, &install_dir)?;

    let result = decompile_coordinator
        .run_exclusive(|| ghidra_edits::run_apply_renames(&installation, &session, &renames))?;

    // The Java transaction exported the updated program before committing,
    // so the in-memory explorer and the durable local snapshot now advance
    // together with the Ghidra project.
    store_export(&export_state, result.imported.export.clone())?;
    project_storage::replace_project_export(&app, &project_id, &result.imported.export)?;

    Ok(result)
}

#[tauri::command(async)]
fn decompile_function(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    decompile_coordinator: tauri::State<'_, DecompileCoordinator>,
    entry_address: String,
) -> Result<DecompiledFunctionDetails, String> {
    let session = session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| {
            "No Ghidra analysis session is active. Analyze a binary before requesting decompiled code.".to_owned()
        })?;

    // Ghidra takes an exclusive project lock even when analyzeHeadless opens
    // the program with -readOnly. Serialize requests so rapid function
    // selections wait their turn instead of failing with LockException.
    let details = decompile_coordinator
        .run_exclusive(|| ghidra_decompile::decompile_function(&app, &session, &entry_address))?;

    // Bulk export never populates `decompiled_code` (decompilation is
    // on-demand by design), so without this write-through the stored
    // export's copy would stay frozen at "nothing decompiled yet" forever
    // -- silently making `decompiled_function_count` in the overview
    // permanently wrong instead of tracking real progress.
    if let Some(decompiled_code) = &details.decompiled_code {
        let mut export = export_state
            .lock()
            .map_err(|_| "the analysis export lock was poisoned".to_owned())?;

        if let Some(export) = export.as_mut() {
            if let Some(function) = export
                .functions
                .iter_mut()
                .find(|function| function.entry_address == entry_address)
            {
                function.decompiled_code = Some(decompiled_code.clone());
            }
        }
    }

    Ok(details)
}

#[tauri::command(async)]
fn prepare_ai_function_contexts(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    export_state: tauri::State<'_, Mutex<Option<GhidraExport>>>,
    decompile_coordinator: tauri::State<'_, DecompileCoordinator>,
    project_id: String,
    entry_addresses: Vec<String>,
) -> Result<Vec<PreparedFunctionContext>, String> {
    let session = session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| "No Ghidra analysis session is active.".to_owned())?;
    project_storage::require_managed_session(&app, &session)?;
    let (_, saved_project) = project_storage::load_project(&app, &project_id)?;
    if !saved_project.session_available || saved_project.metadata.session.as_ref() != Some(&session)
    {
        return Err("The selected project does not match the active Ghidra session.".to_owned());
    }

    let prepared = decompile_coordinator.run_exclusive(|| {
        ghidra_decompile::prepare_function_contexts(&app, &session, &entry_addresses)
    })?;

    let updated_export = {
        let mut state = export_state
            .lock()
            .map_err(|_| "the analysis export lock was poisoned".to_owned())?;
        let export = state
            .as_mut()
            .ok_or_else(|| "no analysis is currently loaded".to_owned())?;
        for item in &prepared {
            if let Some(code) = &item.decompiled_code {
                if let Some(function) = export
                    .functions
                    .iter_mut()
                    .find(|function| function.entry_address == item.entry_address)
                {
                    function.decompiled_code = Some(code.clone());
                    function.return_type = item.return_type.clone();
                    function.parameters = item.parameters.clone();
                }
            }
        }
        export.clone()
    };
    project_storage::replace_project_export(&app, &project_id, &updated_export)?;
    Ok(prepared)
}

#[tauri::command(async)]
fn disassemble_function(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    decompile_coordinator: tauri::State<'_, DecompileCoordinator>,
    entry_address: String,
) -> Result<FunctionDisassembly, String> {
    let session = session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| {
            "No Ghidra analysis session is active. Analyze a binary before requesting a disassembly listing.".to_owned()
        })?;

    // Same exclusive-project-lock reasoning as decompile_function: Ghidra
    // still takes an exclusive lock under -readOnly.
    decompile_coordinator
        .run_exclusive(|| ghidra_disassemble::disassemble_function(&app, &session, &entry_address))
}

#[tauri::command(async)]
fn disassemble_functions(
    app: AppHandle,
    session_state: tauri::State<'_, Mutex<Option<AnalysisSession>>>,
    decompile_coordinator: tauri::State<'_, DecompileCoordinator>,
    entry_addresses: Vec<String>,
) -> Result<FunctionDisassembly, String> {
    let session = session_state
        .lock()
        .map_err(|_| "the analysis session lock was poisoned".to_owned())?
        .clone()
        .ok_or_else(|| {
            "No Ghidra analysis session is active. Analyze a binary before requesting a disassembly listing.".to_owned()
        })?;

    decompile_coordinator.run_exclusive(|| {
        ghidra_disassemble::disassemble_functions(&app, &session, &entry_addresses)
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(None::<AnalysisSession>))
        .manage(Mutex::new(None::<GhidraExport>))
        .manage(services::semantic_memory::SemanticIndexCache::default())
        .manage(DecompileCoordinator::default())
        .invoke_handler(tauri::generate_handler![
            get_backend_status,
            import_ghidra_export_summary,
            import_ghidra_export_details,
            configure_ghidra_installation,
            get_ghidra_installation_status,
            get_setup_overview,
            list_bsim_corpora,
            import_bsim_corpus,
            add_bsim_reference_library,
            set_bsim_corpus_enabled,
            remove_bsim_corpus,
            list_ai_providers,
            add_ai_provider,
            set_ai_provider_enabled,
            remove_ai_provider,
            arbitrate_identification_tie,
            arbitrate_identification_ties,
            save_arbitration_result,
            get_arbitration_results,
            generate_identification_suggestion,
            generate_identification_suggestions,
            refine_identification_suggestions,
            get_semantic_analysis_order,
            save_generation_result,
            save_generation_results,
            get_generation_results,
            get_managed_setup_plan,
            install_managed_setup,
            adopt_existing_ghidra,
            analyze_binary_with_ghidra,
            scan_project_with_bsim,
            compute_bsim_repetition_corroboration,
            decompile_function,
            prepare_ai_function_contexts,
            disassemble_function,
            disassemble_functions,
            get_call_graph,
            get_global_strings,
            get_imports,
            get_external_entry_points,
            get_detected_types,
            get_program_overview,
            export_pdf_report,
            list_projects,
            open_project,
            delete_project,
            rename_project,
            compare_projects,
            apply_function_renames
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    use super::{synthesize_generation_answers, DecompileCoordinator};
    use crate::services::naming_generation::GenerationResult;

    fn generated(name: Option<&str>, confidence: u8) -> GenerationResult {
        GenerationResult {
            suggested_name: name.map(str::to_owned),
            reasoning: "raison observable".to_owned(),
            confidence,
            evidence: vec!["preuve".to_owned()],
            requested_tools: Vec::new(),
        }
    }

    #[test]
    fn generation_synthesis_groups_semantically_equivalent_names() {
        let answers = vec![
            (
                "agent A".to_owned(),
                generated(Some("open_config_file"), 74),
            ),
            ("agent B".to_owned(), generated(Some("loadConfigFile"), 70)),
            ("agent C".to_owned(), generated(Some("encrypt_buffer"), 82)),
        ];

        let result = synthesize_generation_answers("0x1", &answers, 1);

        assert!(matches!(
            result.suggested_name.as_deref(),
            Some("open_config_file" | "loadConfigFile")
        ));
        assert!(
            result.confidence < 74,
            "agent disagreement must reduce confidence"
        );
        assert_eq!(result.provider_label, "agent A + agent B + agent C");
    }

    #[test]
    fn generation_synthesis_preserves_an_explicit_no_name_result() {
        let answers = vec![
            ("agent A".to_owned(), generated(None, 0)),
            ("agent B".to_owned(), generated(None, 0)),
        ];

        let result = synthesize_generation_answers("0x2", &answers, 1);

        assert_eq!(result.suggested_name, None);
        assert_eq!(result.confidence, 0);
    }

    #[test]
    fn decompile_coordinator_serializes_operations() {
        let coordinator = Arc::new(DecompileCoordinator::default());
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let (second_started_tx, second_started_rx) = mpsc::channel();

        let first_coordinator = Arc::clone(&coordinator);
        let first = thread::spawn(move || {
            first_coordinator.run_exclusive(|| {
                first_started_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
                Ok(())
            })
        });

        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the first operation should acquire the queue");

        let second_coordinator = Arc::clone(&coordinator);
        let second = thread::spawn(move || {
            second_coordinator.run_exclusive(|| {
                second_started_tx.send(()).unwrap();
                Ok(())
            })
        });

        assert!(
            second_started_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "the second operation must wait while the first owns the queue"
        );

        release_first_tx.send(()).unwrap();
        second_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the second operation should start after the first releases the queue");

        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    }
}
