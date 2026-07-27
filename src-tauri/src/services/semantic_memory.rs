use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::models::ghidra_export::{GhidraExport, GhidraFunction};
use crate::services::call_graph;

/// Versioned, deterministic facts used by the local naming agent.  This is
/// deliberately not an LLM answer: rebuilding it from the same export must
/// always produce the same result, which makes it suitable as the stable
/// foundation of the persistent semantic memory.
pub const SEMANTIC_MEMORY_VERSION: u32 = 1;

#[derive(Debug)]
struct CachedSemanticIndex {
    fingerprint: u64,
    facts: Arc<HashMap<String, FunctionSemanticFacts>>,
}

/// Process-local cache for the immutable evidence index. It contains no model
/// answer and no filesystem state. A fingerprint over every field that can
/// affect naming invalidates it after decompilation, prototype enrichment,
/// project switching or a confirmed rename.
#[derive(Debug, Default)]
pub struct SemanticIndexCache(Mutex<Option<CachedSemanticIndex>>);

fn semantic_fingerprint(export: &GhidraExport) -> u64 {
    let mut hasher = DefaultHasher::new();
    export.program.sha256.hash(&mut hasher);
    export.functions.len().hash(&mut hasher);
    export.strings.len().hash(&mut hasher);
    export.types.len().hash(&mut hasher);
    for function in &export.functions {
        function.entry_address.hash(&mut hasher);
        function.name.hash(&mut hasher);
        function.return_type.hash(&mut hasher);
        function.decompiled_code.hash(&mut hasher);
        function.namespace.hash(&mut hasher);
        function.rtti_class_names.hash(&mut hasher);
        function.strings.hash(&mut hasher);
        function.thunk_target_address.hash(&mut hasher);
        for parameter in &function.parameters {
            parameter.name.hash(&mut hasher);
            parameter.data_type.hash(&mut hasher);
        }
        for call in &function.calls {
            call.target_address.hash(&mut hasher);
            call.target_name.hash(&mut hasher);
        }
    }
    hasher.finish()
}

impl SemanticIndexCache {
    pub fn get_or_build(
        &self,
        export: &GhidraExport,
    ) -> Result<Arc<HashMap<String, FunctionSemanticFacts>>, String> {
        let fingerprint = semantic_fingerprint(export);
        let mut cached = self
            .0
            .lock()
            .map_err(|_| "the semantic evidence cache lock was poisoned".to_owned())?;
        if let Some(existing) = cached
            .as_ref()
            .filter(|item| item.fingerprint == fingerprint)
        {
            return Ok(Arc::clone(&existing.facts));
        }
        let facts = Arc::new(build_semantic_index(export));
        *cached = Some(CachedSemanticIndex {
            fingerprint,
            facts: Arc::clone(&facts),
        });
        Ok(facts)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationTool {
    FunctionOverview,
    CallerContext,
    CalleeContext,
    TwoHopGraph,
    CrossReferences,
    StringReferences,
    TypeUsages,
    BehaviorSignals,
    NumericConstants,
    GlobalReferences,
    CallsiteArguments,
}

impl InvestigationTool {
    /// Local models occasionally vary casing or separators. Unknown tool
    /// names are ignored instead of invalidating an otherwise useful batch.
    pub fn from_wire_name(value: &str) -> Option<Self> {
        match value
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_")
            .as_str()
        {
            "function_overview" => Some(Self::FunctionOverview),
            "caller_context" => Some(Self::CallerContext),
            "callee_context" => Some(Self::CalleeContext),
            "two_hop_graph" => Some(Self::TwoHopGraph),
            "cross_references" => Some(Self::CrossReferences),
            "string_references" => Some(Self::StringReferences),
            "type_usages" => Some(Self::TypeUsages),
            "behavior_signals" => Some(Self::BehaviorSignals),
            "numeric_constants" => Some(Self::NumericConstants),
            "global_references" => Some(Self::GlobalReferences),
            "callsite_arguments" => Some(Self::CallsiteArguments),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolFinding {
    pub tool: InvestigationTool,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticNeighbor {
    pub entry_address: String,
    pub name: String,
    pub is_generic_name: bool,
    pub is_external: bool,
    pub is_thunk: bool,
    pub return_type: String,
    pub parameter_types: Vec<String>,
    pub strings: Vec<String>,
    pub imported_library: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSemanticFacts {
    pub memory_version: u32,
    pub entry_address: String,
    pub current_name: String,
    pub is_generic_name: bool,
    pub is_external: bool,
    pub is_thunk: bool,
    pub is_entry_point: bool,
    pub anchor_score: u16,
    pub caller_count: usize,
    pub callers: Vec<SemanticNeighbor>,
    pub callees: Vec<SemanticNeighbor>,
    pub unresolved_callee_addresses: Vec<String>,
    pub referenced_strings: Vec<String>,
    pub imported_symbols: Vec<String>,
    pub rtti_class_names: Vec<String>,
    /// Direct observations extracted deterministically from pseudocode. They
    /// improve the hypothesis but remain one source, never three independent
    /// proofs for confidence calibration.
    pub numeric_constants: Vec<String>,
    pub global_references: Vec<String>,
    pub incoming_callsite_arguments: Vec<String>,
    pub callsite_arguments: Vec<String>,
    pub decompiled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct DecompiledObservations {
    numeric_constants: Vec<String>,
    global_references: Vec<String>,
    callsite_arguments: Vec<String>,
}

fn push_unique_bounded(values: &mut Vec<String>, value: String, limit: usize) {
    if values.len() < limit && !value.is_empty() && !values.contains(&value) {
        values.push(value);
    }
}

fn is_numeric_constant(token: &str) -> bool {
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        return !hex.is_empty() && hex.chars().all(|character| character.is_ascii_hexdigit());
    }
    token.len() >= 2 && token.chars().all(|character| character.is_ascii_digit())
}

fn is_global_identifier(token: &str) -> bool {
    let upper = token.to_ascii_uppercase();
    upper.starts_with("DAT_")
        || upper.starts_with("_DAT_")
        || upper.starts_with("PTR_")
        || upper.starts_with("_GLOBAL")
        || upper.starts_with("QWORD_")
        || upper.starts_with("DWORD_")
        || upper.starts_with("WORD_")
        || upper.starts_with("BYTE_")
}

fn call_identifier_before(line: &str, open_parenthesis: usize) -> Option<&str> {
    let prefix = &line[..open_parenthesis];
    let start = prefix
        .char_indices()
        .rev()
        .find(|(_, character)| {
            !character.is_ascii_alphanumeric()
                && *character != '_'
                && *character != ':'
                && *character != '~'
        })
        .map_or(0, |(index, character)| index + character.len_utf8());
    let identifier = prefix[start..].trim();
    (!identifier.is_empty()).then_some(identifier)
}

fn extract_decompiled_observations(function: &GhidraFunction) -> DecompiledObservations {
    let Some(code) = function.decompiled_code.as_deref() else {
        return DecompiledObservations::default();
    };
    let mut observations = DecompiledObservations::default();
    let ignored_calls = [
        "if",
        "for",
        "while",
        "switch",
        "sizeof",
        "return",
        // Common Ghidra cast spellings: parentheses after these tokens are
        // type conversions, not calls and must not pollute call evidence.
        "void",
        "code",
        "char",
        "int",
        "uint",
        "long",
        "ulong",
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
    ];

    for raw_line in code.lines() {
        let line = raw_line.trim();
        for token in line.split(|character: char| {
            !character.is_ascii_alphanumeric() && character != '_' && character != 'x'
        }) {
            if is_numeric_constant(token) {
                push_unique_bounded(&mut observations.numeric_constants, token.to_owned(), 24);
            }
            if is_global_identifier(token) {
                push_unique_bounded(&mut observations.global_references, token.to_owned(), 24);
            }
        }
        for (index, _) in line.match_indices('(') {
            let Some(identifier) = call_identifier_before(line, index) else {
                continue;
            };
            if ignored_calls
                .iter()
                .any(|keyword| identifier.eq_ignore_ascii_case(keyword))
                || identifier == function.name
            {
                continue;
            }
            push_unique_bounded(
                &mut observations.callsite_arguments,
                bounded_fact(line, 500),
                20,
            );
        }
    }
    observations
}

fn extract_incoming_callsites(
    target: &GhidraFunction,
    caller_addresses: &HashSet<&str>,
    functions: &HashMap<&str, &GhidraFunction>,
) -> Vec<String> {
    let needle = format!("{}(", target.name);
    let mut observations = Vec::new();
    let mut sorted_callers = caller_addresses.iter().copied().collect::<Vec<_>>();
    sorted_callers.sort_unstable();
    for caller_address in sorted_callers {
        let Some(caller) = functions.get(caller_address).copied() else {
            continue;
        };
        let Some(code) = caller.decompiled_code.as_deref() else {
            continue;
        };
        for line in code
            .lines()
            .map(str::trim)
            .filter(|line| line.contains(&needle))
        {
            push_unique_bounded(
                &mut observations,
                format!(
                    "depuis {}@{} : {}",
                    caller.name,
                    caller.entry_address,
                    bounded_fact(line, 500)
                ),
                20,
            );
        }
    }
    observations
}

pub fn is_generic_function_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("FUN_")
        || upper.starts_with("SUB_")
        || upper.starts_with("LAB_")
        || upper.starts_with("THUNK_FUN_")
}

fn neighbor(function: &GhidraFunction) -> SemanticNeighbor {
    SemanticNeighbor {
        entry_address: function.entry_address.clone(),
        name: function.name.clone(),
        is_generic_name: is_generic_function_name(&function.name),
        is_external: function.is_external,
        is_thunk: function.is_thunk,
        return_type: function.return_type.clone(),
        parameter_types: function
            .parameters
            .iter()
            .map(|parameter| parameter.data_type.clone())
            .collect(),
        strings: function.strings.iter().take(8).cloned().collect(),
        imported_library: function.library.clone(),
    }
}

fn final_thunk_target<'a>(
    function: &'a GhidraFunction,
    functions: &HashMap<&str, &'a GhidraFunction>,
) -> &'a GhidraFunction {
    let mut current = function;
    let mut visited = HashSet::new();
    while current.is_thunk && visited.insert(current.entry_address.as_str()) {
        let Some(target) = current
            .thunk_target_address
            .as_deref()
            .and_then(|address| functions.get(address).copied())
        else {
            break;
        };
        current = target;
    }
    current
}

fn anchor_score(
    function: &GhidraFunction,
    caller_count: usize,
    is_entry_point: bool,
    imported_symbols: &[String],
) -> u16 {
    let mut score = 0_u16;
    if !is_generic_function_name(&function.name) {
        score += 35;
    }
    if is_entry_point || function.name.eq_ignore_ascii_case("main") {
        score += 35;
    }
    if !function.rtti_class_names.is_empty() {
        score += 25;
    }
    score += (function.strings.len().min(5) as u16) * 5;
    score += (imported_symbols.len().min(5) as u16) * 6;
    score += caller_count.min(10) as u16;
    if function.decompiled_code.is_some() {
        score += 5;
    }
    score
}

/// Builds a whole-program fact index once.  Callers are resolved through the
/// same thunk-aware call graph as the UI, so the agent sees the real function
/// behind PLT/IAT forwarding rather than an unrelated isolated stub.
pub fn build_semantic_index(export: &GhidraExport) -> HashMap<String, FunctionSemanticFacts> {
    let functions: HashMap<&str, &GhidraFunction> = export
        .functions
        .iter()
        .map(|function| (function.entry_address.as_str(), function))
        .collect();
    let callers = call_graph::build_caller_index(export);
    let entry_points: HashSet<&str> = export
        .program
        .external_entry_points
        .iter()
        .map(|entry| entry.address.as_str())
        .collect();

    export
        .functions
        .iter()
        .map(|function| {
            let observations = extract_decompiled_observations(function);
            let caller_addresses = call_graph::resolve_calling_functions(
                &callers,
                &functions,
                &function.entry_address,
            );
            let incoming_callsite_arguments =
                extract_incoming_callsites(function, &caller_addresses, &functions);
            let caller_facts = caller_addresses
                .iter()
                .filter_map(|address| functions.get(address).copied())
                .map(neighbor)
                .collect::<Vec<_>>();

            let mut callee_facts = Vec::new();
            let mut unresolved_callee_addresses = Vec::new();
            let mut imported_symbols = Vec::new();
            for call in &function.calls {
                match call
                    .target_address
                    .as_deref()
                    .and_then(|address| functions.get(address).copied())
                {
                    Some(target) => {
                        let resolved_target = final_thunk_target(target, &functions);
                        if resolved_target.is_external || resolved_target.library.is_some() {
                            imported_symbols.push(match &resolved_target.library {
                                Some(library) => {
                                    format!("{} ({library})", resolved_target.name)
                                }
                                None => resolved_target.name.clone(),
                            });
                        }
                        callee_facts.push(neighbor(target));
                    }
                    None => {
                        if let Some(address) = &call.target_address {
                            unresolved_callee_addresses.push(address.clone());
                        }
                        if !is_generic_function_name(&call.target_name) {
                            imported_symbols.push(call.target_name.clone());
                        }
                    }
                }
            }
            if let Some(target_address) = &function.thunk_target_address {
                if let Some(target) = functions.get(target_address.as_str()).copied() {
                    callee_facts.push(neighbor(target));
                }
            }
            imported_symbols.sort();
            imported_symbols.dedup();
            callee_facts.sort_by(|left, right| left.entry_address.cmp(&right.entry_address));
            callee_facts.dedup_by(|left, right| left.entry_address == right.entry_address);
            unresolved_callee_addresses.sort();
            unresolved_callee_addresses.dedup();

            let is_entry_point = entry_points.contains(function.entry_address.as_str());
            let facts = FunctionSemanticFacts {
                memory_version: SEMANTIC_MEMORY_VERSION,
                entry_address: function.entry_address.clone(),
                current_name: function.name.clone(),
                is_generic_name: is_generic_function_name(&function.name),
                is_external: function.is_external,
                is_thunk: function.is_thunk,
                is_entry_point,
                anchor_score: anchor_score(
                    function,
                    caller_facts.len(),
                    is_entry_point,
                    &imported_symbols,
                ),
                caller_count: caller_facts.len(),
                callers: caller_facts,
                callees: callee_facts,
                unresolved_callee_addresses,
                referenced_strings: function.strings.clone(),
                imported_symbols,
                rtti_class_names: function.rtti_class_names.clone(),
                numeric_constants: observations.numeric_constants,
                global_references: observations.global_references,
                incoming_callsite_arguments,
                callsite_arguments: observations.callsite_arguments,
                decompiled: function.decompiled_code.is_some(),
            };
            (function.entry_address.clone(), facts)
        })
        .collect()
}

/// Stable analysis order: high-signal anchor functions first, then their
/// lower-signal neighbours.  Address is the deterministic tie breaker so a
/// restart produces exactly the same queue.
pub fn rank_for_semantic_analysis(export: &GhidraExport) -> Vec<String> {
    let mut facts = build_semantic_index(export)
        .into_values()
        .filter(|facts| !facts.is_external && !facts.is_thunk)
        .collect::<Vec<_>>();
    facts.sort_by(|left, right| {
        right
            .anchor_score
            .cmp(&left.anchor_score)
            .then_with(|| right.caller_count.cmp(&left.caller_count))
            .then_with(|| left.entry_address.cmp(&right.entry_address))
    });
    facts.into_iter().map(|facts| facts.entry_address).collect()
}

fn compact_function(function: &GhidraFunction) -> String {
    let prototype = format!(
        "{} {}({})",
        function.return_type,
        function.name,
        function
            .parameters
            .iter()
            .map(|parameter| format!("{} {}", parameter.data_type, parameter.name))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let code = function
        .decompiled_code
        .as_deref()
        .map(|value| value.chars().take(2_000).collect::<String>())
        .unwrap_or_else(|| "[pseudocode indisponible]".to_owned());
    format!(
        "{} @ {}\nprototype: {}\nchaines: {}\npseudocode:\n{}",
        function.name,
        function.entry_address,
        prototype,
        function
            .strings
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(" | "),
        code
    )
}

fn bounded_fact(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut bounded = value.chars().take(max_chars).collect::<String>();
    bounded.push_str("...");
    bounded
}

fn behavior_signals(function: &GhidraFunction) -> String {
    let Some(code) = function.decompiled_code.as_deref() else {
        return "Pseudocode indisponible : aucun signal comportemental extrait.".to_owned();
    };
    let mut findings = Vec::new();
    for raw_line in code.lines() {
        let line = raw_line.trim();
        let lower = line.to_ascii_lowercase();
        let category = if lower.starts_with("if ") || lower.starts_with("if(") {
            Some("branche")
        } else if lower.starts_with("for ")
            || lower.starts_with("for(")
            || lower.starts_with("while ")
            || lower.starts_with("while(")
        {
            Some("boucle")
        } else if lower.starts_with("return") {
            Some("retour")
        } else if lower.contains("malloc(")
            || lower.contains("calloc(")
            || lower.contains("realloc(")
            || lower.contains("operator_new")
        {
            Some("allocation")
        } else if lower.contains("memcpy(")
            || lower.contains("memmove(")
            || lower.contains("memset(")
            || lower.contains("strcpy(")
            || lower.contains("strlen(")
        {
            Some("memoire/chaine")
        } else if line.contains("DAT_") && line.contains('=') {
            Some("ecriture_etat")
        } else if line.contains('(') && line.contains(')') && line.ends_with(';') {
            Some("appel")
        } else {
            None
        };
        if let Some(category) = category {
            findings.push(format!("{category}: {}", bounded_fact(line, 500)));
        }
        if findings.len() == 36 {
            break;
        }
    }
    if findings.is_empty() {
        "Aucun signal comportemental distinct extrait du pseudocode.".to_owned()
    } else {
        findings.join("\n")
    }
}

/// Executes a small, read-only investigation selected by the model. This
/// adopts ReVa's useful tool-selection pattern inside our existing process:
/// no MCP listener, arbitrary Python execution, file editing or network call.
/// Results are bounded here rather than relying on the prompt to control size.
pub fn execute_investigation_tools(
    export: &GhidraExport,
    entry_address: &str,
    requested: &[InvestigationTool],
) -> Result<Vec<ToolFinding>, String> {
    let functions: HashMap<&str, &GhidraFunction> = export
        .functions
        .iter()
        .map(|function| (function.entry_address.as_str(), function))
        .collect();
    let function = functions
        .get(entry_address)
        .copied()
        .ok_or_else(|| format!("no function exists at address '{entry_address}'"))?;
    let observations = extract_decompiled_observations(function);
    let caller_index = call_graph::build_caller_index(export);
    let mut unique_tools = Vec::new();
    for tool in requested.iter().take(2) {
        if !unique_tools.contains(tool) {
            unique_tools.push(*tool);
        }
    }

    unique_tools
        .into_iter()
        .map(|tool| {
            let content = match tool {
                InvestigationTool::FunctionOverview => {
                    let caller_count = caller_index
                        .get(entry_address)
                        .map_or(0, |callers| callers.len());
                    let prototype = format!(
                        "{} {}({})",
                        function.return_type,
                        function.name,
                        function
                            .parameters
                            .iter()
                            .map(|parameter| parameter.data_type.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    format!(
                        "prototype: {prototype}\nexterne: {}\nthunk: {}\nappelants directs: {caller_count}\nappels sortants: {}\nchaines: {}\nclasses RTTI: {}",
                        function.is_external,
                        function.is_thunk,
                        function.calls.len(),
                        function.strings.iter().take(12).map(|value| bounded_fact(value, 300)).collect::<Vec<_>>().join(" | "),
                        function.rtti_class_names.iter().take(12).map(|value| bounded_fact(value, 300)).collect::<Vec<_>>().join(" | ")
                    )
                }
                InvestigationTool::CallerContext => {
                    let callers = call_graph::resolve_calling_functions(
                        &caller_index,
                        &functions,
                        entry_address,
                    );
                    let rendered = callers
                        .into_iter()
                        .filter_map(|address| functions.get(address).copied())
                        .take(4)
                        .map(compact_function)
                        .collect::<Vec<_>>();
                    if rendered.is_empty() {
                        "Aucun appelant resolu.".to_owned()
                    } else {
                        rendered.join("\n\n--- appelant suivant ---\n\n")
                    }
                }
                InvestigationTool::CalleeContext => {
                    let rendered = function
                        .calls
                        .iter()
                        .filter_map(|call| {
                            call.target_address
                                .as_deref()
                                .and_then(|address| functions.get(address).copied())
                        })
                        .take(6)
                        .map(compact_function)
                        .collect::<Vec<_>>();
                    if rendered.is_empty() {
                        "Aucune fonction appelee resolue.".to_owned()
                    } else {
                        rendered.join("\n\n--- fonction appelee suivante ---\n\n")
                    }
                }
                InvestigationTool::TwoHopGraph => {
                    let graph = call_graph::compute_neighborhood(
                        export,
                        entry_address,
                        call_graph::CallGraphDirection::Both,
                        2,
                    )?;
                    graph
                        .nodes
                        .iter()
                        .take(40)
                        .map(|node| {
                            let kind = if node.is_external {
                                "externe"
                            } else if node.is_thunk {
                                "thunk"
                            } else {
                                "interne"
                            };
                            format!(
                                "niveau {}: {} @ {} ({})",
                                node.depth, node.name, node.entry_address, kind
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
                InvestigationTool::CrossReferences => {
                    let mut lines = call_graph::resolve_calling_functions(
                        &caller_index,
                        &functions,
                        entry_address,
                    )
                    .into_iter()
                    .filter_map(|address| functions.get(address).copied())
                    .take(20)
                    .map(|caller| {
                        format!("appel entrant: {} @ {}", caller.name, caller.entry_address)
                    })
                    .collect::<Vec<_>>();
                    for string in &export.strings {
                        for reference in string.references.iter().filter(|reference| {
                            reference.function_address.as_deref() == Some(entry_address)
                        }) {
                            lines.push(format!(
                                "reference chaine: {} @ instruction {}",
                                bounded_fact(&string.value, 300), reference.instruction_address
                            ));
                            if lines.len() == 30 {
                                break;
                            }
                        }
                        if lines.len() == 30 {
                            break;
                        }
                    }
                    if let Some(target) = &function.thunk_target_address {
                        lines.push(format!("cible thunk: {target}"));
                    }
                    if lines.is_empty() {
                        "Aucune reference croisee attribuee a cette fonction.".to_owned()
                    } else {
                        lines.join("\n")
                    }
                }
                InvestigationTool::StringReferences => {
                    let mut lines = Vec::new();
                    for string in &export.strings {
                        let references = string
                            .references
                            .iter()
                            .filter(|reference| {
                                reference.function_address.as_deref() == Some(entry_address)
                            })
                            .map(|reference| reference.instruction_address.clone())
                            .collect::<Vec<_>>();
                        if !references.is_empty() {
                            lines.push(format!(
                                "{} @ {} utilisee aux instructions {}",
                                string.value,
                                string.address,
                                references.join(", ")
                            ));
                        }
                    }
                    if lines.is_empty() {
                        "Aucune reference de chaine attribuee a cette fonction.".to_owned()
                    } else {
                        lines.into_iter().take(30).collect::<Vec<_>>().join("\n")
                    }
                }
                InvestigationTool::TypeUsages => {
                    let lines = export
                        .types
                        .iter()
                        .filter_map(|detected_type| {
                            let usages = detected_type
                                .usages
                                .iter()
                                .filter(|usage| {
                                    usage.function_address.as_deref() == Some(entry_address)
                                })
                                .count();
                            (usages > 0).then(|| {
                                format!(
                                    "{} ({:?}, taille {:?}) : {} usage(s) dans la signature",
                                    detected_type.name,
                                    detected_type.kind,
                                    detected_type.size,
                                    usages
                                )
                            })
                        })
                        .take(30)
                        .collect::<Vec<_>>();
                    if lines.is_empty() {
                        "Aucun type structure reference dans la signature.".to_owned()
                    } else {
                        lines.join("\n")
                    }
                }
                InvestigationTool::BehaviorSignals => behavior_signals(function),
                InvestigationTool::NumericConstants => {
                    if observations.numeric_constants.is_empty() {
                        "Aucune constante numerique significative extraite.".to_owned()
                    } else {
                        observations.numeric_constants.join(", ")
                    }
                }
                InvestigationTool::GlobalReferences => {
                    if observations.global_references.is_empty() {
                        "Aucun acces global nomme extrait du pseudocode.".to_owned()
                    } else {
                        observations.global_references.join(", ")
                    }
                }
                InvestigationTool::CallsiteArguments => {
                    let caller_addresses = call_graph::resolve_calling_functions(
                        &caller_index,
                        &functions,
                        entry_address,
                    );
                    let incoming =
                        extract_incoming_callsites(function, &caller_addresses, &functions);
                    if incoming.is_empty() && observations.callsite_arguments.is_empty() {
                        "Aucun appel avec arguments observable dans le pseudocode.".to_owned()
                    } else {
                        incoming
                            .into_iter()
                            .chain(observations.callsite_arguments.iter().cloned())
                            .take(30)
                            .collect::<Vec<_>>()
                            .join("\n")
                    }
                }
            };
            Ok(ToolFinding { tool, content })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_export::GhidraExport;

    fn fauxware() -> GhidraExport {
        GhidraExport::parse_and_validate(include_str!(
            "../../tests/fixtures/real-fauxware-export-v2.json"
        ))
        .expect("the committed real fixture must stay valid")
    }

    #[test]
    fn generic_name_detection_is_deliberately_narrow() {
        assert!(is_generic_function_name("FUN_00401000"));
        assert!(is_generic_function_name("sub_140001000"));
        assert!(!is_generic_function_name("authenticate"));
        assert!(!is_generic_function_name("NtCurrentTeb"));
    }

    #[test]
    fn real_fauxware_context_connects_main_to_meaningful_callees() {
        let index = build_semantic_index(&fauxware());
        let main = &index["0x40071d"];
        let callee_names = main
            .callees
            .iter()
            .map(|callee| callee.name.as_str())
            .collect::<Vec<_>>();
        assert!(callee_names.contains(&"authenticate"));
        assert!(main
            .imported_symbols
            .iter()
            .any(|name| name.contains("read")));
        assert!(main.anchor_score > index["0x400500"].anchor_score);
    }

    #[test]
    fn real_fauxware_authenticate_keeps_strings_and_callers_as_facts() {
        let index = build_semantic_index(&fauxware());
        let authenticate = &index["0x400664"];
        assert!(authenticate
            .referenced_strings
            .iter()
            .any(|value| value == "SOSNEAKY"));
        assert!(authenticate
            .callers
            .iter()
            .any(|caller| caller.name == "main"));
        assert!(authenticate
            .imported_symbols
            .iter()
            .any(|name| name.contains("strcmp")));
    }

    #[test]
    fn ranking_is_deterministic_and_places_main_before_anonymous_leaf_code() {
        let export = fauxware();
        let first = rank_for_semantic_analysis(&export);
        let second = rank_for_semantic_analysis(&export);
        assert_eq!(first, second);
        let main = first
            .iter()
            .position(|address| address == "0x40071d")
            .unwrap();
        let anonymous = first
            .iter()
            .position(|address| address == "0x400500")
            .unwrap();
        assert!(main < anonymous);
    }

    #[test]
    fn investigation_tools_return_bounded_real_context() {
        let export = fauxware();
        let findings = execute_investigation_tools(
            &export,
            "0x400664",
            &[
                InvestigationTool::CallerContext,
                InvestigationTool::StringReferences,
                InvestigationTool::TypeUsages,
            ],
        )
        .expect("read-only tools should execute");
        assert_eq!(findings.len(), 2, "the per-turn tool budget is enforced");
        assert!(findings[0].content.contains("main"));
        assert!(findings[1].content.contains("SOSNEAKY"));
    }

    #[test]
    fn reva_inspired_tools_expose_facts_without_executing_code() {
        let export = fauxware();
        let findings = execute_investigation_tools(
            &export,
            "0x400664",
            &[
                InvestigationTool::FunctionOverview,
                InvestigationTool::CrossReferences,
            ],
        )
        .expect("read-only overview and cross-reference tools should execute");
        assert!(findings[0].content.contains("prototype:"));
        assert!(findings[1].content.contains("appel entrant: main"));
    }

    #[test]
    fn behavior_signals_keep_only_bounded_observable_lines() {
        let mut function = fauxware()
            .functions
            .into_iter()
            .find(|function| function.entry_address == "0x400664")
            .expect("authenticate exists in the fixture");
        function.decompiled_code = Some(
            "void authenticate(void) {\nif (allowed) {\nprintf(\"ok\");\n}\nreturn;\n}".to_owned(),
        );
        let signals = behavior_signals(&function);
        assert!(signals.contains("branche: if (allowed)"));
        assert!(signals.contains("appel: printf"));
        assert!(signals.contains("retour: return"));
    }

    #[test]
    fn deterministic_observations_extract_constants_globals_and_call_arguments() {
        let mut function = fauxware()
            .functions
            .into_iter()
            .find(|function| function.entry_address == "0x400664")
            .expect("authenticate exists in the fixture");
        function.decompiled_code = Some(
            "void authenticate(char *name) {\nDAT_0040a010 = 0x2a;\nread(0, name, 64);\nif (strlen(name) == 16) return;\n}"
                .to_owned(),
        );
        let observations = extract_decompiled_observations(&function);
        assert!(observations.numeric_constants.contains(&"0x2a".to_owned()));
        assert!(observations.numeric_constants.contains(&"64".to_owned()));
        assert!(observations
            .global_references
            .contains(&"DAT_0040a010".to_owned()));
        assert!(observations
            .callsite_arguments
            .iter()
            .any(|line| line.contains("read(0, name, 64)")));
        assert!(observations
            .callsite_arguments
            .iter()
            .any(|line| line.contains("strlen(name)")));
    }

    #[test]
    fn every_new_tool_name_has_a_strict_wire_mapping() {
        assert_eq!(
            InvestigationTool::from_wire_name("numeric-constants"),
            Some(InvestigationTool::NumericConstants)
        );
        assert_eq!(
            InvestigationTool::from_wire_name("global references"),
            Some(InvestigationTool::GlobalReferences)
        );
        assert_eq!(
            InvestigationTool::from_wire_name("callsite_arguments"),
            Some(InvestigationTool::CallsiteArguments)
        );
    }

    #[test]
    fn semantic_index_observes_arguments_from_a_decompiled_caller() {
        let mut export = fauxware();
        export
            .functions
            .iter_mut()
            .find(|function| function.name == "main")
            .expect("main exists")
            .decompiled_code = Some("authenticate(username, password);".to_owned());
        let index = build_semantic_index(&export);
        assert!(index["0x400664"]
            .incoming_callsite_arguments
            .iter()
            .any(|line| line.contains("authenticate(username, password)")));
    }

    #[test]
    fn semantic_cache_reuses_and_invalidates_indexes() {
        let cache = SemanticIndexCache::default();
        let mut export = fauxware();
        let first = cache.get_or_build(&export).expect("first index");
        let reused = cache.get_or_build(&export).expect("cached index");
        assert!(Arc::ptr_eq(&first, &reused));

        export
            .functions
            .iter_mut()
            .find(|function| function.entry_address == "0x400664")
            .expect("authenticate exists")
            .decompiled_code = Some("return 42;".to_owned());
        let rebuilt = cache.get_or_build(&export).expect("rebuilt index");
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert!(rebuilt["0x400664"]
            .numeric_constants
            .contains(&"42".to_owned()));
    }
}
