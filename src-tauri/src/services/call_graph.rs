use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::models::ghidra_export::{GhidraExport, GhidraFunction};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallGraphDirection {
    Outgoing,
    Incoming,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CallGraphNode {
    pub entry_address: String,
    pub name: String,
    pub is_external: bool,
    pub is_thunk: bool,
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CallGraphEdge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CallGraphNeighborhood {
    pub root_address: String,
    pub direction: CallGraphDirection,
    pub requested_max_depth: u32,
    pub depth_reached: u32,
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
}

// Maps a function's address to the addresses of every function whose `calls`
// resolves to it. No such reverse lookup exists anywhere else: the export
// only carries outgoing edges per function.
//
// Also indexes each thunk's `thunk_target_address` as if it were an
// outgoing call: a thunk's body is typically a jump, not a call
// instruction, so Ghidra's own `calls` list is empty for it even though it
// genuinely redirects to that target. Without this, both the call graph
// and import caller-resolution would see a dead end at every thunk.
pub fn build_caller_index(export: &GhidraExport) -> HashMap<&str, Vec<&str>> {
    let mut index: HashMap<&str, Vec<&str>> = HashMap::new();

    for function in &export.functions {
        for call in &function.calls {
            if let Some(target_address) = &call.target_address {
                index
                    .entry(target_address.as_str())
                    .or_default()
                    .push(function.entry_address.as_str());
            }
        }

        if let Some(thunk_target_address) = &function.thunk_target_address {
            index
                .entry(thunk_target_address.as_str())
                .or_default()
                .push(function.entry_address.as_str());
        }
    }

    index
}

// Every distinct *real* (non-thunk) function that ends up calling `start`,
// walking backwards over `caller_index`. A caller that is itself a thunk is
// never counted -- the walk continues past it to find its own callers
// instead, since a thunk chain can be several hops deep (a PLT stub
// redirecting to a GOT-resolved stub, for instance). This is deliberately
// "distinct calling functions", not "call sites": the same function calling
// `start` from three different instructions still counts once, and a
// thunk redirect is never conflated with a real caller. A `visited` set
// guards against cycles (a thunk chain that loops back on itself), which
// simply yield no callers along that path rather than looping forever.
pub fn resolve_calling_functions<'a>(
    caller_index: &HashMap<&'a str, Vec<&'a str>>,
    function_index: &HashMap<&'a str, &'a GhidraFunction>,
    start: &'a str,
) -> HashSet<&'a str> {
    let mut callers: HashSet<&str> = HashSet::new();
    let mut visited: HashSet<&str> = HashSet::new();
    visited.insert(start);

    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(start);

    while let Some(address) = queue.pop_front() {
        let Some(direct_callers) = caller_index.get(address) else {
            continue;
        };

        for &caller in direct_callers {
            if !visited.insert(caller) {
                continue;
            }

            let is_thunk = function_index
                .get(caller)
                .is_some_and(|function| function.is_thunk);

            if is_thunk {
                queue.push_back(caller);
            } else {
                callers.insert(caller);
            }
        }
    }

    callers
}

// Breadth-first search bounded to `max_depth` hops from `root_address`, in
// the requested direction. Deliberately not "the whole program graph": real
// binaries have thousands of functions, so the mockup's own graph view
// scopes to one selected function with a depth/direction control, not a
// single all-nodes rendering.
pub fn compute_neighborhood(
    export: &GhidraExport,
    root_address: &str,
    direction: CallGraphDirection,
    max_depth: u32,
) -> Result<CallGraphNeighborhood, String> {
    let function_index: HashMap<&str, &GhidraFunction> = export
        .functions
        .iter()
        .map(|function| (function.entry_address.as_str(), function))
        .collect();

    if !function_index.contains_key(root_address) {
        return Err(format!("no function exists at address {root_address}"));
    }

    let caller_index = build_caller_index(export);

    let mut depths: HashMap<String, u32> = HashMap::new();
    depths.insert(root_address.to_owned(), 0);

    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(root_address.to_owned());

    let mut seen_edges: HashSet<(String, String)> = HashSet::new();
    let mut edges: Vec<CallGraphEdge> = Vec::new();
    let mut depth_reached = 0u32;

    while let Some(address) = queue.pop_front() {
        let depth = depths[&address];
        depth_reached = depth_reached.max(depth);

        if depth >= max_depth {
            continue;
        }

        let mut touching_edges: Vec<(String, String)> = Vec::new();

        if matches!(
            direction,
            CallGraphDirection::Outgoing | CallGraphDirection::Both
        ) {
            if let Some(function) = function_index.get(address.as_str()) {
                for call in &function.calls {
                    if let Some(target_address) = &call.target_address {
                        // A resolved call target address that isn't itself an
                        // exported function would be a data-integrity
                        // problem upstream; skip it rather than fabricate a
                        // node for it.
                        if function_index.contains_key(target_address.as_str()) {
                            touching_edges.push((address.clone(), target_address.clone()));
                        }
                    }
                }

                // A thunk's redirection never appears in `calls` (see
                // `build_caller_index`), so it has to be added explicitly
                // here too, or a thunk node would show zero outgoing edges
                // even though it genuinely redirects somewhere.
                if let Some(thunk_target_address) = &function.thunk_target_address {
                    if function_index.contains_key(thunk_target_address.as_str()) {
                        touching_edges.push((address.clone(), thunk_target_address.clone()));
                    }
                }
            }
        }

        if matches!(
            direction,
            CallGraphDirection::Incoming | CallGraphDirection::Both
        ) {
            if let Some(callers) = caller_index.get(address.as_str()) {
                for caller in callers {
                    touching_edges.push(((*caller).to_owned(), address.clone()));
                }
            }
        }

        for (from, to) in touching_edges {
            if !seen_edges.insert((from.clone(), to.clone())) {
                continue;
            }

            let other = if from == address {
                to.clone()
            } else {
                from.clone()
            };

            if !depths.contains_key(&other) {
                depths.insert(other.clone(), depth + 1);
                queue.push_back(other);
            }

            edges.push(CallGraphEdge { from, to });
        }
    }

    let mut nodes: Vec<CallGraphNode> = depths
        .iter()
        .map(|(address, depth)| {
            let function = function_index[address.as_str()];

            CallGraphNode {
                entry_address: function.entry_address.clone(),
                name: function.name.clone(),
                is_external: function.is_external,
                is_thunk: function.is_thunk,
                depth: *depth,
            }
        })
        .collect();

    nodes.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then_with(|| a.entry_address.cmp(&b.entry_address))
    });

    Ok(CallGraphNeighborhood {
        root_address: root_address.to_owned(),
        direction,
        requested_max_depth: max_depth,
        depth_reached,
        nodes,
        edges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ghidra_export::{
        Endianness, FunctionCall, FunctionParameter, ProgramMetadata,
    };

    fn function(entry_address: &str, name: &str, calls: &[&str]) -> GhidraFunction {
        GhidraFunction {
            entry_address: entry_address.to_owned(),
            name: name.to_owned(),
            return_type: "void".to_owned(),
            parameters: Vec::<FunctionParameter>::new(),
            is_external: false,
            is_thunk: false,
            decompiled_code: None,
            calls: calls
                .iter()
                .map(|target| FunctionCall {
                    target_address: Some((*target).to_owned()),
                    target_name: format!("callee-{target}"),
                })
                .collect(),
            strings: Vec::new(),
            library: None,
            thunk_target_address: None,
            namespace: None,
        }
    }

    fn external_function(entry_address: &str, name: &str) -> GhidraFunction {
        GhidraFunction {
            is_external: true,
            ..function(entry_address, name, &[])
        }
    }

    fn thunk_function(entry_address: &str, name: &str, target: &str) -> GhidraFunction {
        GhidraFunction {
            is_thunk: true,
            thunk_target_address: Some(target.to_owned()),
            ..function(entry_address, name, &[])
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
    fn caller_index_inverts_resolved_calls_only() {
        let data = export(vec![
            function("0x1", "a", &["0x2"]),
            function("0x2", "b", &[]),
        ]);

        let index = build_caller_index(&data);

        assert_eq!(index.get("0x2"), Some(&vec!["0x1"]));
        assert_eq!(index.get("0x1"), None);
    }

    #[test]
    fn caller_index_indexes_thunk_targets_as_callers() {
        // A thunk's body is a jump, not a call: its own `calls` list is
        // empty, so the only way its redirection is visible is via
        // `thunk_target_address`.
        let data = export(vec![
            thunk_function("0x1", "strcmp", "0x2"),
            external_function("0x2", "strcmp"),
        ]);

        let index = build_caller_index(&data);

        assert_eq!(index.get("0x2"), Some(&vec!["0x1"]));
    }

    #[test]
    fn outgoing_neighborhood_follows_a_thunk_with_no_calls() {
        let data = export(vec![
            thunk_function("0x1", "strcmp", "0x2"),
            external_function("0x2", "strcmp"),
        ]);

        let result = compute_neighborhood(&data, "0x1", CallGraphDirection::Outgoing, 1).unwrap();

        assert_eq!(result.edges.len(), 1);
        assert_eq!(
            result.edges[0],
            CallGraphEdge {
                from: "0x1".to_owned(),
                to: "0x2".to_owned(),
            }
        );
    }

    #[test]
    fn linear_chain_outgoing_respects_depth_limit() {
        let data = export(vec![
            function("0x1", "a", &["0x2"]),
            function("0x2", "b", &["0x3"]),
            function("0x3", "c", &[]),
        ]);

        let result = compute_neighborhood(&data, "0x1", CallGraphDirection::Outgoing, 1).unwrap();

        assert_eq!(result.depth_reached, 1);
        let addresses: Vec<&str> = result
            .nodes
            .iter()
            .map(|node| node.entry_address.as_str())
            .collect();
        assert_eq!(addresses, vec!["0x1", "0x2"]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].from, "0x1");
        assert_eq!(result.edges[0].to, "0x2");
    }

    #[test]
    fn branching_tree_outgoing_reaches_every_child() {
        let data = export(vec![
            function("0x1", "a", &["0x2", "0x3"]),
            function("0x2", "b", &[]),
            function("0x3", "c", &[]),
        ]);

        let result = compute_neighborhood(&data, "0x1", CallGraphDirection::Outgoing, 2).unwrap();

        let addresses: HashSet<&str> = result
            .nodes
            .iter()
            .map(|node| node.entry_address.as_str())
            .collect();
        assert_eq!(addresses, HashSet::from(["0x1", "0x2", "0x3"]));
        assert_eq!(result.edges.len(), 2);
    }

    #[test]
    fn cycle_terminates_and_reports_a_single_edge_pair() {
        let data = export(vec![
            function("0x1", "a", &["0x2"]),
            function("0x2", "b", &["0x1"]),
        ]);

        let result = compute_neighborhood(&data, "0x1", CallGraphDirection::Outgoing, 5).unwrap();

        assert_eq!(result.nodes.len(), 2);
        assert_eq!(result.edges.len(), 2);
        assert!(result.depth_reached <= 5);
    }

    #[test]
    fn self_loop_produces_exactly_one_edge() {
        let data = export(vec![function("0x1", "a", &["0x1"])]);

        let result = compute_neighborhood(&data, "0x1", CallGraphDirection::Outgoing, 3).unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert_eq!(
            result.edges,
            vec![CallGraphEdge {
                from: "0x1".to_owned(),
                to: "0x1".to_owned(),
            }]
        );
    }

    #[test]
    fn external_leaf_function_is_included_with_no_further_expansion() {
        let mut functions = vec![function("0x1", "a", &["0x2"])];
        functions.push(external_function("0x2", "CreateFileA"));
        let data = export(functions);

        let result = compute_neighborhood(&data, "0x1", CallGraphDirection::Outgoing, 3).unwrap();

        let external_node = result
            .nodes
            .iter()
            .find(|node| node.entry_address == "0x2")
            .expect("the external function should be included");
        assert!(external_node.is_external);
        assert_eq!(result.edges.len(), 1);
    }

    #[test]
    fn incoming_direction_walks_callers() {
        let data = export(vec![
            function("0x1", "a", &["0x3"]),
            function("0x2", "b", &["0x3"]),
            function("0x3", "c", &[]),
        ]);

        let result = compute_neighborhood(&data, "0x3", CallGraphDirection::Incoming, 1).unwrap();

        let addresses: HashSet<&str> = result
            .nodes
            .iter()
            .map(|node| node.entry_address.as_str())
            .collect();
        assert_eq!(addresses, HashSet::from(["0x1", "0x2", "0x3"]));
        assert_eq!(result.edges.len(), 2);
    }

    #[test]
    fn both_direction_reaches_callers_and_callees() {
        let data = export(vec![
            function("0x1", "a", &["0x2"]),
            function("0x2", "b", &["0x3"]),
            function("0x3", "c", &[]),
        ]);

        let result = compute_neighborhood(&data, "0x2", CallGraphDirection::Both, 1).unwrap();

        let addresses: HashSet<&str> = result
            .nodes
            .iter()
            .map(|node| node.entry_address.as_str())
            .collect();
        assert_eq!(addresses, HashSet::from(["0x1", "0x2", "0x3"]));
    }

    #[test]
    fn unknown_root_address_is_rejected() {
        let data = export(vec![function("0x1", "a", &[])]);

        let error = compute_neighborhood(&data, "0x9", CallGraphDirection::Outgoing, 1)
            .expect_err("an unknown root address should be rejected");

        assert!(error.contains("0x9"));
    }
}
