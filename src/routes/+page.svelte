<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open, save } from "@tauri-apps/plugin-dialog";
  import SetupAssistant from "$lib/SetupAssistant.svelte";
  import ProgressRing from "$lib/ProgressRing.svelte";

  interface GhidraImportSummary {
    function_count: number;
    external_function_count: number;
    decompiled_function_count: number;
    call_count: number;
    string_count: number;
  }

  type ExternalEntryPointKind = "function" | "data" | "unknown";

  interface ExternalEntryPoint {
    address: string;
    name: string | null;
    kind: ExternalEntryPointKind;
  }

  interface ProgramMetadata {
  name: string;
  sha256: string;
  format: string;
  architecture: string;
  endianness: "little" | "big";
  image_base: string;
  external_entry_points: ExternalEntryPoint[];
  required_libraries: string[];
}

interface FunctionParameter {
  name: string;
  data_type: string;
}

interface FunctionCall {
  target_address: string | null;
  target_name: string;
}

interface GhidraFunction {
  entry_address: string;
  name: string;
  return_type: string;
  parameters: FunctionParameter[];
  is_external: boolean;
  is_thunk: boolean;
  decompiled_code: string | null;
  calls: FunctionCall[];
  strings: string[];
  library: string | null;
  thunk_target_address: string | null;
  namespace: string | null;
}

interface GhidraExport {
  schema_version: number;
  program: ProgramMetadata;
  functions: GhidraFunction[];
}

interface ImportedGhidraExport {
  export: GhidraExport;
  summary: GhidraImportSummary;
}

interface AnalysisSession {
  project_dir: string;
  project_name: string;
  program_path_in_project: string;
}

interface ProjectMetadata {
  id: string;
  name: string;
  created_at_unix_seconds: number;
  // The permanent reference to this project's original Ghidra analysis,
  // if it has one -- present for any automatic analysis, even if its
  // Ghidra project files are currently unreachable. Only ever null for a
  // project that never had one to begin with (a manual JSON import). See
  // `session_available` on ProjectSummary for whether it currently works.
  session: AnalysisSession | null;
  program_name: string;
  program_format: string;
  program_architecture: string;
  function_count: number;
}

// What the backend actually returns for listing/opening a project:
// `session`'s presence is a permanent fact, but `session_available` is
// re-tested fresh every time (never cached) -- a project can go from
// "live" to "unavailable" and back to "live" again across opens, e.g. if
// its Ghidra project sits on a drive that gets unplugged and reconnected.
interface ProjectSummary extends ProjectMetadata {
  session_available: boolean;
}

interface LoadedProject {
  export: GhidraExport;
  identifications: FunctionIdentification[] | null;
  project: ProjectSummary;
}

interface GhidraInstallation {
  install_dir: string;
  version_label: string;
  extensions_dir: string;
}

type GhidraInstallationStatus =
  | { status: "not_configured" }
  | { status: "invalid"; install_dir: string; reason: string }
  | { status: "valid"; installation: GhidraInstallation };

interface DecompiledFunctionDetails {
  decompiled_code: string | null;
  return_type: string;
  parameters: FunctionParameter[];
  calling_convention: string;
  bsim: BsimQueryResult;
}

interface BsimCandidate {
  name: string;
  executable: string;
  similarity: number;
  significance: number;
}

interface BsimQueryResult {
  status: "available" | "unavailable" | "error";
  matches: BsimCandidate[];
  message: string | null;
}

interface FidCandidate {
  name: string;
  library_family: string;
  library_version: string;
  library_variant: string;
  overall_score: number;
  match_mode: string;
}

interface FunctionIdentification {
  entry_address: string;
  candidates: FidCandidate[];
}

type CallGraphDirection = "outgoing" | "incoming" | "both";

interface CallGraphNode {
  entry_address: string;
  name: string;
  is_external: boolean;
  is_thunk: boolean;
  depth: number;
}

interface CallGraphEdge {
  from: string;
  to: string;
}

interface CallGraphNeighborhood {
  root_address: string;
  direction: CallGraphDirection;
  requested_max_depth: number;
  depth_reached: number;
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
}

interface AutomaticAnalysisResult {
  imported: ImportedGhidraExport;
  identifications: FunctionIdentification[];
  saved_project: ProjectMetadata | null;
}

interface ReferencingFunction {
  entry_address: string;
  name: string;
}

interface GlobalStringView {
  address: string;
  value: string;
  reference_count: number;
  referencing_functions: ReferencingFunction[];
}

interface ImportView {
  entry_address: string;
  name: string;
  library: string | null;
  used_by_function_count: number;
}

type DetectedTypeKind = "struct" | "union" | "enum" | "typedef";

interface TypeField {
  name: string | null;
  data_type: string;
  offset: number;
}

interface EnumValue {
  name: string;
  value: number;
}

type TypeUsageKind = "function_parameter" | "function_return" | "global_data";

interface TypeUsage {
  kind: TypeUsageKind;
  function_address: string | null;
  function_name: string | null;
  parameter_name: string | null;
  data_address: string | null;
  data_label: string | null;
}

interface DetectedType {
  name: string;
  kind: DetectedTypeKind;
  category: string;
  size: number | null;
  is_opaque: boolean;
  is_anonymous: boolean;
  fields: TypeField[];
  enum_values: EnumValue[];
  target_type_name: string | null;
  usages: TypeUsage[];
}

interface FunctionUsageCount {
  entry_address: string;
  name: string;
  used_by_function_count: number;
}

interface StringReferenceCount {
  address: string;
  value: string;
  reference_count: number;
}

interface ProgramOverview {
  function_count: number;
  internal_function_count: number;
  external_function_count: number;
  thunk_function_count: number;
  decompiled_function_count: number;
  call_site_count: number;
  string_count: number;
  total_string_reference_count: number;
  most_referenced_string: StringReferenceCount | null;
  required_library_count: number;
  external_entry_point_count: number;
  external_entry_point_function_count: number;
  most_used_function: FunctionUsageCount | null;
  detected_type_count: number;
  struct_count: number;
  union_count: number;
  enum_count: number;
  typedef_count: number;
  opaque_type_count: number;
  anonymous_type_count: number;
}

type MatchMethod = "symbol_name" | "same_address";
type UnmatchedReason = "auto_generated_name" | "ambiguous_name" | "no_candidate";
type FunctionChangeKind =
  | "return_type"
  | "parameters"
  | "thunk_status"
  | "external_status"
  | "outgoing_call_count";

interface ComparedFunctionRef {
  entry_address: string;
  name: string;
  namespace: string | null;
}

interface FunctionChange {
  kind: FunctionChangeKind;
  before: string;
  after: string;
}

interface FunctionMatch {
  method: MatchMethod;
  same_address: boolean;
  function_a: ComparedFunctionRef;
  function_b: ComparedFunctionRef;
  changes: FunctionChange[];
}

interface UnmatchedFunction extends ComparedFunctionRef {
  reason: UnmatchedReason;
}

interface ProjectComparison {
  same_binary: boolean;
  matches: FunctionMatch[];
  unmatched_a: UnmatchedFunction[];
  unmatched_b: UnmatchedFunction[];
}

interface PdfReportResult {
  path: string;
  page_count: number;
  function_count_included: number;
  string_count_included: number;
  type_count_included: number;
}

interface AppliedFunctionRename {
  entry_address: string;
  old_name: string;
  new_name: string;
}

interface ApplyRenamesResult {
  applied: AppliedFunctionRename[];
  imported: ImportedGhidraExport;
}

  let backendStatus = $state("");
  let exportPath = $state("");
  let importSummary = $state<GhidraImportSummary | null>(null);
  let importedExport = $state<GhidraExport | null>(null);
  let selectedFunctionAddress = $state<string | null>(null);
  let functionSearch = $state("");
  let graphNavigationHistory = $state<string[]>([]);
  let graphHistoryProgramSha: string | null = null;

  let selectedFunction = $derived(
    importedExport?.functions.find(
      (func) => func.entry_address === selectedFunctionAddress,
    ) ?? null,
  );

  let filteredFunctions = $derived.by(() => {
    if (!importedExport) return [];
    const query = functionSearch.trim().toLowerCase();
    if (!query) return importedExport.functions;
    return importedExport.functions.filter(
      (func) =>
        func.name.toLowerCase().includes(query) ||
        func.entry_address.toLowerCase().includes(query),
    );
  });

  let importError = $state("");
  let isImporting = $state(false);

  let ghidraInstallationStatus = $state<GhidraInstallationStatus | null>(null);
  let ghidraConfigError = $state("");
  let isConfiguringGhidra = $state(false);
  let analyzeError = $state("");
  let isAnalyzing = $state(false);

  let analysisSource = $state<"none" | "automatic" | "manual">("none");
  let activeProjectId = $state<string | null>(null);
  type WorkspaceView =
    | "overview"
    | "functions"
    | "strings"
    | "imports"
    | "types"
    | "graph"
    | "projects"
    | "comparison"
    | "reports"
    | "settings";
  let activeWorkspaceView = $state<WorkspaceView>("overview");

  const primaryViews: { id: WorkspaceView; label: string; icon: string }[] = [
    { id: "overview", label: "Aperçu", icon: "⌂" },
    { id: "functions", label: "Fonctions", icon: "ƒ" },
    { id: "strings", label: "Chaînes", icon: "\"" },
    { id: "types", label: "Structures", icon: "◇" },
    { id: "imports", label: "Imports / Exports", icon: "⇄" },
    { id: "graph", label: "Graphes", icon: "⌘" },
    { id: "comparison", label: "Comparaison", icon: "≋" },
    { id: "reports", label: "Rapports", icon: "▤" },
  ];

  let savedProjects = $state<ProjectSummary[] | null>(null);
  let savedProjectsError = $state("");
  let isLoadingSavedProjects = $state(false);
  let projectActionError = $state("");
  let renamingProjectId = $state<string | null>(null);
  let renameDraft = $state("");

  let comparisonProjectAId = $state("");
  let comparisonProjectBId = $state("");
  let projectComparison = $state<ProjectComparison | null>(null);
  let projectComparisonError = $state("");
  let isComparingProjects = $state(false);
  let comparisonMatchesFilter = $state<"changed" | "all">("changed");

  let filteredComparisonMatches = $derived.by(() => {
    if (!projectComparison) return [];
    if (comparisonMatchesFilter === "all") return projectComparison.matches;
    return projectComparison.matches.filter((match) => match.changes.length > 0);
  });

  let changedComparisonCount = $derived(
    projectComparison?.matches.filter((match) => match.changes.length > 0).length ?? 0,
  );

  let decompileCache = $state(new Map<string, DecompiledFunctionDetails>());
  let pendingDecompiles = $state(new Set<string>());
  let decompileErrors = $state(new Map<string, string>());
  let identifications = $state(new Map<string, FidCandidate[]>());
  let functionIdAnalysisAvailable = $state(false);
  let functionRenameDraft = $state("");
  let isApplyingFunctionRename = $state(false);
  let functionRenameError = $state("");
  let functionRenameSuccess = $state("");
  let renameDraftAddress: string | null = null;

  let selectedIdentificationCandidates = $derived(
    selectedFunctionAddress
      ? (identifications.get(selectedFunctionAddress) ?? [])
      : [],
  );

  // Real, honest stand-in for "functions identified": how many internal
  // (non-external) functions have at least one FunctionID candidate, out of
  // how many internal functions exist. Deliberately not a blended
  // confidence score -- FunctionID's own scores are shown per-candidate
  // where a function is selected, never averaged into one number here.
  let identifiedFunctionStats = $derived.by(() => {
    if (!importedExport) return null;
    if (!functionIdAnalysisAvailable) return null;

    const internalFunctions = importedExport.functions.filter(
      (func) => !func.is_external,
    );
    const identifiedCount = internalFunctions.filter(
      (func) => (identifications.get(func.entry_address)?.length ?? 0) > 0,
    ).length;

    return {
      identifiedCount,
      totalCount: internalFunctions.length,
      percentage:
        internalFunctions.length === 0
          ? 0
          : Math.round((identifiedCount / internalFunctions.length) * 100),
    };
  });

  function topIdentificationFor(entryAddress: string): FidCandidate | null {
    return identifications.get(entryAddress)?.[0] ?? null;
  }

  function initialFunctionAddress(exportData: GhidraExport): string | null {
    const internalFunctions = exportData.functions.filter((func) => !func.is_external);
    const normalizedName = (func: GhidraFunction) =>
      func.name.toLowerCase().replace(/^.*::/, "");

    const mainNames = new Set(["main", "wmain", "winmain", "wwinmain"]);
    const mainFunction = internalFunctions.find((func) => mainNames.has(normalizedName(func)));
    if (mainFunction) return mainFunction.entry_address;

    const entryAddresses = new Set(
      exportData.program.external_entry_points
        .filter((entry) => entry.kind === "function")
        .map((entry) => entry.address),
    );
    const programEntryFunction = internalFunctions.find((func) =>
      entryAddresses.has(func.entry_address),
    );
    if (programEntryFunction) return programEntryFunction.entry_address;

    const entryNames = new Set(["_start", "start", "entry", "__start"]);
    const namedEntryFunction = internalFunctions.find((func) =>
      entryNames.has(normalizedName(func)),
    );
    if (namedEntryFunction) return namedEntryFunction.entry_address;

    return (
      internalFunctions.find((func) => !func.is_thunk)?.entry_address ??
      internalFunctions[0]?.entry_address ??
      exportData.functions[0]?.entry_address ??
      null
    );
  }

  let importantFunctions = $derived.by(() => {
    if (!importedExport) return [];

    const callCounts = new Map<string, number>();
    for (const caller of importedExport.functions) {
      const targets = new Set(
        caller.calls
          .map((call) => call.target_address)
          .filter((address): address is string => address !== null),
      );
      if (caller.thunk_target_address) targets.add(caller.thunk_target_address);
      for (const target of targets) {
        callCounts.set(target, (callCounts.get(target) ?? 0) + 1);
      }
    }

    return importedExport.functions
      .filter((func) => !func.is_external && !func.is_thunk)
      .map((func) => ({
        ...func,
        callerCount: callCounts.get(func.entry_address) ?? 0,
        identification: topIdentificationFor(func.entry_address),
      }))
      .sort((a, b) => b.callerCount - a.callerCount || a.name.localeCompare(b.name))
      .slice(0, 8);
  });

  let detectedLibraries = $derived.by(() => {
    const libraries = new Map<string, { candidateCount: number; scoreTotal: number }>();
    for (const candidates of identifications.values()) {
      for (const candidate of candidates.slice(0, 1)) {
        const label = [candidate.library_family, candidate.library_version]
          .filter(Boolean)
          .join(" ");
        if (!label) continue;
        const current = libraries.get(label) ?? { candidateCount: 0, scoreTotal: 0 };
        current.candidateCount += 1;
        current.scoreTotal += candidate.overall_score;
        libraries.set(label, current);
      }
    }
    return [...libraries.entries()]
      .map(([name, value]) => ({
        name,
        candidateCount: value.candidateCount,
        averageScore: value.scoreTotal / value.candidateCount,
      }))
      .sort((a, b) => b.candidateCount - a.candidateCount)
      .slice(0, 5);
  });

  let globalStrings = $state<GlobalStringView[] | null>(null);
  let globalStringsError = $state("");
  let isLoadingGlobalStrings = $state(false);
  let globalStringsSearch = $state("");

  let filteredGlobalStrings = $derived.by(() => {
    if (!globalStrings) return [];

    const query = globalStringsSearch.trim().toLowerCase();
    if (!query) return globalStrings;

    return globalStrings.filter((entry) =>
      entry.value.toLowerCase().includes(query),
    );
  });

  let interestingStrings = $derived(
    [...(globalStrings ?? [])]
      .sort((a, b) => b.reference_count - a.reference_count)
      .slice(0, 5),
  );

  let imports = $state<ImportView[] | null>(null);
  let importsError = $state("");
  let isLoadingImports = $state(false);
  let importsSearch = $state("");

  let filteredImports = $derived.by(() => {
    if (!imports) return [];

    const query = importsSearch.trim().toLowerCase();
    if (!query) return imports;

    return imports.filter(
      (entry) =>
        entry.name.toLowerCase().includes(query) ||
        (entry.library ?? "").toLowerCase().includes(query),
    );
  });

  let externalEntryPoints = $state<ExternalEntryPoint[] | null>(null);
  let externalEntryPointsError = $state("");
  let isLoadingExternalEntryPoints = $state(false);
  let externalEntryPointsSearch = $state("");
  let externalEntryPointsFunctionsOnly = $state(true);

  let filteredExternalEntryPoints = $derived.by(() => {
    if (!externalEntryPoints) return [];

    const query = externalEntryPointsSearch.trim().toLowerCase();

    return externalEntryPoints.filter((entry) => {
      if (externalEntryPointsFunctionsOnly && entry.kind !== "function") {
        return false;
      }

      if (!query) return true;

      return (entry.name ?? "").toLowerCase().includes(query);
    });
  });

  let detectedTypes = $state<DetectedType[] | null>(null);
  let detectedTypesError = $state("");
  let isLoadingDetectedTypes = $state(false);
  let detectedTypesSearch = $state("");
  let detectedTypesKindFilter = $state<DetectedTypeKind | "all">("all");
  let expandedDetectedTypeKey = $state<string | null>(null);

  let filteredDetectedTypes = $derived.by(() => {
    if (!detectedTypes) return [];

    const query = detectedTypesSearch.trim().toLowerCase();

    return detectedTypes.filter((type) => {
      if (detectedTypesKindFilter !== "all" && type.kind !== detectedTypesKindFilter) {
        return false;
      }

      if (!query) return true;

      return type.name.toLowerCase().includes(query);
    });
  });

  let programOverview = $state<ProgramOverview | null>(null);
  let programOverviewError = $state("");
  let isLoadingProgramOverview = $state(false);
  let isExportingPdfReport = $state(false);
  let pdfReportError = $state("");
  let pdfReportResult = $state<PdfReportResult | null>(null);

  // Real on-demand decompilation progress (not a confidence/quality score):
  // how many functions have been decompiled so far this session, out of how
  // many exist. Reused as the overview's progress ring.
  let decompiledProgress = $derived.by(() => {
    if (!programOverview || programOverview.function_count === 0) return 0;
    return (programOverview.decompiled_function_count / programOverview.function_count) * 100;
  });

  type DetailTab = "overview" | "code" | "evidence" | "strings" | "calls";
  let activeDetailTab = $state<DetailTab>("overview");
  const detailTabs: { id: DetailTab; label: string }[] = [
    { id: "overview", label: "Aperçu" },
    { id: "code", label: "Code décompilé" },
    { id: "evidence", label: "Preuves" },
    { id: "strings", label: "Chaînes" },
    { id: "calls", label: "Appels" },
  ];

  let callGraphDirection = $state<CallGraphDirection>("outgoing");
  let callGraphDepth = $state(3);
  let callGraphResult = $state<CallGraphNeighborhood | null>(null);
  let callGraphError = $state("");
  let isLoadingCallGraph = $state(false);
  let callGraphRequestSeq = 0;

  const graphCanvasWidth = 1120;
  const graphNodeWidth = 184;
  const graphNodeHeight = 62;

  let callGraphLayout = $derived.by(() => {
    if (!callGraphResult) return { nodes: [], height: 360 };

    const depthGroups = new Map<number, CallGraphNode[]>();
    for (const node of callGraphResult.nodes) {
      const group = depthGroups.get(node.depth) ?? [];
      group.push(node);
      depthGroups.set(node.depth, group);
    }

    const nodes = [...depthGroups.entries()].flatMap(([depth, group]) =>
      group.map((node, index) => ({
        ...node,
        x: Math.round(((index + 1) * graphCanvasWidth) / (group.length + 1) - graphNodeWidth / 2),
        y: 38 + depth * 142,
      })),
    );

    return {
      nodes,
      height: Math.max(330, 138 + callGraphResult.depth_reached * 142),
    };
  });

  let graphNodePosition = $derived(
    new Map(callGraphLayout.nodes.map((node) => [node.entry_address, node])),
  );

  const overviewGraphWidth = 520;
  const overviewGraphNodeWidth = 126;
  const overviewGraphNodeHeight = 48;
  let overviewGraphLayout = $derived.by(() => {
    if (!callGraphResult) return { nodes: [], edges: [], height: 280 };
    const grouped = new Map<number, CallGraphNode[]>();
    for (const node of callGraphResult.nodes) {
      const group = grouped.get(node.depth) ?? [];
      if (group.length < (node.depth === 0 ? 1 : 3)) group.push(node);
      grouped.set(node.depth, group);
    }
    const nodes = [...grouped.entries()]
      .filter(([depth]) => depth <= 2)
      .flatMap(([depth, group]) =>
        group.map((node, index) => ({
          ...node,
          x: Math.round(((index + 1) * overviewGraphWidth) / (group.length + 1) - overviewGraphNodeWidth / 2),
          y: 22 + depth * 96,
        })),
      );
    const addresses = new Set(nodes.map((node) => node.entry_address));
    return {
      nodes,
      edges: callGraphResult.edges.filter(
        (edge) => addresses.has(edge.from) && addresses.has(edge.to),
      ),
      height: 280,
    };
  });

  let overviewGraphPositions = $derived(
    new Map(overviewGraphLayout.nodes.map((node) => [node.entry_address, node])),
  );

  let isDecompilingSelected = $derived(
    selectedFunctionAddress !== null &&
      pendingDecompiles.has(selectedFunctionAddress),
  );

  let selectedDecompileError = $derived(
    selectedFunctionAddress === null
      ? ""
      : (decompileErrors.get(selectedFunctionAddress) ?? ""),
  );

  let selectedDecompiledCode = $derived.by(() => {
    if (!selectedFunction) return null;
    if (analysisSource !== "automatic") return selectedFunction.decompiled_code;
    if (selectedFunction.decompiled_code !== null) {
      return selectedFunction.decompiled_code;
    }
    return decompileCache.get(selectedFunction.entry_address)?.decompiled_code ?? null;
  });

  let enrichedDetails = $derived(
    selectedFunction && analysisSource === "automatic"
      ? decompileCache.get(selectedFunction.entry_address)
      : undefined,
  );

  let displayedReturnType = $derived(
    enrichedDetails?.return_type ?? selectedFunction?.return_type ?? "",
  );

  let displayedParameters = $derived(
    enrichedDetails?.parameters ?? selectedFunction?.parameters ?? [],
  );

  let displayedCallingConvention = $derived(enrichedDetails?.calling_convention ?? null);

  let selectedPrototype = $derived.by(() => {
    if (!selectedFunction) return "";
    const parameters = displayedParameters
      .map((parameter) => `${parameter.data_type} ${parameter.name}`)
      .join(", ");
    return `${displayedReturnType || "undefined"} ${selectedFunction.name}(${parameters})`;
  });
  let selectedBsimResult = $derived(enrichedDetails?.bsim ?? null);

  $effect(() => {
    const address = selectedFunctionAddress;
    if (address === renameDraftAddress) return;
    renameDraftAddress = address;
    const func = selectedFunction;
    functionRenameDraft = func?.name ?? "";
    functionRenameError = "";
    functionRenameSuccess = "";
    activeDetailTab = "overview";
  });

  $effect(() => {
    const currentProgramSha = importedExport?.program.sha256 ?? null;
    if (currentProgramSha !== graphHistoryProgramSha) {
      graphHistoryProgramSha = currentProgramSha;
      graphNavigationHistory = [];
    }
  });

  $effect(() => {
    loadGhidraInstallationStatus();
  });

  $effect(() => {
    requestProjectList();
  });

  async function requestProjectList() {
    isLoadingSavedProjects = true;
    savedProjectsError = "";

    try {
      savedProjects = await invoke<ProjectSummary[]>("list_projects");
    } catch (error) {
      savedProjects = null;
      savedProjectsError = String(error);
    } finally {
      isLoadingSavedProjects = false;
    }
  }

  async function openProject(id: string) {
    projectActionError = "";
    importError = "";
    analyzeError = "";
    importSummary = null;
    importedExport = null;
    selectedFunctionAddress = null;
    analysisSource = "none";
    activeProjectId = null;
    decompileCache = new Map();
    pendingDecompiles = new Set();
    decompileErrors = new Map();
    identifications = new Map();
    functionIdAnalysisAvailable = false;

    try {
      const loaded = await invoke<LoadedProject>("open_project", { id });

      importedExport = loaded.export;
      selectedFunctionAddress = initialFunctionAddress(loaded.export);
      identifications = new Map(
        (loaded.identifications ?? []).map((identification) => [
          identification.entry_address,
          identification.candidates,
        ]),
      );
      functionIdAnalysisAvailable = loaded.identifications !== null;
      // A currently-available session (Ghidra project files genuinely
      // present right now, just re-verified by the backend) keeps
      // on-demand decompilation working, exactly like a fresh automatic
      // analysis. Anything else -- no session at all, or one whose Ghidra
      // project is unreachable this time -- behaves like a manual import.
      analysisSource = loaded.project.session_available ? "automatic" : "manual";
      activeProjectId = loaded.project.id;
      activeWorkspaceView = "overview";
    } catch (error) {
      projectActionError = String(error);
    }
  }

  async function deleteProject(project: ProjectSummary) {
    const message = project.session
      ? `Delete "${project.name}"? This also permanently deletes its Ghidra analysis project on disk. This cannot be undone.`
      : `Delete "${project.name}"? This cannot be undone.`;

    if (!confirm(message)) {
      return;
    }

    projectActionError = "";

    try {
      await invoke("delete_project", { id: project.id });

      if (activeProjectId === project.id) {
        activeProjectId = null;
      }

      if (
        comparisonProjectAId === project.id ||
        comparisonProjectBId === project.id
      ) {
        projectComparison = null;
        projectComparisonError = "";
        if (comparisonProjectAId === project.id) comparisonProjectAId = "";
        if (comparisonProjectBId === project.id) comparisonProjectBId = "";
      }

      await requestProjectList();
    } catch (error) {
      projectActionError = String(error);
    }
  }

  async function compareSavedProjects() {
    projectComparisonError = "";
    projectComparison = null;

    if (!comparisonProjectAId || !comparisonProjectBId) {
      projectComparisonError = "Select two saved projects.";
      return;
    }

    if (comparisonProjectAId === comparisonProjectBId) {
      projectComparisonError = "Select two different saved projects.";
      return;
    }

    isComparingProjects = true;

    try {
      projectComparison = await invoke<ProjectComparison>("compare_projects", {
        projectAId: comparisonProjectAId,
        projectBId: comparisonProjectBId,
      });
    } catch (error) {
      projectComparisonError = String(error);
    } finally {
      isComparingProjects = false;
    }
  }

  function comparisonProjectName(id: string): string {
    return savedProjects?.find((project) => project.id === id)?.name ?? id;
  }

  function qualifiedFunctionName(functionRef: ComparedFunctionRef): string {
    return functionRef.namespace
      ? `${functionRef.namespace}::${functionRef.name}`
      : functionRef.name;
  }

  function formatChangeKind(kind: FunctionChangeKind): string {
    return kind.replaceAll("_", " ");
  }

  function formatUnmatchedReason(reason: UnmatchedReason): string {
    switch (reason) {
      case "auto_generated_name":
        return "automatic Ghidra name";
      case "ambiguous_name":
        return "ambiguous name";
      case "no_candidate":
        return "no unique symbol-name candidate";
    }
  }

  function startRenamingProject(project: ProjectSummary) {
    renamingProjectId = project.id;
    renameDraft = project.name;
  }

  async function confirmRenameProject(id: string) {
    const newName = renameDraft.trim();

    if (!newName) {
      projectActionError = "Project name must not be empty.";
      return;
    }

    projectActionError = "";

    try {
      await invoke("rename_project", { id, newName });
      renamingProjectId = null;
      await requestProjectList();
    } catch (error) {
      projectActionError = String(error);
    }
  }

  $effect(() => {
    if (!importedExport) {
      globalStrings = null;
      globalStringsError = "";
      return;
    }

    requestGlobalStrings();
  });

  async function requestGlobalStrings() {
    isLoadingGlobalStrings = true;
    globalStringsError = "";

    try {
      globalStrings = await invoke<GlobalStringView[]>("get_global_strings");
    } catch (error) {
      globalStrings = null;
      globalStringsError = String(error);
    } finally {
      isLoadingGlobalStrings = false;
    }
  }

  $effect(() => {
    if (!importedExport) {
      imports = null;
      importsError = "";
      return;
    }

    requestImports();
  });

  async function requestImports() {
    isLoadingImports = true;
    importsError = "";

    try {
      imports = await invoke<ImportView[]>("get_imports");
    } catch (error) {
      imports = null;
      importsError = String(error);
    } finally {
      isLoadingImports = false;
    }
  }

  $effect(() => {
    if (!importedExport) {
      externalEntryPoints = null;
      externalEntryPointsError = "";
      return;
    }

    requestExternalEntryPoints();
  });

  async function requestExternalEntryPoints() {
    isLoadingExternalEntryPoints = true;
    externalEntryPointsError = "";

    try {
      externalEntryPoints = await invoke<ExternalEntryPoint[]>(
        "get_external_entry_points",
      );
    } catch (error) {
      externalEntryPoints = null;
      externalEntryPointsError = String(error);
    } finally {
      isLoadingExternalEntryPoints = false;
    }
  }

  $effect(() => {
    if (!importedExport) {
      detectedTypes = null;
      detectedTypesError = "";
      return;
    }

    requestDetectedTypes();
  });

  async function requestDetectedTypes() {
    isLoadingDetectedTypes = true;
    detectedTypesError = "";

    try {
      detectedTypes = await invoke<DetectedType[]>("get_detected_types");
    } catch (error) {
      detectedTypes = null;
      detectedTypesError = String(error);
    } finally {
      isLoadingDetectedTypes = false;
    }
  }

  function formatTypeSize(size: number | null): string {
    if (size === null) return "size unknown";
    return size === 1 ? "1 byte" : `${size} bytes`;
  }

  function formatProjectDate(createdAtUnixSeconds: number): string {
    return new Date(createdAtUnixSeconds * 1000).toLocaleString();
  }

  $effect(() => {
    if (!importedExport) {
      programOverview = null;
      programOverviewError = "";
      return;
    }

    requestProgramOverview();
  });

  async function requestProgramOverview() {
    isLoadingProgramOverview = true;
    programOverviewError = "";

    try {
      programOverview = await invoke<ProgramOverview>("get_program_overview");
    } catch (error) {
      programOverview = null;
      programOverviewError = String(error);
    } finally {
      isLoadingProgramOverview = false;
    }
  }

  async function exportPdfReport() {
    pdfReportError = "";
    pdfReportResult = null;

    try {
      const destinationPath = await save({
        title: "Export analysis report",
        defaultPath: `${importedExport?.program.name ?? "analysis"}-report.pdf`,
        filters: [{ name: "PDF report", extensions: ["pdf"] }],
      });
      if (typeof destinationPath !== "string") return;

      isExportingPdfReport = true;
      pdfReportResult = await invoke<PdfReportResult>("export_pdf_report", {
        destinationPath,
      });
    } catch (error) {
      pdfReportError = String(error);
    } finally {
      isExportingPdfReport = false;
    }
  }

  $effect(() => {
    const func = selectedFunction;

    if (!func || analysisSource !== "automatic" || func.is_external) return;
    if (func.decompiled_code !== null) return;
    if (
      decompileCache.has(func.entry_address) ||
      pendingDecompiles.has(func.entry_address)
    )
      return;

    requestDecompiledCode(func.entry_address);
  });

  $effect(() => {
    const address = selectedFunctionAddress;
    const direction = callGraphDirection;
    const depth = callGraphDepth;

    if (!address || analysisSource === "none") {
      callGraphResult = null;
      callGraphError = "";
      return;
    }

    requestCallGraph(address, direction, depth);
  });

  async function requestCallGraph(
    entryAddress: string,
    direction: CallGraphDirection,
    maxDepth: number,
  ) {
    const requestId = ++callGraphRequestSeq;
    isLoadingCallGraph = true;
    callGraphError = "";

    try {
      const result = await invoke<CallGraphNeighborhood>("get_call_graph", {
        entryAddress,
        direction,
        maxDepth,
      });

      if (requestId === callGraphRequestSeq) {
        callGraphResult = result;
      }
    } catch (error) {
      if (requestId === callGraphRequestSeq) {
        callGraphResult = null;
        callGraphError = String(error);
      }
    } finally {
      if (requestId === callGraphRequestSeq) {
        isLoadingCallGraph = false;
      }
    }
  }

  async function requestDecompiledCode(entryAddress: string) {
    pendingDecompiles = new Set(pendingDecompiles).add(entryAddress);

    const errorsWithoutCurrentAddress = new Map(decompileErrors);
    errorsWithoutCurrentAddress.delete(entryAddress);
    decompileErrors = errorsWithoutCurrentAddress;

    try {
      const details = await invoke<DecompiledFunctionDetails>(
        "decompile_function",
        { entryAddress },
      );

      decompileCache = new Map(decompileCache).set(entryAddress, details);

      // The backend writes this function's pseudocode back into the
      // stored export as it decompiles, so the overview's decompiled-count
      // genuinely advances -- but only if this refetches it; the effect
      // that fetches it only reruns when a whole new analysis loads.
      if (details.decompiled_code !== null) {
        requestProgramOverview();
      }
    } catch (error) {
      decompileErrors = new Map(decompileErrors).set(entryAddress, String(error));
    } finally {
      const remainingDecompiles = new Set(pendingDecompiles);
      remainingDecompiles.delete(entryAddress);
      pendingDecompiles = remainingDecompiles;
    }
  }

  async function applySelectedFunctionRename() {
    if (!selectedFunction || !activeProjectId || analysisSource !== "automatic") {
      functionRenameError = "Open a live saved project before applying a rename.";
      return;
    }
    const newName = functionRenameDraft.trim();
    if (!newName || newName === selectedFunction.name) {
      functionRenameError = "Enter a different non-empty function name.";
      return;
    }

    functionRenameError = "";
    functionRenameSuccess = "";
    isApplyingFunctionRename = true;
    const entryAddress = selectedFunction.entry_address;

    try {
      const result = await invoke<ApplyRenamesResult>("apply_function_renames", {
        projectId: activeProjectId,
        renames: [{ entry_address: entryAddress, new_name: newName }],
      });
      importedExport = result.imported.export;
      importSummary = result.imported.summary;
      decompileCache = new Map();
      decompileErrors = new Map();
      functionRenameSuccess = `Renamed in Ghidra: ${result.applied[0].old_name} → ${result.applied[0].new_name}`;
      await requestProjectList();
    } catch (error) {
      functionRenameError = String(error);
    } finally {
      isApplyingFunctionRename = false;
    }
  }

  function selectFunctionRenameSuggestion(name: string) {
    functionRenameDraft = name;
    functionRenameError = "";
    functionRenameSuccess = "";
  }

  function openFunction(entryAddress: string | null, navigateToFunctions = true) {
    if (!entryAddress) return;
    selectedFunctionAddress = entryAddress;
    if (navigateToFunctions) activeWorkspaceView = "functions";
  }

  function navigateWithinGraph(entryAddress: string) {
    if (selectedFunctionAddress && selectedFunctionAddress !== entryAddress) {
      graphNavigationHistory = [...graphNavigationHistory, selectedFunctionAddress];
    }
    openFunction(entryAddress, false);
  }

  function navigateBackInGraph() {
    const previousAddress = graphNavigationHistory.at(-1);
    if (!previousAddress) return;
    graphNavigationHistory = graphNavigationHistory.slice(0, -1);
    openFunction(previousAddress, false);
  }

  async function checkBackendStatus() {
    backendStatus = await invoke<string>("get_backend_status");
  }

  async function loadGhidraInstallationStatus() {
    try {
      ghidraInstallationStatus = await invoke<GhidraInstallationStatus>(
        "get_ghidra_installation_status",
      );
    } catch (error) {
      ghidraConfigError = String(error);
    }
  }

  async function selectGhidraInstallDir() {
    ghidraConfigError = "";

    try {
      const selectedPath = await open({
        title: "Select the Ghidra install directory",
        multiple: false,
        directory: true,
      });

      if (typeof selectedPath === "string") {
        await configureGhidraInstallation(selectedPath);
      }
    } catch (error) {
      ghidraConfigError = `Unable to open the folder selector: ${String(error)}`;
    }
  }

  async function configureGhidraInstallation(installDir: string) {
    ghidraConfigError = "";
    isConfiguringGhidra = true;

    try {
      await invoke("adopt_existing_ghidra", { installDir });
      await loadGhidraInstallationStatus();
    } catch (error) {
      ghidraConfigError = String(error);
    } finally {
      isConfiguringGhidra = false;
    }
  }

  async function selectAndAnalyzeBinary() {
    analyzeError = "";

    try {
      const selectedPath = await open({
        title: "Select a binary to analyze",
        multiple: false,
        directory: false,
      });

      if (typeof selectedPath === "string") {
        await analyzeBinary(selectedPath);
      }
    } catch (error) {
      analyzeError = `Unable to open the file selector: ${String(error)}`;
    }
  }

  async function analyzeBinary(binaryPath: string) {
    analyzeError = "";
    importSummary = null;
    importedExport = null;
    selectedFunctionAddress = null;
    analysisSource = "none";
    decompileCache = new Map();
    pendingDecompiles = new Set();
    decompileErrors = new Map();
    identifications = new Map();
    functionIdAnalysisAvailable = false;

    isAnalyzing = true;

    try {
      const result = await invoke<AutomaticAnalysisResult>(
        "analyze_binary_with_ghidra",
        { binaryPath },
      );

      importedExport = result.imported.export;
      importSummary = result.imported.summary;
      selectedFunctionAddress = initialFunctionAddress(result.imported.export);
      analysisSource = "automatic";
      activeProjectId = result.saved_project?.id ?? null;
      activeWorkspaceView = "overview";
      identifications = new Map(
        result.identifications.map((identification) => [
          identification.entry_address,
          identification.candidates,
        ]),
      );
      functionIdAnalysisAvailable = true;
      // The backend auto-saves every completed analysis as a local
      // project -- refresh the list so it shows up right away.
      requestProjectList();
    } catch (error) {
      analyzeError = String(error);
    } finally {
      isAnalyzing = false;
    }
  }

  async function selectGhidraExport() {
    importError = "";

    try {
      const selectedPath = await open({
        title: "Select a Ghidra JSON export",
        multiple: false,
        directory: false,
        filters: [
          {
            name: "Ghidra JSON export",
            extensions: ["json"],
          },
        ],
      });

      if (typeof selectedPath === "string") {
        exportPath = selectedPath;
      }
    } catch (error) {
      importError = `Unable to open the file selector: ${String(error)}`;
    }
  }

  async function importGhidraExport() {
    importError = "";
    importSummary = null;
    importedExport = null;
    selectedFunctionAddress = null;
    analysisSource = "none";
    decompileCache = new Map();
    pendingDecompiles = new Set();
    decompileErrors = new Map();
    identifications = new Map();
    functionIdAnalysisAvailable = false;

    const path = exportPath.trim();

    if (!path) {
      importError = "Enter the path of a Ghidra JSON export.";
      return;
    }

    isImporting = true;

    try {
      const imported = await invoke<ImportedGhidraExport>(
        "import_ghidra_export_details",
        { path },
      );

      importedExport = imported.export;
      importSummary = imported.summary;
      selectedFunctionAddress = initialFunctionAddress(imported.export);
      analysisSource = "manual";
      activeProjectId = null;
      activeWorkspaceView = "overview";
      requestProjectList();
      } catch (error) {
      importError = String(error);
      } finally {
      isImporting = false;
    }
  }
</script>

<svelte:head>
  <title>Reverse Assistant</title>
  <meta
    name="description"
    content="Local and AI-agnostic reverse engineering assistant"
  />
</svelte:head>

<main class="app-shell">
  <SetupAssistant onready={loadGhidraInstallationStatus} />
  <aside class="app-sidebar">
    <div class="brand">
      <span class="brand-mark">RA</span>
      <span>Reverse Assistant</span>
      <small>BETA</small>
    </div>

    <button type="button" class="new-analysis" onclick={selectAndAnalyzeBinary} disabled={isAnalyzing}>
      <span>+</span>{isAnalyzing ? "Analyse en cours" : "Nouvelle analyse"}
    </button>

    <nav class="sidebar-nav" aria-label="Navigation principale">
      <button
        type="button"
        class:active={activeWorkspaceView === "projects"}
        onclick={() => (activeWorkspaceView = "projects")}
      ><span>▣</span>Projets</button>
      <button
        type="button"
        class:active={activeWorkspaceView === "comparison"}
        onclick={() => (activeWorkspaceView = "comparison")}
      ><span>≋</span>Comparaisons</button>
      <button
        type="button"
        class:active={activeWorkspaceView === "reports"}
        onclick={() => (activeWorkspaceView = "reports")}
      ><span>▤</span>Rapports</button>
      <button
        type="button"
        class:active={activeWorkspaceView === "settings"}
        onclick={() => (activeWorkspaceView = "settings")}
      ><span>⚙</span>Paramètres</button>
    </nav>

    <div class="sidebar-status">
      <span class:ready={ghidraInstallationStatus?.status === "valid"}></span>
      <div>
        <strong>Environnement local</strong>
        <small>{ghidraInstallationStatus?.status === "valid" ? "Prêt" : "À configurer"}</small>
      </div>
    </div>
  </aside>

  <section class="workspace">
    <header class="workspace-header">
      <div>
        <p>{activeProjectId ? "ANALYSE LOCALE" : "ESPACE DE TRAVAIL"}</p>
        <h1>{importedExport?.program.name ?? "Reverse Assistant"}</h1>
        {#if importedExport}
          <span>
            {importedExport.program.format} · {importedExport.program.architecture} ·
            {importedExport.functions.length.toLocaleString()} fonctions
          </span>
        {:else}
          <span>Sélectionne un projet ou analyse un nouveau binaire.</span>
        {/if}
      </div>
      <div class="header-actions">
        <button type="button" class="secondary-button" onclick={selectAndAnalyzeBinary} disabled={isAnalyzing}>
          {isAnalyzing ? "Analyse en cours..." : "Importer un binaire"}
        </button>
        <button
          type="button"
          disabled={!importedExport || isExportingPdfReport}
          onclick={exportPdfReport}
        >
          {isExportingPdfReport ? "Export..." : "Rapport PDF"}
        </button>
      </div>
    </header>

    {#if importedExport}
      <nav class="workspace-tabs" aria-label="Navigation de l’analyse">
        {#each primaryViews as view (view.id)}
          <button
            type="button"
            class:active={activeWorkspaceView === view.id}
            onclick={() => (activeWorkspaceView = view.id)}
          ><span>{view.icon}</span>{view.label}</button>
        {/each}
      </nav>
    {/if}

    <div class="workspace-scroll">
      <section class="panel">
    <p class="phase">Phase 7 — Ghidra Headless automation</p>

    <h1>Reverse Assistant</h1>

    <p class="description">
      Analyze a binary directly, or import an existing Ghidra JSON export.
    </p>

    {#if !importedExport && activeWorkspaceView === "overview"}
      <section class="empty-workspace">
        <span aria-hidden="true">⌁</span>
        <p>NOUVELLE ANALYSE</p>
        <h2>Commence avec un binaire</h2>
        <p>
          L’analyse reste sur cette machine. Ghidra, les signatures et le corpus BSim sont
          utilisés localement.
        </p>
        <button type="button" onclick={selectAndAnalyzeBinary} disabled={isAnalyzing}>
          {isAnalyzing ? "Analyse en cours..." : "Choisir un binaire"}
        </button>
      </section>
    {/if}

    {#if !importedExport && activeWorkspaceView === "reports"}
      <section class="empty-workspace compact">
        <span aria-hidden="true">▤</span>
        <h2>Aucun rapport disponible</h2>
        <p>Ouvre une analyse existante ou importe un binaire avant de générer un rapport.</p>
      </section>
    {/if}

    <section
      class="saved-projects"
      class:view-hidden={activeWorkspaceView !== "projects" && activeWorkspaceView !== "comparison"}
      class:comparison-mode={activeWorkspaceView === "comparison"}
      aria-labelledby="saved-projects-title"
    >
      <h2 id="saved-projects-title">Saved projects (local)</h2>

      <p class="saved-projects-note">
        Every completed analysis or import is saved here automatically. A "live" project
        keeps on-demand decompilation working after reopening it; availability is checked
        again every time it's opened, so a project only temporarily unavailable (e.g. its
        Ghidra project sits on a drive that's currently unplugged) becomes live again on its
        own once its files are back — nothing is permanently lost. A "snapshot" project shows
        the same data read-only. Nothing here is ever synced or uploaded.
      </p>

      {#if isLoadingSavedProjects}
        <p>Loading projects...</p>
      {:else if savedProjectsError}
        <p class="error" role="alert">{savedProjectsError}</p>
      {:else if savedProjects}
        {#if savedProjects.length === 0}
          <p>No saved projects yet — analyze or import a binary to create one.</p>
        {:else}
          <ul class="saved-projects-list">
            {#each savedProjects as project (project.id)}
              <li class:active={project.id === activeProjectId}>
                <div class="saved-projects-entry-header">
                  {#if renamingProjectId === project.id}
                    <input
                      type="text"
                      class="global-strings-search"
                      bind:value={renameDraft}
                    />
                    <button
                      type="button"
                      onclick={() => confirmRenameProject(project.id)}
                    >
                      Save
                    </button>
                    <button
                      type="button"
                      class="secondary-button"
                      onclick={() => (renamingProjectId = null)}
                    >
                      Cancel
                    </button>
                  {:else}
                    <strong>{project.name}</strong>
                    <span class="global-strings-count">
                      {#if project.session_available}
                        live
                      {:else if project.session}
                        snapshot (Ghidra project unavailable)
                      {:else}
                        snapshot
                      {/if}
                    </span>
                    {#if project.id === activeProjectId}
                      <span class="global-strings-count">currently open</span>
                    {/if}
                  {/if}
                </div>

                <p class="saved-projects-meta">
                  {project.program_name} — {project.program_format}/{project.program_architecture},
                  {project.function_count} functions — saved {formatProjectDate(
                    project.created_at_unix_seconds,
                  )}
                </p>

                <div class="saved-projects-actions">
                  <button
                    type="button"
                    disabled={project.id === activeProjectId}
                    onclick={() => openProject(project.id)}
                  >
                    Open
                  </button>

                  {#if renamingProjectId !== project.id}
                    <button
                      type="button"
                      class="secondary-button"
                      onclick={() => startRenamingProject(project)}
                    >
                      Rename
                    </button>
                  {/if}

                  <button
                    type="button"
                    class="secondary-button"
                    onclick={() => deleteProject(project)}
                  >
                    Delete
                  </button>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
      {/if}

      {#if projectActionError}
        <p class="error" role="alert">{projectActionError}</p>
      {/if}

      {#if savedProjects && savedProjects.length >= 2}
        <section
          class="project-comparison"
          class:view-hidden={activeWorkspaceView !== "comparison"}
          aria-labelledby="project-comparison-title"
        >
          <h3 id="project-comparison-title">Compare two saved projects</h3>
          <p class="saved-projects-note">
            This first comparison matches unique, meaningful symbols. Automatic Ghidra names
            remain explicitly unmatched unless both projects are analyses of the exact same binary.
          </p>

          <div class="project-comparison-controls">
            <label>
              Project A
              <select
                bind:value={comparisonProjectAId}
                onchange={() => {
                  projectComparison = null;
                  projectComparisonError = "";
                }}
              >
                <option value="">Select a project...</option>
                {#each savedProjects as project (project.id)}
                  <option value={project.id} disabled={project.id === comparisonProjectBId}>
                    {project.name} — {project.program_name}
                  </option>
                {/each}
              </select>
            </label>

            <label>
              Project B
              <select
                bind:value={comparisonProjectBId}
                onchange={() => {
                  projectComparison = null;
                  projectComparisonError = "";
                }}
              >
                <option value="">Select a project...</option>
                {#each savedProjects as project (project.id)}
                  <option value={project.id} disabled={project.id === comparisonProjectAId}>
                    {project.name} — {project.program_name}
                  </option>
                {/each}
              </select>
            </label>

            <button
              type="button"
              disabled={isComparingProjects}
              onclick={compareSavedProjects}
            >
              {isComparingProjects ? "Comparing..." : "Compare"}
            </button>
          </div>

          {#if projectComparisonError}
            <p class="error" role="alert">{projectComparisonError}</p>
          {/if}

          {#if projectComparison}
            <div class="project-comparison-result">
              <p class="project-comparison-context">
                <strong>{comparisonProjectName(comparisonProjectAId)}</strong>
                versus
                <strong>{comparisonProjectName(comparisonProjectBId)}</strong>
                — {projectComparison.same_binary
                  ? "exact same binary (address matching allowed)"
                  : "different binaries (no address fallback)"}
              </p>

              <dl class="summary-grid">
                <div>
                  <dt>Matched functions</dt>
                  <dd>{projectComparison.matches.length}</dd>
                </div>
                <div>
                  <dt>Changed matches</dt>
                  <dd>{changedComparisonCount}</dd>
                </div>
                <div>
                  <dt>Unmatched in A</dt>
                  <dd>{projectComparison.unmatched_a.length}</dd>
                </div>
                <div>
                  <dt>Unmatched in B</dt>
                  <dd>{projectComparison.unmatched_b.length}</dd>
                </div>
              </dl>

              <div class="comparison-filter">
                <label>
                  Matched functions
                  <select bind:value={comparisonMatchesFilter}>
                    <option value="changed">Changed only</option>
                    <option value="all">All matches</option>
                  </select>
                </label>
                <span>{filteredComparisonMatches.length} results</span>
              </div>

              {#if filteredComparisonMatches.length === 0}
                <p>No matched function satisfies this filter.</p>
              {:else}
                <ul class="comparison-list">
                  {#each filteredComparisonMatches.slice(0, 200) as match (`${match.function_a.entry_address}-${match.function_b.entry_address}`)}
                    <li>
                      <div class="comparison-function-heading">
                        <strong>{qualifiedFunctionName(match.function_a)}</strong>
                        <span>
                          {match.function_a.entry_address} → {match.function_b.entry_address}
                        </span>
                      </div>
                      <p class="comparison-match-method">
                        Matched by {match.method === "symbol_name" ? "unique symbol name" : "same address"}
                        {match.same_address ? " · same address" : ""}
                      </p>
                      {#if match.changes.length === 0}
                        <p class="comparison-unchanged">No detected metadata change.</p>
                      {:else}
                        <ul class="comparison-changes">
                          {#each match.changes as change}
                            <li>
                              <strong>{formatChangeKind(change.kind)}:</strong>
                              <code>{change.before || "(empty)"}</code>
                              →
                              <code>{change.after || "(empty)"}</code>
                            </li>
                          {/each}
                        </ul>
                      {/if}
                    </li>
                  {/each}
                </ul>
                {#if filteredComparisonMatches.length > 200}
                  <p class="saved-projects-note">
                    Showing the first 200 results to keep this provisional view responsive.
                  </p>
                {/if}
              {/if}

              <div class="comparison-unmatched-grid">
                <section>
                  <h4>Unmatched in {comparisonProjectName(comparisonProjectAId)}</h4>
                  {#if projectComparison.unmatched_a.length === 0}
                    <p>None.</p>
                  {:else}
                    <ul class="comparison-unmatched-list">
                      {#each projectComparison.unmatched_a.slice(0, 200) as functionRef (functionRef.entry_address)}
                        <li>
                          <code>{functionRef.entry_address}</code>
                          <strong>{qualifiedFunctionName(functionRef)}</strong>
                          <span>{formatUnmatchedReason(functionRef.reason)}</span>
                        </li>
                      {/each}
                    </ul>
                    {#if projectComparison.unmatched_a.length > 200}
                      <p class="saved-projects-note">Showing the first 200 unmatched functions.</p>
                    {/if}
                  {/if}
                </section>

                <section>
                  <h4>Unmatched in {comparisonProjectName(comparisonProjectBId)}</h4>
                  {#if projectComparison.unmatched_b.length === 0}
                    <p>None.</p>
                  {:else}
                    <ul class="comparison-unmatched-list">
                      {#each projectComparison.unmatched_b.slice(0, 200) as functionRef (functionRef.entry_address)}
                        <li>
                          <code>{functionRef.entry_address}</code>
                          <strong>{qualifiedFunctionName(functionRef)}</strong>
                          <span>{formatUnmatchedReason(functionRef.reason)}</span>
                        </li>
                      {/each}
                    </ul>
                    {#if projectComparison.unmatched_b.length > 200}
                      <p class="saved-projects-note">Showing the first 200 unmatched functions.</p>
                    {/if}
                  {/if}
                </section>
              </div>
            </div>
          {/if}
        </section>
      {:else if activeWorkspaceView === "comparison"}
        <div class="comparison-empty empty-workspace compact">
          <span aria-hidden="true">≋</span>
          <h2>Deux projets sont nécessaires</h2>
          <p>Analyse ou importe un second binaire pour activer la comparaison locale.</p>
        </div>
      {/if}
    </section>

    <section
      class="ghidra-setup"
      class:view-hidden={activeWorkspaceView !== "settings"}
      aria-labelledby="ghidra-setup-title"
    >
      <h2 id="ghidra-setup-title">Ghidra installation</h2>

      {#if ghidraInstallationStatus?.status === "valid"}
        <p class="status">
          Configured: {ghidraInstallationStatus.installation.version_label}
        </p>

        <button
          type="button"
          class="secondary-button"
          onclick={selectGhidraInstallDir}
        >
          Change...
        </button>

        <button
          type="button"
          disabled={isAnalyzing}
          onclick={selectAndAnalyzeBinary}
        >
          {isAnalyzing ? "Analyse en cours..." : "Analyser un binaire"}
        </button>
      {:else}
        {#if ghidraInstallationStatus?.status === "invalid"}
          <p class="error" role="alert">
            {ghidraInstallationStatus.reason}
          </p>
        {/if}

        <button
          type="button"
          class="secondary-button"
          disabled={isConfiguringGhidra}
          onclick={selectGhidraInstallDir}
        >
          {isConfiguringGhidra ? "Configuring..." : "Configurer Ghidra"}
        </button>
      {/if}

      {#if ghidraConfigError}
        <p class="error" role="alert">{ghidraConfigError}</p>
      {/if}

      {#if analyzeError}
        <p class="error" role="alert">{analyzeError}</p>
      {/if}
    </section>

    <h2 class="manual-import-title" class:view-hidden={activeWorkspaceView !== "settings"}>
      Manual JSON import (debug)
    </h2>

    <form
      class="import-form"
      class:view-hidden={activeWorkspaceView !== "settings"}
      onsubmit={(event) => {
        event.preventDefault();
        importGhidraExport();
      }}
    >
      <label for="export-path">Ghidra export path</label>

      <div class="path-picker">
        <input
          id="export-path"
          type="text"
          bind:value={exportPath}
          placeholder="No Ghidra JSON export selected"
          readonly
      />

        <button type="button" class="secondary-button" onclick={selectGhidraExport}>
          Browse...
        </button>
      </div>

      <button type="submit" disabled={isImporting}>
        {isImporting ? "Importing..." : "Import Ghidra export"}
      </button>
    </form>

    {#if importError}
      <p class="error" class:view-hidden={activeWorkspaceView !== "settings"} role="alert">
        {importError}
      </p>
    {/if}

    {#if importSummary}
      <section
        class="summary import-summary"
        class:view-hidden={activeWorkspaceView !== "overview"}
        aria-labelledby="summary-title"
      >
        <h2 id="summary-title">Import summary</h2>

        <dl class="summary-grid">
          <div>
            <dt>Functions</dt>
            <dd>{importSummary.function_count}</dd>
          </div>

          <div>
            <dt>External functions</dt>
            <dd>{importSummary.external_function_count}</dd>
          </div>

          <div>
            <dt>Calls</dt>
            <dd>{importSummary.call_count}</dd>
          </div>

          <div>
            <dt>Strings</dt>
            <dd>{importSummary.string_count}</dd>
          </div>
        </dl>
      </section>
    {/if}

    {#if importedExport && programOverview}
      <section
        class="kpi-row"
        class:view-hidden={activeWorkspaceView !== "overview"}
        aria-label="Indicateurs clés de l'analyse"
      >
        <article class="kpi-card">
          <p class="detail-label">Fonctions</p>
          <strong>{programOverview.function_count.toLocaleString()}</strong>
          <span>
            {programOverview.internal_function_count.toLocaleString()} internes ·
            {programOverview.external_function_count.toLocaleString()} externes ·
            {programOverview.thunk_function_count.toLocaleString()} thunks
          </span>
        </article>

        <article class="kpi-card">
          <p class="detail-label">Fonctions identifiées (FunctionID)</p>
          {#if identifiedFunctionStats}
            <strong>{identifiedFunctionStats.identifiedCount.toLocaleString()} / {identifiedFunctionStats.totalCount.toLocaleString()}</strong>
            <span>{identifiedFunctionStats.percentage}% des fonctions internes ont au moins une candidature</span>
          {:else}
            <strong>—</strong>
            <span>Non disponible pour cette session (import manuel ou projet rouvert)</span>
          {/if}
        </article>

        <article class="kpi-card">
          <p class="detail-label">Chaînes de caractères</p>
          <strong>{programOverview.string_count.toLocaleString()}</strong>
          <span>{programOverview.total_string_reference_count.toLocaleString()} références</span>
        </article>

        <article class="kpi-card">
          <p class="detail-label">Bibliothèques requises</p>
          <strong>{programOverview.required_library_count.toLocaleString()}</strong>
          <span>{programOverview.external_function_count.toLocaleString()} imports</span>
        </article>

        <article class="kpi-card kpi-card-ring">
          <ProgressRing
            percentage={decompiledProgress}
            label="décompilées"
            sublabel={`${programOverview.decompiled_function_count} / ${programOverview.function_count} fonctions`}
          />
        </article>
      </section>
    {/if}

    {#if importedExport}
      <section
        class="summary"
        class:view-hidden={activeWorkspaceView !== "reports"}
        aria-labelledby="program-overview-title"
      >
        <h2 id="program-overview-title">Rapport d’analyse</h2>

        <div class="report-export-controls">
          <button type="button" disabled={isExportingPdfReport} onclick={exportPdfReport}>
            {isExportingPdfReport ? "Exporting report..." : "Export PDF report"}
          </button>
          {#if pdfReportResult}
            <span>
              Saved {pdfReportResult.page_count} page(s) to {pdfReportResult.path}
            </span>
          {/if}
        </div>
        {#if pdfReportError}
          <p class="error" role="alert">{pdfReportError}</p>
        {/if}

        {#if isLoadingProgramOverview}
          <p>Loading overview...</p>
        {:else if programOverviewError}
          <p class="error" role="alert">{programOverviewError}</p>
        {:else if programOverview}
          <dl class="summary-grid">
            <div>
              <dt>Functions</dt>
              <dd>
                {programOverview.function_count}
                ({programOverview.internal_function_count} internal, {programOverview.external_function_count}
                external, {programOverview.thunk_function_count} thunks)
              </dd>
            </div>

            <div>
              <dt>Decompiled functions</dt>
              <dd>{programOverview.decompiled_function_count} (so far this session)</dd>
            </div>

            <div>
              <dt>Call sites</dt>
              <dd>{programOverview.call_site_count}</dd>
            </div>

            <div>
              <dt>Most-used function</dt>
              <dd>
                {#if programOverview.most_used_function}
                  <code>{programOverview.most_used_function.name}</code>
                  — called by {programOverview.most_used_function.used_by_function_count} distinct
                  functions
                {:else}
                  none
                {/if}
              </dd>
            </div>

            <div>
              <dt>Strings</dt>
              <dd>
                {programOverview.string_count} distinct, {programOverview.total_string_reference_count}
                references
                {#if programOverview.most_referenced_string}
                  (most: <code>{programOverview.most_referenced_string.value}</code>
                  with {programOverview.most_referenced_string.reference_count})
                {/if}
              </dd>
            </div>

            <div>
              <dt>Imports / exports</dt>
              <dd>
                {programOverview.external_function_count} imports,
                {programOverview.external_entry_point_count} external entry points
                ({programOverview.external_entry_point_function_count} functions),
                {programOverview.required_library_count} required libraries
              </dd>
            </div>

            <div>
              <dt>Detected types</dt>
              <dd>
                {programOverview.detected_type_count} total —
                {programOverview.struct_count} structs, {programOverview.union_count} unions,
                {programOverview.enum_count} enums, {programOverview.typedef_count} typedefs
                ({programOverview.opaque_type_count} opaque, {programOverview.anonymous_type_count}
                anonymous)
              </dd>
            </div>
          </dl>
        {/if}
      </section>

      <section
        class="dashboard-insights"
        class:view-hidden={true}
        aria-label="Informations principales de l’analyse"
      >
        <article>
          <header><h3>Chaînes de caractères</h3><button type="button" onclick={() => (activeWorkspaceView = "strings")}>Voir tout</button></header>
          {#if globalStrings && globalStrings.length > 0}
            <ul>
              {#each globalStrings.slice(0, 5) as entry (entry.address)}
                <li><code>{entry.address}</code><span title={entry.value}>{entry.value}</span><strong>{entry.reference_count}</strong></li>
              {/each}
            </ul>
          {:else}<p>Aucune chaîne chargée.</p>{/if}
        </article>
        <article>
          <header><h3>Structures détectées</h3><button type="button" onclick={() => (activeWorkspaceView = "types")}>Voir tout</button></header>
          {#if detectedTypes && detectedTypes.length > 0}
            <ul>
              {#each detectedTypes.slice(0, 5) as type (`${type.category}-${type.name}`)}
                <li><span title={type.name}>{type.name}</span><code>{type.kind}</code><strong>{type.usages.length}</strong></li>
              {/each}
            </ul>
          {:else}<p>Aucun type chargé.</p>{/if}
        </article>
        <article>
          <header><h3>Imports principaux</h3><button type="button" onclick={() => (activeWorkspaceView = "imports")}>Voir tout</button></header>
          {#if imports && imports.length > 0}
            <ul>
              {#each imports.slice(0, 5) as entry (entry.entry_address)}
                <li><span title={entry.name}>{entry.name}</span><code>{entry.library ?? "—"}</code><strong>{entry.used_by_function_count}</strong></li>
              {/each}
            </ul>
          {:else}<p>Aucun import chargé.</p>{/if}
        </article>
        <article>
          <header><h3>Fonction la plus appelée</h3><button type="button" onclick={() => (activeWorkspaceView = "functions")}>Explorer</button></header>
          {#if programOverview?.most_used_function}
            <div class="top-function">
              <strong>{programOverview.most_used_function.name}</strong>
              <span>{programOverview.most_used_function.used_by_function_count} fonctions appelantes</span>
              <button type="button" onclick={() => openFunction(programOverview?.most_used_function?.entry_address ?? null)}>Ouvrir la fonction</button>
            </div>
          {:else}<p>Aucune fonction dominante.</p>{/if}
        </article>
      </section>

      <section
        class="overview-dashboard"
        class:view-hidden={activeWorkspaceView !== "overview"}
        aria-label="Tableau de bord de l’analyse"
      >
        <div class="overview-main-grid">
          <article class="overview-card important-functions-card">
            <header class="overview-card-header">
              <div><h2>Fonctions les plus importantes</h2><span>Classées par nombre de fonctions appelantes</span></div>
            </header>
            {#if importantFunctions.length > 0}
              <table>
                <thead><tr><th>Fonction</th><th>Identification</th><th>Appels</th></tr></thead>
                <tbody>
                  {#each importantFunctions as func (func.entry_address)}
                    <tr class:selected={func.entry_address === selectedFunctionAddress}>
                      <td><button type="button" onclick={() => navigateWithinGraph(func.entry_address)}>{func.name}</button><code>{func.entry_address}</code></td>
                      <td>
                        {#if func.identification}
                          <span class="identification-badge" title={`Score FunctionID ${func.identification.overall_score.toFixed(1)}`}>
                            {func.identification.name}
                          </span>
                        {:else}<span class="muted-value">—</span>{/if}
                      </td>
                      <td><strong>{func.callerCount}</strong></td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {:else}<p class="overview-empty">Aucune relation d’appel disponible.</p>{/if}
            <button type="button" class="overview-card-link" onclick={() => (activeWorkspaceView = "functions")}>Voir toutes les fonctions →</button>
          </article>

          <article class="overview-card overview-graph-card">
            <header class="overview-card-header">
              <div><h2>Graphe d’appels (aperçu)</h2><span>Voisinage réel de la fonction sélectionnée</span></div>
              <div class="overview-graph-actions">
                <button type="button" disabled={graphNavigationHistory.length === 0} onclick={navigateBackInGraph}>← Retour</button>
                <button type="button" onclick={() => (activeWorkspaceView = "graph")}>Ouvrir le graphe complet</button>
              </div>
            </header>
            {#if isLoadingCallGraph}
              <p class="overview-empty">Construction du graphe…</p>
            {:else if callGraphError}
              <p class="error" role="alert">{callGraphError}</p>
            {:else if overviewGraphLayout.nodes.length > 0}
              <div class="overview-graph-scroll">
                <div class="overview-graph-stage" style={`width:${overviewGraphWidth}px;height:${overviewGraphLayout.height}px`}>
                  <svg viewBox={`0 0 ${overviewGraphWidth} ${overviewGraphLayout.height}`} aria-hidden="true">
                    <defs><marker id="overview-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker></defs>
                    {#each overviewGraphLayout.edges as edge (`overview-${edge.from}-${edge.to}`)}
                      {@const from = overviewGraphPositions.get(edge.from)}
                      {@const to = overviewGraphPositions.get(edge.to)}
                      {#if from && to}
                        <path class="overview-edge" d={`M ${from.x + overviewGraphNodeWidth / 2} ${from.y + overviewGraphNodeHeight} C ${from.x + overviewGraphNodeWidth / 2} ${from.y + 28}, ${to.x + overviewGraphNodeWidth / 2} ${to.y - 28}, ${to.x + overviewGraphNodeWidth / 2} ${to.y}`} marker-end="url(#overview-arrow)"></path>
                      {/if}
                    {/each}
                  </svg>
                  {#each overviewGraphLayout.nodes as node (node.entry_address)}
                    <button
                      type="button"
                      class="overview-graph-node"
                      class:root={node.entry_address === selectedFunctionAddress}
                      class:external={node.is_external}
                      class:thunk={node.is_thunk}
                      style={`left:${node.x}px;top:${node.y}px;width:${overviewGraphNodeWidth}px;height:${overviewGraphNodeHeight}px`}
                      onclick={() => navigateWithinGraph(node.entry_address)}
                    ><strong>{node.name}</strong><code>{node.entry_address}</code></button>
                  {/each}
                </div>
              </div>
              <div class="overview-graph-legend"><span class="root">Sélection</span><span>Interne</span><span class="external">Externe</span><span class="thunk">Thunk</span></div>
            {:else}<p class="overview-empty">Sélectionne une fonction pour afficher son graphe.</p>{/if}
          </article>

          <article class="overview-card selected-function-card">
            <header class="selected-function-heading">
              <div><p class="detail-label">Détails de la fonction sélectionnée</p><h2>{selectedFunction?.name ?? "Aucune fonction"}</h2>{#if selectedFunction}<code>{selectedFunction.entry_address}</code>{/if}</div>
              {#if selectedFunction}<span class="function-kind-badge">{selectedFunction.is_external ? "Externe" : selectedFunction.is_thunk ? "Thunk" : "Interne"}</span>{/if}
            </header>
            {#if selectedFunction}
              <nav class="overview-detail-tabs" aria-label="Aperçu de la fonction">
                {#each detailTabs as tab (tab.id)}
                  <button type="button" class:active={activeDetailTab === tab.id} onclick={() => (activeDetailTab = tab.id)}>{tab.label}</button>
                {/each}
              </nav>
              {#if activeDetailTab === "overview"}
                <div class="overview-function-content">
                  <p class="mini-label">Prototype</p><code class="prototype-line">{selectedPrototype}</code>
                  <p class="mini-label">Preuves disponibles</p>
                  <ul class="evidence-list">
                    <li class:available={selectedIdentificationCandidates.length > 0}>FunctionID : {selectedIdentificationCandidates.length > 0 ? `${selectedIdentificationCandidates.length} candidature(s)` : "aucune candidature"}</li>
                    <li class:available={selectedBsimResult?.status === "available" && selectedBsimResult.matches.length > 0}>BSim : {selectedBsimResult?.status === "available" ? `${selectedBsimResult.matches.length} correspondance(s)` : "non interrogé"}</li>
                    <li class:available={selectedFunction.strings.length > 0}>{selectedFunction.strings.length} chaîne(s) référencée(s)</li>
                    <li class:available={selectedFunction.calls.length > 0}>{selectedFunction.calls.length} appel(s) sortant(s)</li>
                  </ul>
                </div>
              {:else if activeDetailTab === "code"}
                <div class="overview-code-preview">{#if isDecompilingSelected}<p>Décompilation…</p>{:else if selectedDecompiledCode}<pre><code>{selectedDecompiledCode}</code></pre>{:else}<p>Aucun pseudocode disponible.</p>{/if}</div>
              {:else if activeDetailTab === "evidence"}
                <div class="overview-function-content"><p>{selectedIdentificationCandidates.length} candidature(s) FunctionID et {selectedBsimResult?.matches.length ?? 0} correspondance(s) BSim.</p></div>
              {:else if activeDetailTab === "strings"}
                <ul class="compact-detail-list">{#each selectedFunction.strings.slice(0, 6) as value}<li><code>{value}</code></li>{/each}</ul>
              {:else}
                <ul class="compact-detail-list">{#each selectedFunction.calls.slice(0, 6) as call}<li><span>{call.target_name}</span><code>{call.target_address ?? "?"}</code></li>{/each}</ul>
              {/if}
              <button type="button" class="overview-card-link" onclick={() => (activeWorkspaceView = "functions")}>Ouvrir la fiche complète →</button>
            {:else}<p class="overview-empty">Sélectionne une fonction dans la liste.</p>{/if}
          </article>
        </div>

        <div class="overview-bottom-grid">
          <article class="overview-card compact-overview-card">
            <header class="overview-card-header"><div><h2>Chaînes intéressantes</h2><span>Classées par références</span></div></header>
            <ul class="overview-data-list">{#each interestingStrings as entry (entry.address)}<li><code>{entry.address}</code><span title={entry.value}>{entry.value}</span><strong>{entry.reference_count}</strong></li>{/each}</ul>
            <button type="button" class="overview-card-link" onclick={() => (activeWorkspaceView = "strings")}>Voir toutes les chaînes →</button>
          </article>
          <article class="overview-card compact-overview-card">
            <header class="overview-card-header"><div><h2>Imports principaux</h2><span>{imports?.length ?? 0} imports détectés</span></div></header>
            {#if imports && imports.length > 0}<ul class="overview-data-list">{#each [...imports].sort((a, b) => b.used_by_function_count - a.used_by_function_count).slice(0, 5) as entry (entry.entry_address)}<li><span title={entry.name}>{entry.name}</span><code>{entry.library ?? "Bibliothèque inconnue"}</code><strong>{entry.used_by_function_count}</strong></li>{/each}</ul>{:else}<p class="overview-empty">Aucun import détecté.</p>{/if}
            <button type="button" class="overview-card-link" onclick={() => (activeWorkspaceView = "imports")}>Voir tous les imports →</button>
          </article>
          <article class="overview-card compact-overview-card">
            <header class="overview-card-header"><div><h2>Bibliothèques reconnues</h2><span>Candidatures FunctionID réelles</span></div></header>
            {#if detectedLibraries.length > 0}<ul class="overview-data-list library-list">{#each detectedLibraries as library (library.name)}<li><span>{library.name}</span><code>score moyen {library.averageScore.toFixed(1)}</code><strong>{library.candidateCount}</strong></li>{/each}</ul>{:else}<p class="overview-empty">Aucune bibliothèque reconnue dans cette session.</p>{/if}
          </article>
          <article class="overview-card compact-overview-card comparison-preview-card">
            <header class="overview-card-header"><div><h2>Comparaison de versions</h2><span>Deux projets locaux nécessaires</span></div></header>
            {#if savedProjects && savedProjects.length >= 2}
              <strong>{savedProjects.length} projets disponibles</strong><p>Choisis deux analyses pour comparer les fonctions modifiées.</p><button type="button" onclick={() => (activeWorkspaceView = "comparison")}>Configurer la comparaison</button>
            {:else}<p class="overview-empty">Analyse ou importe un second binaire pour activer cette vue.</p>{/if}
          </article>
        </div>
      </section>

      <section
        class="global-strings"
        class:view-hidden={activeWorkspaceView !== "strings"}
        aria-labelledby="global-strings-title"
      >
        <h2 id="global-strings-title">Strings (global)</h2>

        <input
          type="text"
          class="global-strings-search"
          placeholder="Filter by string content..."
          bind:value={globalStringsSearch}
        />

        {#if isLoadingGlobalStrings}
          <p>Loading strings...</p>
        {:else if globalStringsError}
          <p class="error" role="alert">{globalStringsError}</p>
        {:else if globalStrings}
          <p class="global-strings-stats">
            {filteredGlobalStrings.length} of {globalStrings.length} strings
          </p>

          {#if filteredGlobalStrings.length === 0}
            <p>No string matches this filter.</p>
          {:else}
            <ul class="global-strings-list">
              {#each filteredGlobalStrings as entry (entry.address)}
                <li>
                  <div class="global-strings-entry-header">
                    <code>{entry.address}</code>
                    <span class="global-strings-value">{entry.value}</span>
                    <span class="global-strings-count">
                      {entry.reference_count}
                      {entry.reference_count === 1 ? "reference" : "references"}
                    </span>
                  </div>

                  {#if entry.referencing_functions.length > 0}
                    <div class="global-strings-functions">
                      {#each entry.referencing_functions as fn (fn.entry_address)}
                        <button
                          type="button"
                          class="global-strings-function"
                          onclick={() => openFunction(fn.entry_address)}
                        >
                          {fn.name}
                        </button>
                      {/each}
                    </div>
                  {/if}
                </li>
              {/each}
            </ul>
          {/if}
        {/if}
      </section>
    {/if}

    {#if importedExport}
      <section
        class="global-strings"
        class:view-hidden={activeWorkspaceView !== "imports"}
        aria-labelledby="imports-title"
      >
        <h2 id="imports-title">Imports (global)</h2>

        <input
          type="text"
          class="global-strings-search"
          placeholder="Filter by name or library..."
          bind:value={importsSearch}
        />

        {#if isLoadingImports}
          <p>Loading imports...</p>
        {:else if importsError}
          <p class="error" role="alert">{importsError}</p>
        {:else if imports}
          <p class="global-strings-stats">
            {filteredImports.length} of {imports.length} imports
          </p>

          {#if filteredImports.length === 0}
            <p>No import matches this filter.</p>
          {:else}
            <ul class="global-strings-list">
              {#each filteredImports as entry (entry.entry_address)}
                <li>
                  <div class="global-strings-entry-header">
                    <code>{entry.entry_address}</code>
                    <span class="global-strings-value">
                      {entry.name}
                      <em>({entry.library ?? "unknown library"})</em>
                    </span>
                    <span class="global-strings-count">
                      used by {entry.used_by_function_count}
                      {entry.used_by_function_count === 1 ? "function" : "functions"}
                    </span>
                  </div>

                  <div class="global-strings-functions">
                    <button
                      type="button"
                      class="global-strings-function"
                      onclick={() => openFunction(entry.entry_address)}
                    >
                      Select function
                    </button>
                  </div>
                </li>
              {/each}
            </ul>
          {/if}
        {/if}
      </section>
    {/if}

    {#if importedExport}
      <section
        class="global-strings"
        class:view-hidden={activeWorkspaceView !== "imports"}
        aria-labelledby="external-entry-points-title"
      >
        <h2 id="external-entry-points-title">External entry points (exports)</h2>

        <p class="global-strings-stats">
          On a real library/DLL this is a clean export table; on a plain executable it is
          broader and noisier (closer to every globally-visible symbol).
        </p>

        <div class="external-entry-points-controls">
          <input
            type="text"
            class="global-strings-search"
            placeholder="Filter by name..."
            bind:value={externalEntryPointsSearch}
          />

          <label class="external-entry-points-toggle">
            <input type="checkbox" bind:checked={externalEntryPointsFunctionsOnly} />
            Functions only
          </label>
        </div>

        {#if isLoadingExternalEntryPoints}
          <p>Loading external entry points...</p>
        {:else if externalEntryPointsError}
          <p class="error" role="alert">{externalEntryPointsError}</p>
        {:else if externalEntryPoints}
          <p class="global-strings-stats">
            {filteredExternalEntryPoints.length} of {externalEntryPoints.length} entries
          </p>

          {#if filteredExternalEntryPoints.length === 0}
            <p>No entry matches this filter.</p>
          {:else}
            <ul class="global-strings-list">
              {#each filteredExternalEntryPoints as entry (entry.address)}
                <li>
                  <div class="global-strings-entry-header">
                    <code>{entry.address}</code>
                    <span class="global-strings-value">{entry.name ?? "(anonymous)"}</span>
                    <span class="global-strings-count">{entry.kind}</span>
                  </div>

                  {#if entry.kind === "function"}
                    <div class="global-strings-functions">
                      <button
                        type="button"
                        class="global-strings-function"
                        onclick={() => openFunction(entry.address)}
                      >
                        Select function
                      </button>
                    </div>
                  {/if}
                </li>
              {/each}
            </ul>
          {/if}
        {/if}
      </section>

      <section
        class="global-strings"
        class:view-hidden={activeWorkspaceView !== "types"}
        aria-labelledby="detected-types-title"
      >
        <h2 id="detected-types-title">Detected structures/types</h2>

        <p class="global-strings-stats">
          Structures, unions, enums and typedefs actually used by a function signature or
          global data, plus the types they themselves reference (struct fields, a typedef's
          target). A type only reached that second way has no usages listed here -- that
          relationship is already visible in the referencing type's fields.
        </p>

        <div class="external-entry-points-controls">
          <input
            type="text"
            class="global-strings-search"
            placeholder="Filter by name..."
            bind:value={detectedTypesSearch}
          />

          <select bind:value={detectedTypesKindFilter}>
            <option value="all">All kinds</option>
            <option value="struct">Struct</option>
            <option value="union">Union</option>
            <option value="enum">Enum</option>
            <option value="typedef">Typedef</option>
          </select>
        </div>

        {#if isLoadingDetectedTypes}
          <p>Loading detected types...</p>
        {:else if detectedTypesError}
          <p class="error" role="alert">{detectedTypesError}</p>
        {:else if detectedTypes}
          <p class="global-strings-stats">
            {filteredDetectedTypes.length} of {detectedTypes.length} types
          </p>

          {#if filteredDetectedTypes.length === 0}
            <p>No type matches this filter.</p>
          {:else}
            <ul class="global-strings-list">
              {#each filteredDetectedTypes as type (type.category + "|" + type.name)}
                {@const typeKey = type.category + "|" + type.name}
                <li>
                  <div class="global-strings-entry-header">
                    <span class="global-strings-count">{type.kind}</span>
                    <span class="global-strings-value">{type.name}</span>
                    {#if type.is_opaque}<em>(opaque)</em>{/if}
                    {#if type.is_anonymous}<em>(anonymous)</em>{/if}
                    <span class="global-strings-count">
                      {formatTypeSize(type.size)}
                    </span>
                    <span class="global-strings-count">{type.usages.length} usages</span>
                    <button
                      type="button"
                      class="global-strings-function"
                      onclick={() => {
                        expandedDetectedTypeKey =
                          expandedDetectedTypeKey === typeKey ? null : typeKey;
                      }}
                    >
                      {expandedDetectedTypeKey === typeKey ? "Hide details" : "Show details"}
                    </button>
                  </div>

                  {#if expandedDetectedTypeKey === typeKey}
                    <div class="global-strings-functions">
                      {#if type.kind === "typedef"}
                        <p>Alias for <code>{type.target_type_name}</code></p>
                      {:else if type.kind === "enum"}
                        <ul>
                          {#each type.enum_values as enumValue (enumValue.name)}
                            <li><code>{enumValue.name}</code> = {enumValue.value}</li>
                          {/each}
                        </ul>
                      {:else if type.fields.length > 0}
                        <ul>
                          {#each type.fields as field (field.offset + (field.name ?? ""))}
                            <li>
                              +{field.offset}
                              <code>{field.name ?? "(anonymous)"}</code>:
                              <code>{field.data_type}</code>
                            </li>
                          {/each}
                        </ul>
                      {:else}
                        <p>No known fields (opaque).</p>
                      {/if}

                      {#if type.usages.length > 0}
                        <p class="global-strings-stats">Usages</p>
                        <ul>
                          {#each type.usages as usage, index (index)}
                            <li>
                              {#if usage.kind === "global_data"}
                                global data <code>{usage.data_address}</code>
                                {usage.data_label ? `(${usage.data_label})` : ""}
                              {:else}
                                {usage.kind === "function_parameter"
                                  ? `parameter "${usage.parameter_name}" of`
                                  : "return type of"}
                                <code>{usage.function_name}</code>
                                <button
                                  type="button"
                                  class="global-strings-function"
                                  onclick={() => openFunction(usage.function_address)}
                                >
                                  Select function
                                </button>
                              {/if}
                            </li>
                          {/each}
                        </ul>
                      {/if}
                    </div>
                  {/if}
                </li>
              {/each}
            </ul>
          {/if}
        {/if}
      </section>
    {/if}

    {#if importedExport}
      <section
        class="graph-workspace"
        class:view-hidden={activeWorkspaceView !== "graph"}
        aria-labelledby="graph-workspace-title"
      >
        <header class="section-toolbar">
          <div>
            <p class="detail-label">Exploration visuelle</p>
            <h2 id="graph-workspace-title">Graphe d’appels</h2>
          </div>
          <div class="call-graph-controls compact-controls">
            <button type="button" class="graph-back-button" disabled={graphNavigationHistory.length === 0} onclick={navigateBackInGraph}>
              ← Retour {graphNavigationHistory.length > 0 ? `(${graphNavigationHistory.length})` : ""}
            </button>
            <label>
              Direction
              <select bind:value={callGraphDirection}>
                <option value="outgoing">Appels sortants</option>
                <option value="incoming">Appels entrants</option>
                <option value="both">Les deux</option>
              </select>
            </label>
            <label>
              Profondeur
              <input type="number" min="1" max="5" bind:value={callGraphDepth} />
            </label>
          </div>
        </header>

        <div class="graph-layout">
          <div class="graph-stage-wrap">
            {#if isLoadingCallGraph}
              <p class="graph-message">Construction du graphe…</p>
            {:else if callGraphError}
              <p class="error" role="alert">{callGraphError}</p>
            {:else if callGraphResult}
              <div class="graph-legend">
                <span class="user">Fonction analysée</span>
                <span class="internal">Fonction interne</span>
                <span class="external">Bibliothèque / externe</span>
                <span class="thunk">Thunk</span>
              </div>
              <p class="call-graph-stats">
                {callGraphResult.nodes.length} fonctions · {callGraphResult.edges.length} appels ·
                profondeur {callGraphResult.depth_reached}
              </p>
              <div
                class="graph-stage"
                style={`width:${graphCanvasWidth}px;height:${callGraphLayout.height}px`}
              >
                <svg
                  class="graph-edges"
                  viewBox={`0 0 ${graphCanvasWidth} ${callGraphLayout.height}`}
                  aria-hidden="true"
                >
                  <defs>
                    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                      <path d="M 0 0 L 10 5 L 0 10 z"></path>
                    </marker>
                  </defs>
                  {#each callGraphResult.edges as edge (`${edge.from}-${edge.to}`)}
                    {@const from = graphNodePosition.get(edge.from)}
                    {@const to = graphNodePosition.get(edge.to)}
                    {#if from && to}
                      <path
                        d={`M ${from.x + graphNodeWidth / 2} ${from.y + graphNodeHeight} C ${from.x + graphNodeWidth / 2} ${from.y + graphNodeHeight + 45}, ${to.x + graphNodeWidth / 2} ${to.y - 45}, ${to.x + graphNodeWidth / 2} ${to.y}`}
                        marker-end="url(#arrow)"
                      ></path>
                    {/if}
                  {/each}
                </svg>
                {#each callGraphLayout.nodes as node (node.entry_address)}
                  <button
                    type="button"
                    class="visual-graph-node"
                    class:root={node.entry_address === selectedFunctionAddress}
                    class:external={node.is_external}
                    class:thunk={node.is_thunk}
                    style={`left:${node.x}px;top:${node.y}px;width:${graphNodeWidth}px;height:${graphNodeHeight}px`}
                    onclick={() => navigateWithinGraph(node.entry_address)}
                  >
                    <strong>{node.name}</strong>
                    <code>{node.entry_address}</code>
                  </button>
                {/each}
              </div>
            {:else}
              <p class="graph-message">Sélectionne une fonction pour afficher son voisinage.</p>
            {/if}
          </div>

          <aside class="graph-inspector">
            {#if callGraphResult}
              <p class="detail-label">Informations sur le graphe</p>
              <dl class="graph-info-grid">
                <div><dt>Vue</dt><dd>{callGraphDirection === "outgoing" ? "Appels sortants" : callGraphDirection === "incoming" ? "Appels entrants" : "Les deux"}</dd></div>
                <div><dt>Nœuds</dt><dd>{callGraphResult.nodes.length}</dd></div>
                <div><dt>Appels (arêtes)</dt><dd>{callGraphResult.edges.length}</dd></div>
                <div><dt>Profondeur atteinte</dt><dd>{callGraphResult.depth_reached}</dd></div>
                <div><dt>Fonctions externes</dt><dd>{callGraphResult.nodes.filter((node) => node.is_external).length}</dd></div>
              </dl>
            {/if}

            <p class="detail-label">Fonction sélectionnée</p>
            <h3>{selectedFunction?.name ?? "Aucune fonction"}</h3>
            {#if selectedFunction}
              <code>{selectedFunction.entry_address}</code>
              <dl>
                <div><dt>Type</dt><dd>{selectedFunction.is_external ? "Externe" : selectedFunction.is_thunk ? "Thunk" : "Interne"}</dd></div>
                <div><dt>Appels</dt><dd>{selectedFunction.calls.length}</dd></div>
                <div><dt>Chaînes</dt><dd>{selectedFunction.strings.length}</dd></div>
                <div><dt>Paramètres</dt><dd>{displayedParameters.length}</dd></div>
              </dl>
              <button type="button" onclick={() => (activeWorkspaceView = "functions")}>Voir les détails</button>
            {/if}
          </aside>
        </div>
      </section>

      <section
        class="function-explorer"
        class:view-hidden={activeWorkspaceView !== "functions"}
        aria-labelledby="functions-title"
      >
        <header class="function-list-heading">
          <div>
            <h2 id="functions-title">Fonctions</h2>
            <span>{filteredFunctions.length.toLocaleString()} sur {importedExport.functions.length.toLocaleString()}</span>
          </div>
          <input type="search" placeholder="Rechercher une fonction…" bind:value={functionSearch} />
        </header>

        {#if importedExport.functions.length === 0}
          <p>No functions were found in this export.</p>
        {:else}
          <div class="function-table-wrap">
            <table class="function-table">
              <thead>
                <tr>
                  <th scope="col">Nom</th>
                  <th scope="col">Adresse</th>
                  <th scope="col">Type</th>
                  <th scope="col">Appels</th>
                  <th scope="col">Identification (FunctionID)</th>
                </tr>
              </thead>
              <tbody>
                {#each filteredFunctions as func (func.entry_address)}
                  {@const topCandidate = topIdentificationFor(func.entry_address)}
                  <tr
                    class:active={func.entry_address === selectedFunctionAddress}
                    aria-selected={func.entry_address === selectedFunctionAddress}
                  >
                    <td>
                      <button
                        type="button"
                        class="function-table-name"
                        onclick={() => openFunction(func.entry_address)}
                      >
                        {func.name}
                      </button>
                    </td>
                    <td><code>{func.entry_address}</code></td>
                    <td>{func.is_external ? "Externe" : func.is_thunk ? "Thunk" : "Interne"}</td>
                    <td>{func.calls.length}</td>
                    <td>
                      {#if topCandidate}
                        <span title={`score ${topCandidate.overall_score.toFixed(1)}`}>
                          {topCandidate.name}
                          <em>({topCandidate.overall_score.toFixed(1)})</em>
                        </span>
                      {:else}
                        <span class="function-table-muted">—</span>
                      {/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>

        {#if selectedFunction}
          <article
            class="function-details"
            aria-labelledby="function-details-title"
          >
            <header class="function-details-header">
              <div>
                <p class="detail-label">Fonction sélectionnée</p>
                <h3 id="function-details-title">{selectedFunction.name}</h3>
                <code>{selectedFunction.entry_address}</code>
              </div>

              <div class="function-flags">
                <span>{selectedFunction.is_external ? "Externe" : "Interne"}</span>

                {#if selectedFunction.is_thunk}
                  <span>Thunk</span>
                {/if}
              </div>
            </header>

            <dl class="function-metadata">
              <div>
                <dt>Type de retour</dt>
                <dd><code>{displayedReturnType}</code></dd>
              </div>

              <div>
                <dt>Paramètres</dt>
                <dd>{displayedParameters.length}</dd>
              </div>

              <div>
                <dt>Appels</dt>
                <dd>{selectedFunction.calls.length}</dd>
              </div>

            <div>
                <dt>Chaînes</dt>
                <dd>{selectedFunction.strings.length}</dd>
              </div>

              {#if displayedCallingConvention}
                <div>
                  <dt>Convention d'appel</dt>
                  <dd><code>{displayedCallingConvention}</code></dd>
                </div>
              {/if}
            </dl>

            <nav class="detail-tabs" aria-label="Détails de la fonction sélectionnée">
              {#each detailTabs as tab (tab.id)}
                <button
                  type="button"
                  class:active={activeDetailTab === tab.id}
                  onclick={() => (activeDetailTab = tab.id)}
                >
                  {tab.label}
                </button>
              {/each}
            </nav>

            <div class="detail-tab-panel" class:view-hidden={activeDetailTab !== "overview"}>
              <div class="function-overview-grid">
                <div class="function-overview-primary">
                  <section class="function-section function-prototype-card">
                    <h4>Prototype</h4>
                    <code>{selectedPrototype}</code>
                  </section>

                  <section class="function-section">
                    <h4>Paramètres</h4>
                    {#if displayedParameters.length === 0}
                      <p>Aucun paramètre n'a été identifié.</p>
                    {:else}
                      <ul>
                        {#each displayedParameters as parameter}
                          <li><code>{parameter.data_type}</code><span>{parameter.name}</span></li>
                        {/each}
                      </ul>
                    {/if}
                  </section>
                </div>

                <section class="function-section function-graph-preview">
                  <div class="function-section-heading">
                    <div>
                      <h4>Graphe d'appels</h4>
                      {#if callGraphResult}
                        <span>{callGraphResult.nodes.length} fonctions · {callGraphResult.edges.length} appels</span>
                      {/if}
                    </div>
                    <div class="function-graph-actions">
                      <button type="button" disabled={graphNavigationHistory.length === 0} onclick={navigateBackInGraph}>← Retour</button>
                      <button type="button" onclick={() => (activeWorkspaceView = "graph")}>Graphe complet ↗</button>
                    </div>
                  </div>

                  {#if isLoadingCallGraph}
                    <p class="overview-empty">Construction du graphe…</p>
                  {:else if callGraphError}
                    <p class="error" role="alert">{callGraphError}</p>
                  {:else if overviewGraphLayout.nodes.length > 0}
                    <div class="function-graph-scroll">
                      <div class="overview-graph-stage" style={`width:${overviewGraphWidth}px;height:${overviewGraphLayout.height}px`}>
                        <svg viewBox={`0 0 ${overviewGraphWidth} ${overviewGraphLayout.height}`} aria-hidden="true">
                          <defs><marker id="function-overview-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker></defs>
                          {#each overviewGraphLayout.edges as edge (`function-overview-${edge.from}-${edge.to}`)}
                            {@const from = overviewGraphPositions.get(edge.from)}
                            {@const to = overviewGraphPositions.get(edge.to)}
                            {#if from && to}
                              <path class="overview-edge" d={`M ${from.x + overviewGraphNodeWidth / 2} ${from.y + overviewGraphNodeHeight} C ${from.x + overviewGraphNodeWidth / 2} ${from.y + 28}, ${to.x + overviewGraphNodeWidth / 2} ${to.y - 28}, ${to.x + overviewGraphNodeWidth / 2} ${to.y}`} marker-end="url(#function-overview-arrow)"></path>
                            {/if}
                          {/each}
                        </svg>
                        {#each overviewGraphLayout.nodes as node (node.entry_address)}
                          <button
                            type="button"
                            class="overview-graph-node"
                            class:root={node.entry_address === selectedFunctionAddress}
                            class:external={node.is_external}
                            class:thunk={node.is_thunk}
                            style={`left:${node.x}px;top:${node.y}px;width:${overviewGraphNodeWidth}px;height:${overviewGraphNodeHeight}px`}
                            onclick={() => navigateWithinGraph(node.entry_address)}
                          ><strong>{node.name}</strong><code>{node.entry_address}</code></button>
                        {/each}
                      </div>
                    </div>
                  {:else}
                    <p class="overview-empty">Aucune relation d'appel disponible.</p>
                  {/if}
                </section>
              </div>
            </div>

            <div class="detail-tab-panel" class:view-hidden={activeDetailTab !== "code"}>
              <section class="function-section">
                <h4>Decompiled code</h4>

                {#if isDecompilingSelected}
                  <p>Decompiling...</p>
                {:else if selectedDecompileError}
                  <p class="error" role="alert">{selectedDecompileError}</p>
                {:else if selectedDecompiledCode}
                  <pre><code>{selectedDecompiledCode}</code></pre>
                {:else}
                  <p>No decompiled code is available for this function.</p>
                {/if}
              </section>
            </div>

            <div class="detail-tab-panel" class:view-hidden={activeDetailTab !== "evidence"}>
              {#if analysisSource === "automatic" && activeProjectId && !selectedFunction.is_external}
                <section class="function-section ghidra-rename-control compact-rename-control">
                  <div class="rename-heading">
                    <div><h4>Nom à appliquer dans Ghidra</h4><p>Sélectionne une preuve ci-dessous ou saisis un nom, puis confirme.</p></div>
                  </div>
                  <div>
                    <input type="text" maxlength="512" bind:value={functionRenameDraft} />
                    <button
                      type="button"
                      disabled={isApplyingFunctionRename || functionRenameDraft.trim() === selectedFunction.name}
                      onclick={applySelectedFunctionRename}
                    >{isApplyingFunctionRename ? "Application…" : "Appliquer le nom"}</button>
                  </div>
                  {#if functionRenameError}<p class="error" role="alert">{functionRenameError}</p>{/if}
                  {#if functionRenameSuccess}<p class="status">{functionRenameSuccess}</p>{/if}
                </section>
              {/if}

              {#if selectedIdentificationCandidates.length === 0 && !selectedBsimResult}
                <p class="detail-label">Aucune preuve disponible pour cette fonction.</p>
              {/if}

              {#if selectedIdentificationCandidates.length > 0}
                <section class="function-section">
                  <h4>Possible match (FunctionID)</h4>

                  <ul>
                    {#each selectedIdentificationCandidates as candidate}
                      <li
                        class="rename-suggestion-item"
                        class:selected={functionRenameDraft === candidate.name}
                      >
                        <button
                          type="button"
                          class="rename-suggestion"
                          title={`Use ${candidate.name} as the proposed Ghidra name`}
                          onclick={() => selectFunctionRenameSuggestion(candidate.name)}
                        >
                          <span>
                            {candidate.name}
                            <em>
                              ({candidate.library_family} {candidate.library_version}
                              {candidate.library_variant}, {candidate.match_mode})
                            </em>
                          </span>
                          <code>score {candidate.overall_score.toFixed(1)}</code>
                        </button>
                      </li>
                    {/each}
                  </ul>
                </section>
              {/if}

              {#if selectedBsimResult}
                <section class="function-section">
                  <h4>Similar functions (BSim)</h4>

                  {#if selectedBsimResult.status === "available"}
                    {#if selectedBsimResult.matches.length === 0}
                      <p>No sufficiently similar function was found in the seed corpus.</p>
                    {:else}
                      <ul>
                        {#each selectedBsimResult.matches as candidate}
                          <li
                            class="rename-suggestion-item"
                            class:selected={functionRenameDraft === candidate.name}
                          >
                            <button
                              type="button"
                              class="rename-suggestion"
                              title={`Use ${candidate.name} as the proposed Ghidra name`}
                              onclick={() => selectFunctionRenameSuggestion(candidate.name)}
                            >
                              <span>
                                {candidate.name}
                                <em>({candidate.executable})</em>
                              </span>
                              <code>
                                similarity {candidate.similarity.toFixed(3)} · significance
                                {candidate.significance.toFixed(1)}
                              </code>
                            </button>
                          </li>
                        {/each}
                      </ul>
                    {/if}
                  {:else if selectedBsimResult.status === "unavailable"}
                    <p>{selectedBsimResult.message ?? "The BSim seed corpus is unavailable."}</p>
                  {:else}
                    <p class="bsim-error">
                      BSim query failed: {selectedBsimResult.message ?? "unknown error"}
                    </p>
                  {/if}
                </section>
              {/if}
            </div>

            <div class="detail-tab-panel" class:view-hidden={activeDetailTab !== "strings"}>
              <section class="function-section">
                <h4>Referenced strings</h4>

                {#if selectedFunction.strings.length === 0}
                  <p>No referenced strings were identified.</p>
                {:else}
                  <ul>
                    {#each selectedFunction.strings as referencedString}
                      <li><code>{referencedString}</code></li>
                    {/each}
                  </ul>
                {/if}
              </section>
            </div>

            <div class="detail-tab-panel" class:view-hidden={activeDetailTab !== "calls"}>
              <section class="function-section">
                <h4>Function calls</h4>

                {#if selectedFunction.calls.length === 0}
                  <p>No outgoing calls were identified.</p>
                {:else}
                  <ul>
                    {#each selectedFunction.calls as call}
                      <li>
                        <span>{call.target_name}</span>

                        {#if call.target_address}
                          <code class="call-address">{call.target_address}</code>
                        {:else}
                          <em>Unresolved address</em>
                        {/if}
                      </li>
                    {/each}
                  </ul>
                {/if}
              </section>
            </div>
      </article>
    {/if}
  {/if}
</section>
{/if}

    <div class="backend-check" class:view-hidden={activeWorkspaceView !== "settings"}>
      <button type="button" class="secondary-button" onclick={checkBackendStatus}>
        Check Rust backend
      </button>

      {#if backendStatus}
        <p class="status">{backendStatus}</p>
      {/if}
        </div>
      </section>
    </div>
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    min-width: 320px;
    background-color: #111827;
    color: #f9fafb;
    font-family: Inter, Arial, sans-serif;
  }

  button,
  input {
    font: inherit;
  }

  .panel {
    width: min(760px, 100%);
    margin: 0 auto;
    padding: 2rem;
    box-sizing: border-box;
    border: 1px solid #334155;
    border-radius: 16px;
    background-color: #1e293b;
  }

  .phase {
    margin-top: 0;
    color: #22d3ee;
    font-weight: 600;
  }

  h1 {
    margin: 0.5rem 0;
    font-size: clamp(2rem, 7vw, 3rem);
  }

  .description {
    margin-bottom: 2rem;
    color: #cbd5e1;
  }

  .import-form {
    display: grid;
    gap: 0.75rem;
  }

  .path-picker {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 0.75rem;
  }

  .path-picker .secondary-button {
    white-space: nowrap;
  }

  @media (max-width: 560px) {
    .path-picker {
      grid-template-columns: 1fr;
    }
  }

  label {
    font-weight: 700;
  }

  input {
    box-sizing: border-box;
    width: 100%;
    padding: 0.85rem 1rem;
    border: 1px solid #475569;
    border-radius: 8px;
    background-color: #0f172a;
    color: #f8fafc;
  }

  input:focus {
    border-color: #22d3ee;
    outline: 2px solid rgb(34 211 238 / 25%);
  }

  button {
    padding: 0.8rem 1.2rem;
    border: 0;
    border-radius: 8px;
    background-color: #22d3ee;
    color: #0f172a;
    font-weight: 700;
    cursor: pointer;
  }

  button:hover:not(:disabled) {
    background-color: #67e8f9;
  }

  button:disabled {
    cursor: wait;
    opacity: 0.65;
  }

  .error,
  .status {
    margin-top: 1.5rem;
    padding: 0.8rem 1rem;
    border-radius: 8px;
    overflow-wrap: anywhere;
  }

  .error {
    border: 1px solid #ef4444;
    color: #fca5a5;
  }

  .summary {
    margin-top: 2rem;
  }

  .summary h2 {
    font-size: 1.25rem;
  }

  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin: 0;
  }

  .summary-grid div {
    padding: 1rem;
    border: 1px solid #334155;
    border-radius: 10px;
    background-color: #0f172a;
  }

  .summary-grid dt {
    color: #94a3b8;
  }

  .summary-grid dd {
    margin: 0.4rem 0 0;
    color: #67e8f9;
    font-size: 1.75rem;
    font-weight: 700;
  }

  .global-strings {
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid #374151;
  }

  .global-strings h2 {
    margin: 0 0 1rem;
    font-size: 1.25rem;
  }

  .global-strings-search {
    margin-bottom: 0.75rem;
  }

  .global-strings-stats {
    margin: 0 0 0.75rem;
    color: #94a3b8;
    font-size: 0.85rem;
  }

  .global-strings-list {
    display: grid;
    max-height: 480px;
    margin: 0;
    padding: 0;
    gap: 0.5rem;
    overflow-y: auto;
    list-style: none;
  }

  .global-strings-list li {
    padding: 0.65rem;
    border: 1px solid #374151;
    border-radius: 0.5rem;
    background-color: #1f2937;
  }

  .global-strings-entry-header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
  }

  .global-strings-entry-header code {
    flex-shrink: 0;
    color: #93c5fd;
  }

  .global-strings-value {
    flex: 1 1 auto;
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .global-strings-value em {
    margin-left: 0.35rem;
    color: #94a3b8;
    font-style: normal;
  }

  .global-strings-count {
    flex-shrink: 0;
    color: #94a3b8;
    font-size: 0.8rem;
    white-space: nowrap;
  }

  .global-strings-functions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.6rem;
  }

  .global-strings-function {
    padding: 0.3rem 0.6rem;
    border: 1px solid #3b82f6;
    border-radius: 999px;
    background-color: #172554;
    color: #bfdbfe;
    font-size: 0.8rem;
    font-weight: 400;
    cursor: pointer;
  }

  .global-strings-function:hover:not(:disabled) {
    background-color: #1e3a8a;
  }

  .global-strings-function:disabled {
    background-color: #1e3a5f;
    color: #f9fafb;
    cursor: default;
    opacity: 1;
  }

  .saved-projects {
    margin-bottom: 1.5rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid #374151;
  }

  .saved-projects h2 {
    margin: 0 0 0.5rem;
    font-size: 1.25rem;
  }

  .saved-projects-note {
    margin: 0 0 0.75rem;
    color: #94a3b8;
    font-size: 0.85rem;
  }

  .saved-projects-list {
    display: grid;
    max-height: 420px;
    margin: 0;
    padding: 0;
    gap: 0.5rem;
    overflow-y: auto;
    list-style: none;
  }

  .saved-projects-list li {
    padding: 0.65rem;
    border: 1px solid #374151;
    border-radius: 0.5rem;
    background-color: #1f2937;
  }

  .saved-projects-list li.active {
    border-color: #3b82f6;
  }

  .saved-projects-entry-header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
  }

  .saved-projects-meta {
    margin: 0.35rem 0 0;
    color: #94a3b8;
    font-size: 0.8rem;
  }

  .saved-projects-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.6rem;
  }

  .project-comparison {
    margin-top: 1.25rem;
    padding-top: 1.25rem;
    border-top: 1px solid #374151;
  }

  .report-export-controls {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }

  .report-export-controls span {
    color: #94a3b8;
    font-size: 0.8rem;
    overflow-wrap: anywhere;
  }

  .project-comparison h3,
  .project-comparison h4 {
    margin: 0 0 0.5rem;
  }

  .project-comparison-controls {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    gap: 0.75rem;
  }

  .project-comparison-controls label,
  .comparison-filter label {
    display: grid;
    flex: 1 1 260px;
    gap: 0.35rem;
    color: #94a3b8;
    font-size: 0.85rem;
  }

  .project-comparison-controls select,
  .comparison-filter select {
    min-width: 0;
    padding: 0.55rem 0.7rem;
    border: 1px solid #475569;
    border-radius: 0.5rem;
    background-color: #0f172a;
    color: #f8fafc;
  }

  .project-comparison-result {
    margin-top: 1rem;
  }

  .project-comparison-context {
    color: #cbd5e1;
  }

  .comparison-filter {
    display: flex;
    align-items: end;
    gap: 1rem;
    margin: 1rem 0 0.75rem;
  }

  .comparison-filter span,
  .comparison-match-method,
  .comparison-unchanged {
    color: #94a3b8;
    font-size: 0.8rem;
  }

  .comparison-list,
  .comparison-unmatched-list {
    display: grid;
    max-height: 520px;
    margin: 0;
    padding: 0;
    gap: 0.5rem;
    overflow-y: auto;
    list-style: none;
  }

  .comparison-list > li,
  .comparison-unmatched-list li {
    padding: 0.65rem;
    border: 1px solid #374151;
    border-radius: 0.5rem;
    background-color: #111827;
  }

  .comparison-function-heading {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .comparison-function-heading span {
    color: #93c5fd;
    font-family: monospace;
    font-size: 0.8rem;
  }

  .comparison-match-method,
  .comparison-unchanged {
    margin: 0.35rem 0 0;
  }

  .comparison-changes {
    display: grid;
    margin: 0.6rem 0 0;
    padding-left: 1.2rem;
    gap: 0.35rem;
  }

  .comparison-changes code {
    overflow-wrap: anywhere;
  }

  .comparison-unmatched-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 1rem;
    margin-top: 1.25rem;
  }

  .comparison-unmatched-list li {
    display: grid;
    gap: 0.2rem;
  }

  .comparison-unmatched-list code {
    color: #93c5fd;
  }

  .comparison-unmatched-list span {
    color: #94a3b8;
    font-size: 0.8rem;
  }

  @media (max-width: 760px) {
    .comparison-unmatched-grid {
      grid-template-columns: 1fr;
    }
  }

  .external-entry-points-controls {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }

  .external-entry-points-controls .global-strings-search {
    flex: 1 1 auto;
    margin-bottom: 0;
  }

  .external-entry-points-toggle {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    color: #94a3b8;
    font-size: 0.85rem;
    white-space: nowrap;
  }

  .backend-check {
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid #334155;
  }

  .ghidra-setup {
    display: grid;
    gap: 0.75rem;
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid #334155;
  }

  .ghidra-setup h2 {
    margin: 0;
    font-size: 1.25rem;
  }

  .ghidra-setup button {
    justify-self: start;
  }

  .manual-import-title {
    margin: 0 0 0.75rem;
    color: #94a3b8;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .secondary-button {
    border: 1px solid #64748b;
    background-color: transparent;
    color: #e2e8f0;
  }

  .secondary-button:hover:not(:disabled) {
    background-color: #334155;
  }

  .status {
    border: 1px solid #22c55e;
    color: #86efac;
  }

      .function-explorer {
    display: grid;
    grid-template-columns: minmax(260px, 0.8fr) minmax(0, 2fr);
    margin-top: 2rem;
    padding-top: 1.5rem;
    gap: 1.5rem;
    border-top: 1px solid #374151;
    align-items: start;
  }

  .function-explorer > p {
    grid-column: 1 / -1;
    margin: 0;
  }

  .function-table-wrap {
    max-height: 720px;
    overflow: auto;
    border: 1px solid #374151;
    border-radius: 0.5rem;
  }

  .function-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }

  .function-table thead th {
    position: sticky;
    top: 0;
    padding: 0.6rem 0.75rem;
    background-color: #1f2937;
    color: #94a3b8;
    font-size: 0.72rem;
    font-weight: 600;
    text-align: left;
    white-space: nowrap;
  }

  .function-table tbody td {
    padding: 0.55rem 0.75rem;
    border-top: 1px solid #263349;
    color: #d7e0ef;
    overflow-wrap: anywhere;
  }

  .function-table tbody tr:hover {
    background-color: #16263f;
  }

  .function-table tbody tr.active {
    background-color: #1e3a5f;
  }

  .function-table code {
    color: #93c5fd;
    font-size: 0.76rem;
    white-space: nowrap;
  }

  .function-table-name {
    padding: 0;
    background: transparent;
    color: #f3f6fb;
    font-weight: 600;
    text-align: left;
    text-decoration: underline;
    text-decoration-color: transparent;
  }

  .function-table-name:hover {
    text-decoration-color: currentColor;
  }

  .function-table td em {
    margin-left: 0.3rem;
    color: #8292ad;
    font-size: 0.72rem;
    font-style: normal;
  }

  .function-table-muted {
    color: #556077;
  }

  .function-details {
    min-width: 0;
    max-height: 720px;
    padding: 1.25rem;
    border: 1px solid #374151;
    border-radius: 0.75rem;
    background-color: #111827;
    overflow-y: auto;
  }

  .function-details-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid #374151;
  }

  .function-details-header h3 {
    margin: 0.25rem 0 0.5rem;
    color: #f9fafb;
    overflow-wrap: anywhere;
  }

  .detail-label {
    margin: 0;
    color: #94a3b8;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .function-flags {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 0.5rem;
  }

  .function-flags span {
    padding: 0.3rem 0.6rem;
    border: 1px solid #3b82f6;
    border-radius: 999px;
    background-color: #172554;
    color: #bfdbfe;
    font-size: 0.8rem;
  }

  .function-metadata {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    margin: 1rem 0;
    gap: 0.75rem;
  }

  .function-metadata div {
    min-width: 0;
    padding: 0.75rem;
    border: 1px solid #374151;
    border-radius: 0.5rem;
    background-color: #1f2937;
  }

  .function-metadata dt {
    color: #94a3b8;
    font-size: 0.8rem;
  }

  .function-metadata dd {
    margin: 0.35rem 0 0;
    color: #e2e8f0;
    overflow-wrap: anywhere;
  }

  .detail-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0.2rem;
    margin: 0.9rem 0 0;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #263349;
  }

  .detail-tabs button {
    padding: 0.4rem 0.7rem;
    border: 0;
    border-radius: 6px;
    background: transparent;
    color: #8292ad;
    font-size: 0.74rem;
    font-weight: 600;
  }

  .detail-tabs button:hover:not(.active),
  .detail-tabs button.active {
    background: rgb(124 58 237 / 12%);
    color: #e9e3ff;
  }

  .detail-tab-panel {
    margin-top: 0.25rem;
  }

  .function-section {
    margin-top: 1.25rem;
  }

  .function-section h4 {
    margin: 0 0 0.75rem;
    color: #67e8f9;
  }

  .function-section-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    margin-bottom: 0.5rem;
  }

  .function-section-heading h4 {
    margin: 0;
  }

  .function-section-heading button {
    padding: 0.3rem 0.5rem;
    border: 1px solid #4c3a83;
    background: #201743;
    color: #c4b5fd;
    font-size: 0.66rem;
  }

  .function-section p {
    color: #94a3b8;
  }

  .function-section .bsim-error {
    color: #fca5a5;
  }

  .ghidra-rename-control > div {
    display: flex;
    gap: 0.6rem;
  }

  .ghidra-rename-control input {
    min-width: 0;
    flex: 1 1 auto;
    padding: 0.55rem 0.7rem;
    border: 1px solid #475569;
    border-radius: 0.5rem;
    background-color: #0f172a;
    color: #f8fafc;
  }

  .call-graph-controls {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .call-graph-controls label {
    display: grid;
    gap: 0.35rem;
    color: #94a3b8;
    font-size: 0.85rem;
    font-weight: 400;
  }

  .call-graph-controls select,
  .call-graph-controls input {
    padding: 0.5rem 0.65rem;
    border: 1px solid #475569;
    border-radius: 0.5rem;
    background-color: #0f172a;
    color: #f8fafc;
  }

  .call-graph-stats {
    margin: 0 0 0.75rem;
    color: #94a3b8;
    font-size: 0.85rem;
  }

  .function-section li span em {
    margin-left: 0.35rem;
    color: #94a3b8;
    font-style: normal;
  }

  .function-section ul {
    display: grid;
    margin: 0;
    padding: 0;
    gap: 0.5rem;
    list-style: none;
  }

  .function-section li {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.65rem;
    border: 1px solid #374151;
    border-radius: 0.5rem;
    background-color: #1f2937;
    overflow-wrap: anywhere;
  }

  .function-section li.rename-suggestion-item {
    padding: 0;
    transition: border-color 120ms ease, background-color 120ms ease;
  }

  .function-section li.rename-suggestion-item.selected {
    border-color: #22d3ee;
    background-color: #164e63;
  }

  .rename-suggestion {
    display: flex;
    width: 100%;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.65rem;
    border-radius: 0.5rem;
    background: transparent;
    color: #f8fafc;
    font-weight: 400;
    text-align: left;
  }

  .rename-suggestion:hover:not(:disabled) {
    background-color: rgb(34 211 238 / 10%);
  }

  .rename-suggestion code {
    color: #e2e8f0;
    text-align: right;
  }

  .function-section pre {
    max-width: 100%;
    margin: 0;
    padding: 1rem;
    border: 1px solid #374151;
    border-radius: 0.5rem;
    background-color: #020617;
    overflow-x: auto;
  }

  .function-section pre code {
    color: #d1fae5;
    font-family: Consolas, "Courier New", monospace;
    font-size: 0.85rem;
    line-height: 1.5;
    white-space: pre;
  }

  .function-metadata dd code {
    font-size: 0.85rem;
  }

  .call-address {
    flex-shrink: 0;
    white-space: nowrap;
  }

  @media (max-width: 850px) {
    .function-explorer {
      grid-template-columns: 1fr;
    }

    .function-explorer > p {
      grid-column: 1;
    }

    .function-metadata {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  .view-hidden {
    display: none !important;
  }

  .app-shell {
    display: grid;
    grid-template-columns: 224px minmax(0, 1fr);
    width: 100%;
    height: 100vh;
    overflow: hidden;
    background: #07101e;
  }

  .app-sidebar {
    display: flex;
    min-width: 0;
    flex-direction: column;
    padding: 1rem 0.8rem;
    border-right: 1px solid #1f2b40;
    background: #080f1c;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    min-height: 2.5rem;
    padding: 0 0.35rem;
    font-weight: 800;
  }

  .brand-mark {
    display: grid;
    width: 1.9rem;
    height: 1.9rem;
    place-items: center;
    border: 1px solid #7c3aed;
    border-radius: 7px;
    background: linear-gradient(135deg, #6d28d9, #312e81);
    font-size: 0.68rem;
  }

  .brand small {
    padding: 0.12rem 0.35rem;
    border: 1px solid #334155;
    border-radius: 4px;
    color: #8fa0bb;
    font-size: 0.55rem;
  }

  .new-analysis {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.45rem;
    margin-top: 1.25rem;
    padding: 0.68rem 0.8rem;
    background: #6d28d9;
    color: white;
  }

  .sidebar-nav {
    display: grid;
    gap: 0.25rem;
    margin-top: 1.25rem;
  }

  .sidebar-nav button {
    display: flex;
    align-items: center;
    justify-content: flex-start;
    gap: 0.7rem;
    padding: 0.62rem 0.7rem;
    border: 1px solid transparent;
    background: transparent;
    color: #93a3bd;
    font-size: 0.86rem;
    font-weight: 600;
    text-align: left;
  }

  .sidebar-nav button:hover:not(:disabled),
  .sidebar-nav button.active {
    border-color: #2d3a52;
    background: #121c2e;
    color: #f3f6fb;
  }

  .sidebar-nav button.active {
    box-shadow: inset 3px 0 #7c3aed;
  }

  .sidebar-nav button span {
    width: 1rem;
    color: #a78bfa;
    text-align: center;
  }

  .sidebar-status {
    display: flex;
    gap: 0.65rem;
    align-items: center;
    margin-top: auto;
    padding: 0.8rem;
    border: 1px solid #26334a;
    border-radius: 10px;
    background: #0d1626;
  }

  .sidebar-status > span {
    width: 0.55rem;
    height: 0.55rem;
    flex: 0 0 auto;
    border-radius: 50%;
    background: #f59e0b;
  }

  .sidebar-status > span.ready {
    background: #10b981;
    box-shadow: 0 0 10px rgb(16 185 129 / 55%);
  }

  .sidebar-status div {
    display: grid;
    gap: 0.15rem;
  }

  .sidebar-status strong {
    color: #dbe5f5;
    font-size: 0.75rem;
  }

  .sidebar-status small {
    color: #8292ad;
    font-size: 0.68rem;
  }

  .workspace {
    display: grid;
    min-width: 0;
    min-height: 0;
    grid-template-rows: auto auto minmax(0, 1fr);
    background: radial-gradient(circle at 75% -20%, rgb(76 29 149 / 13%), transparent 35%), #0a1322;
  }

  .workspace-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    padding: 1rem 1.4rem 0.85rem;
    border-bottom: 1px solid #1e2b40;
  }

  .workspace-header p {
    margin: 0 0 0.25rem;
    color: #7f8faa;
    font-size: 0.65rem;
    font-weight: 800;
    letter-spacing: 0.13em;
  }

  .workspace-header h1 {
    margin: 0;
    font-size: clamp(1.25rem, 2.5vw, 1.8rem);
  }

  .workspace-header > div:first-child > span {
    display: block;
    margin-top: 0.35rem;
    color: #8292ad;
    font-size: 0.78rem;
  }

  .header-actions {
    display: flex;
    flex: 0 0 auto;
    gap: 0.55rem;
  }

  .header-actions button {
    padding: 0.55rem 0.8rem;
    font-size: 0.78rem;
  }

  .workspace-tabs {
    display: flex;
    gap: 0.15rem;
    min-width: 0;
    padding: 0.55rem 1.25rem 0;
    border-bottom: 1px solid #1e2b40;
    overflow-x: auto;
  }

  .workspace-tabs button {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    flex: 0 0 auto;
    padding: 0.62rem 0.72rem;
    border: 0;
    border-bottom: 2px solid transparent;
    border-radius: 7px 7px 0 0;
    background: transparent;
    color: #8292ad;
    font-size: 0.76rem;
    font-weight: 650;
  }

  .workspace-tabs button:hover:not(:disabled),
  .workspace-tabs button.active {
    border-bottom-color: #8b5cf6;
    background: rgb(124 58 237 / 9%);
    color: #f4f1ff;
  }

  .workspace-tabs button span {
    color: #a78bfa;
  }

  .workspace-scroll {
    min-width: 0;
    min-height: 0;
    overflow: auto;
  }

  .workspace-scroll > .panel {
    width: 100%;
    max-width: none;
    min-height: 100%;
    margin: 0;
    padding: 1.25rem 1.4rem 3rem;
    border: 0;
    border-radius: 0;
    background: transparent;
  }

  .workspace-scroll > .panel > .phase,
  .workspace-scroll > .panel > h1,
  .workspace-scroll > .panel > .description {
    display: none;
  }

  .saved-projects,
  .ghidra-setup,
  .summary,
  .global-strings,
  .function-explorer {
    margin-top: 0;
  }

  .saved-projects.comparison-mode > :not(.project-comparison):not(.comparison-empty) {
    display: none;
  }

  .empty-workspace {
    display: grid;
    width: min(620px, 100%);
    justify-items: center;
    margin: clamp(3rem, 10vh, 7rem) auto 0;
    padding: 2.5rem;
    box-sizing: border-box;
    border: 1px solid #26344d;
    border-radius: 16px;
    background: linear-gradient(145deg, rgb(17 27 46 / 90%), rgb(10 19 34 / 75%));
    text-align: center;
  }

  .empty-workspace > span {
    display: grid;
    width: 3.5rem;
    height: 3.5rem;
    place-items: center;
    border: 1px solid #6d28d9;
    border-radius: 14px;
    background: rgb(109 40 217 / 15%);
    color: #a78bfa;
    font-size: 1.6rem;
  }

  .empty-workspace > p:first-of-type {
    margin: 1rem 0 0.3rem;
    color: #8b5cf6;
    font-size: 0.68rem;
    font-weight: 800;
    letter-spacing: 0.14em;
  }

  .empty-workspace h2 {
    margin: 0.25rem 0;
  }

  .empty-workspace p {
    max-width: 480px;
    color: #91a1ba;
    line-height: 1.55;
  }

  .empty-workspace button {
    margin-top: 0.6rem;
  }

  .empty-workspace.compact {
    margin-top: 3rem;
  }

  @media (max-width: 1050px) {
    .app-shell {
      grid-template-columns: 76px minmax(0, 1fr);
    }

    .brand {
      justify-content: center;
      padding: 0;
    }

    .brand > span:not(.brand-mark),
    .brand small,
    .new-analysis:not(:disabled),
    .sidebar-nav button:not(.active) {
      font-size: 0;
    }

    .new-analysis span,
    .sidebar-nav button span {
      width: auto;
      font-size: 1rem;
    }

    .sidebar-nav button,
    .new-analysis {
      justify-content: center;
    }

    .sidebar-status div {
      display: none;
    }

    .sidebar-status {
      justify-content: center;
    }
  }

  @media (max-width: 720px) {
    .workspace-header {
      align-items: flex-start;
      flex-direction: column;
    }

    .header-actions {
      width: 100%;
    }

    .header-actions button {
      flex: 1 1 0;
    }
  }

  /* Dense analysis workspace inspired by the validated target mockups. */
  .import-summary {
    display: none;
  }

  .summary {
    padding: 1rem;
    border: 1px solid #1d2a40;
    border-radius: 10px;
    background: #0b1423;
  }

  .summary h2 {
    margin: 0 0 0.85rem;
  }

  .summary-grid {
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.65rem;
  }

  .summary-grid div {
    min-height: 82px;
    padding: 0.8rem;
    border-color: #223149;
    background: #0e192b;
  }

  .summary-grid dt {
    font-size: 0.72rem;
  }

  .summary-grid dd {
    font-size: 1rem;
    line-height: 1.35;
  }

  .kpi-row {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr)) auto;
    gap: 0.7rem;
    margin-bottom: 0.8rem;
  }

  .kpi-card {
    min-width: 0;
    padding: 0.9rem 1rem;
    border: 1px solid #1d2a40;
    border-radius: 10px;
    background: #0b1423;
  }

  .kpi-card .detail-label {
    margin-bottom: 0.4rem;
  }

  .kpi-card strong {
    display: block;
    color: #f3f6fb;
    font-size: 1.4rem;
    line-height: 1.2;
  }

  .kpi-card span {
    display: block;
    margin-top: 0.3rem;
    color: #71819c;
    font-size: 0.7rem;
  }

  .kpi-card-ring {
    display: grid;
    place-items: center;
    padding: 0.6rem;
  }

  @media (max-width: 1180px) {
    .kpi-row {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .kpi-card-ring {
      grid-column: 1 / -1;
    }
  }

  .dashboard-insights {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.7rem;
    margin-top: 0.8rem;
  }

  .dashboard-insights article {
    min-width: 0;
    min-height: 210px;
    padding: 0.8rem;
    border: 1px solid #1d2a40;
    border-radius: 9px;
    background: #0b1423;
  }

  .dashboard-insights header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    margin-bottom: 0.65rem;
  }

  .dashboard-insights h3 {
    margin: 0;
    font-size: 0.78rem;
  }

  .dashboard-insights header button,
  .top-function button {
    padding: 0.25rem 0.4rem;
    background: transparent;
    color: #a78bfa;
    font-size: 0.68rem;
  }

  .dashboard-insights ul {
    display: grid;
    margin: 0;
    padding: 0;
    gap: 0.15rem;
    list-style: none;
  }

  .dashboard-insights li {
    display: grid;
    grid-template-columns: minmax(58px, auto) minmax(0, 1fr) auto;
    align-items: center;
    gap: 0.45rem;
    min-height: 25px;
    border-bottom: 1px solid #17243a;
    font-size: 0.7rem;
  }

  .dashboard-insights li span {
    overflow: hidden;
    color: #dbe5f5;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .dashboard-insights li code,
  .dashboard-insights li strong {
    color: #7dd3fc;
    font-size: 0.65rem;
  }

  .dashboard-insights p {
    color: #71819c;
    font-size: 0.75rem;
  }

  .top-function {
    display: grid;
    align-content: center;
    min-height: 140px;
    gap: 0.45rem;
  }

  .top-function > strong {
    color: #c4b5fd;
    font-size: 1.05rem;
  }

  .top-function > span {
    color: #8190a8;
    font-size: 0.72rem;
  }

  .section-toolbar,
  .function-list-heading {
    display: flex;
    align-items: end;
    justify-content: space-between;
    gap: 1rem;
  }

  .section-toolbar h2,
  .function-list-heading h2 {
    margin: 0.15rem 0 0;
    font-size: 1rem;
  }

  .graph-workspace {
    min-width: 0;
  }

  .graph-layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 220px;
    min-height: 610px;
    margin-top: 0.75rem;
    border: 1px solid #1e2c42;
    border-radius: 10px;
    background: #080f1c;
    overflow: hidden;
  }

  .graph-stage-wrap {
    position: relative;
    min-width: 0;
    padding: 0.75rem;
    overflow: auto;
    background-image: radial-gradient(#27364e 0.7px, transparent 0.7px);
    background-size: 18px 18px;
  }

  .graph-stage {
    position: relative;
    min-width: 100%;
    margin-top: 0.5rem;
  }

  .graph-edges {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    overflow: visible;
  }

  .graph-edges path:not(:first-child) {
    fill: none;
    stroke: #52627d;
    stroke-width: 1.5;
  }

  .graph-edges marker path {
    fill: #7183a3;
  }

  .visual-graph-node {
    position: absolute;
    display: grid;
    align-content: center;
    padding: 0.55rem 0.7rem;
    border: 1px solid #2563eb;
    border-radius: 7px;
    background: #102447;
    box-shadow: 0 10px 28px rgb(0 0 0 / 22%);
    color: #eaf2ff;
    text-align: center;
  }

  .visual-graph-node:hover:not(:disabled) {
    border-color: #60a5fa;
    background: #173464;
  }

  .visual-graph-node strong,
  .visual-graph-node code {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .visual-graph-node strong {
    font-size: 0.72rem;
  }

  .visual-graph-node code {
    margin-top: 0.25rem;
    color: #91a9ca;
    font-size: 0.62rem;
  }

  .visual-graph-node.root {
    border-color: #8b5cf6;
    background: #29205a;
    box-shadow: 0 0 0 2px rgb(139 92 246 / 18%);
  }

  .visual-graph-node.external {
    border-color: #7c3aed;
    background: #211845;
  }

  .visual-graph-node.thunk:not(.root) {
    border-color: #d97706;
    background: #3a2412;
  }

  .graph-legend {
    display: flex;
    flex-wrap: wrap;
    gap: 0.8rem;
    color: #8090aa;
    font-size: 0.66rem;
  }

  .graph-legend span::before {
    display: inline-block;
    width: 7px;
    height: 7px;
    margin-right: 0.35rem;
    border-radius: 2px;
    background: #2563eb;
    content: "";
  }

  .graph-legend .internal::before { background: #16a34a; }
  .graph-legend .external::before { background: #7c3aed; }
  .graph-legend .thunk::before { background: #d97706; }

  .graph-inspector {
    padding: 1rem;
    border-left: 1px solid #1e2c42;
    background: #0d1727;
  }

  .graph-inspector h3 {
    margin: 0.4rem 0;
    overflow-wrap: anywhere;
  }

  .graph-inspector > code { color: #93c5fd; }

  .graph-info-grid {
    padding-bottom: 0.9rem;
    margin-bottom: 0.9rem !important;
    border-bottom: 1px solid #1e2c42;
  }

  .graph-inspector dl {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.45rem;
    margin: 1rem 0;
  }

  .graph-inspector dl div {
    padding: 0.55rem;
    border: 1px solid #26354e;
    border-radius: 6px;
    background: #111e31;
  }

  .graph-inspector dt { color: #7f8faa; font-size: 0.65rem; }
  .graph-inspector dd { margin: 0.25rem 0 0; font-size: 0.78rem; }
  .graph-inspector button { width: 100%; padding: 0.55rem; font-size: 0.72rem; }
  .graph-message { margin: 4rem auto; color: #8292ad; text-align: center; }

  .compact-controls {
    margin: 0;
  }

  .compact-controls label {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.68rem;
  }

  .compact-controls select,
  .compact-controls input {
    width: auto;
    padding: 0.38rem 0.5rem;
    font-size: 0.7rem;
  }

  .function-explorer {
    grid-template-columns: 330px minmax(0, 1fr);
    gap: 0.7rem;
    margin-top: 0;
    padding-top: 0;
    border-top: 0;
  }

  .function-list-heading {
    grid-column: 1 / -1;
    align-items: center;
    padding-bottom: 0.65rem;
    border-bottom: 1px solid #1d2a40;
  }

  .function-list-heading > div {
    display: flex;
    align-items: baseline;
    gap: 0.55rem;
  }

  .function-list-heading span {
    color: #74849e;
    font-size: 0.68rem;
  }

  .function-list-heading input {
    width: min(320px, 45vw);
    padding: 0.5rem 0.7rem;
    font-size: 0.72rem;
  }

  .function-table-wrap {
    max-height: calc(100vh - 220px);
    border-color: #1d2a40;
  }

  .function-table thead th {
    background-color: #101d30;
  }

  .function-details {
    max-height: calc(100vh - 220px);
    padding: 1rem;
    border-color: #1d2a40;
    border-radius: 8px;
    background: #0b1423;
  }

  .function-details-header h3 { font-size: 1.2rem; }

  .function-metadata {
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 0.45rem;
  }

  .function-metadata div {
    padding: 0.55rem;
    border-color: #25344c;
    background: #101d30;
  }

  .function-section {
    margin-top: 0.9rem;
  }

  .function-section h4 {
    margin-bottom: 0.5rem;
    color: #a78bfa;
    font-size: 0.82rem;
  }

  .function-section li {
    padding: 0.5rem;
    border-color: #25344c;
    background: #101d30;
    font-size: 0.72rem;
  }

  @media (max-width: 1180px) {
    .dashboard-insights { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .graph-layout { grid-template-columns: minmax(0, 1fr); }
    .graph-inspector { border-top: 1px solid #1e2c42; border-left: 0; }
  }

  /* Overview: compact three-column composition matching the target dashboard. */
  .app-shell {
    grid-template-columns: 176px minmax(0, 1fr);
  }

  .app-sidebar {
    padding: 0.65rem 0.55rem;
  }

  .brand {
    gap: 0.4rem;
    padding: 0 0.2rem;
    font-size: 0.76rem;
    white-space: nowrap;
  }

  .brand-mark {
    width: 1.55rem;
    height: 1.55rem;
  }

  .brand small { font-size: 0.48rem; }
  .new-analysis { margin-top: 0.8rem; padding: 0.55rem; font-size: 0.72rem; }
  .sidebar-nav { margin-top: 0.8rem; }
  .sidebar-nav button { padding: 0.48rem 0.5rem; font-size: 0.72rem; }
  .sidebar-status { padding: 0.6rem; }

  .workspace-header {
    padding: 0.65rem 0.9rem 0.55rem;
  }

  .workspace-header p { margin-bottom: 0.15rem; font-size: 0.55rem; }
  .workspace-header h1 { font-size: 1.15rem; }
  .workspace-header > div:first-child > span { margin-top: 0.2rem; font-size: 0.65rem; }
  .header-actions button { padding: 0.42rem 0.65rem; font-size: 0.66rem; }

  .workspace-tabs {
    padding: 0.25rem 0.85rem 0;
  }

  .workspace-tabs button {
    padding: 0.48rem 0.62rem;
    border-radius: 0;
    font-size: 0.64rem;
  }

  .workspace-tabs button:hover:not(:disabled),
  .workspace-tabs button.active {
    background: transparent;
  }

  .workspace-scroll > .panel {
    padding: 0.7rem 0.85rem 1.5rem;
  }

  .kpi-row {
    grid-template-columns: repeat(4, minmax(0, 1fr)) 150px;
    gap: 0.45rem;
    margin-bottom: 0.55rem;
  }

  .kpi-card {
    min-height: 72px;
    padding: 0.6rem 0.7rem;
    border-radius: 7px;
    background: #0a1423;
  }

  .kpi-card .detail-label { margin-bottom: 0.25rem; font-size: 0.56rem; }
  .kpi-card strong { font-size: 1rem; }
  .kpi-card span { margin-top: 0.2rem; font-size: 0.56rem; }
  .kpi-card-ring { min-height: 72px; padding: 0.25rem; }

  .overview-dashboard {
    display: grid;
    gap: 0.5rem;
  }

  .overview-main-grid {
    display: grid;
    grid-template-columns: minmax(245px, 0.86fr) minmax(360px, 1.25fr) minmax(310px, 1fr);
    gap: 0.5rem;
    min-height: 348px;
  }

  .overview-card {
    min-width: 0;
    border: 1px solid #1d2a40;
    border-radius: 7px;
    background: #091321;
    overflow: hidden;
  }

  .overview-card-header {
    display: flex;
    min-height: 35px;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    padding: 0.55rem 0.65rem;
    border-bottom: 1px solid #19263a;
  }

  .overview-card-header h2 {
    margin: 0;
    font-size: 0.68rem;
  }

  .overview-card-header span {
    display: block;
    margin-top: 0.15rem;
    color: #62728c;
    font-size: 0.52rem;
  }

  .overview-card-link {
    padding: 0.25rem 0.4rem;
    background: transparent;
    color: #a78bfa;
    font-size: 0.55rem;
  }

  .overview-graph-actions {
    display: flex;
    align-items: center;
    gap: 0.35rem;
  }

  .overview-graph-actions button,
  .graph-back-button {
    padding: 0.3rem 0.45rem;
    border: 1px solid #4c3a83;
    background: #201743;
    color: #c4b5fd;
    font-size: 0.68rem;
  }

  .overview-graph-actions button:disabled,
  .graph-back-button:disabled {
    border-color: #253149;
    background: #111a2a;
    color: #53617a;
    cursor: not-allowed;
    opacity: 1;
  }

  .important-functions-card table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }

  .important-functions-card th {
    padding: 0.38rem 0.5rem;
    color: #60708a;
    font-size: 0.5rem;
    font-weight: 600;
    text-align: left;
  }

  .important-functions-card th:first-child { width: 44%; }
  .important-functions-card th:nth-child(2) { width: 40%; }
  .important-functions-card th:last-child { width: 16%; text-align: right; }

  .important-functions-card td {
    padding: 0.35rem 0.5rem;
    border-top: 1px solid #142136;
    font-size: 0.56rem;
    overflow: hidden;
  }

  .important-functions-card tr.selected { background: #1c1740; }
  .important-functions-card td:last-child { color: #86efac; text-align: right; }

  .important-functions-card td > button {
    display: block;
    max-width: 100%;
    padding: 0;
    background: transparent;
    color: #dbe7f8;
    font-size: 0.58rem;
    font-weight: 650;
    overflow: hidden;
    text-align: left;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .important-functions-card td > code {
    display: block;
    margin-top: 0.1rem;
    color: #55749c;
    font-size: 0.48rem;
  }

  .identification-badge {
    display: block;
    color: #86efac;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .muted-value { color: #46566f; }

  .important-functions-card > .overview-card-link {
    display: block;
    width: calc(100% - 1rem);
    margin: 0.35rem 0.5rem 0;
    border-top: 1px solid #17243a;
    text-align: center;
  }

  .overview-graph-card {
    display: grid;
    grid-template-rows: auto minmax(0, 1fr) auto;
  }

  .overview-graph-scroll {
    min-height: 0;
    overflow: auto hidden;
    background-image: radial-gradient(#26354d 0.55px, transparent 0.55px);
    background-size: 15px 15px;
  }

  .overview-graph-stage {
    position: relative;
    margin: 0 auto;
  }

  .overview-graph-stage svg {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
  }

  .overview-edge { fill: none; stroke: #52627d; stroke-width: 1.3; }
  #overview-arrow path { fill: #7183a3; }

  .overview-graph-node {
    position: absolute;
    display: grid;
    align-content: center;
    padding: 0.35rem;
    border: 1px solid #2563eb;
    border-radius: 5px;
    background: #102447;
    color: #edf5ff;
    text-align: center;
  }

  .overview-graph-node strong,
  .overview-graph-node code {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .overview-graph-node strong { font-size: 0.54rem; }
  .overview-graph-node code { margin-top: 0.12rem; color: #8399b8; font-size: 0.45rem; }
  .overview-graph-node.root { border-color: #8b5cf6; background: #29205a; }
  .overview-graph-node.external { border-color: #7c3aed; background: #211845; }
  .overview-graph-node.thunk:not(.root) { border-color: #d97706; background: #38220f; }

  .overview-graph-legend {
    display: flex;
    justify-content: center;
    gap: 0.7rem;
    padding: 0.35rem;
    border-top: 1px solid #17243a;
    color: #687994;
    font-size: 0.48rem;
  }

  .overview-graph-legend span::before {
    display: inline-block;
    width: 6px;
    height: 6px;
    margin-right: 0.25rem;
    border-radius: 1px;
    background: #2563eb;
    content: "";
  }

  .overview-graph-legend .root::before { background: #8b5cf6; }
  .overview-graph-legend .external::before { background: #7c3aed; }
  .overview-graph-legend .thunk::before { background: #d97706; }

  .selected-function-card { padding: 0.65rem; }

  .selected-function-heading {
    display: flex;
    align-items: start;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .selected-function-heading h2 { margin: 0.2rem 0 0.15rem; font-size: 0.85rem; }
  .selected-function-heading > div > code { color: #6882a5; font-size: 0.52rem; }

  .function-kind-badge {
    padding: 0.18rem 0.35rem;
    border: 1px solid #16a34a;
    border-radius: 4px;
    background: #0c2b20;
    color: #86efac;
    font-size: 0.5rem;
  }

  .overview-detail-tabs {
    display: flex;
    margin-top: 0.55rem;
    border-bottom: 1px solid #1d2a40;
    overflow-x: auto;
  }

  .overview-detail-tabs button {
    flex: 0 0 auto;
    padding: 0.35rem 0.42rem;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    background: transparent;
    color: #71819a;
    font-size: 0.5rem;
  }

  .overview-detail-tabs button.active { border-bottom-color: #8b5cf6; color: #e4dcff; }
  .overview-function-content { padding-top: 0.55rem; }
  .mini-label { margin: 0 0 0.28rem; color: #71819a; font-size: 0.5rem; }

  .prototype-line {
    display: block;
    padding: 0.45rem;
    border: 1px solid #1c2a40;
    border-radius: 4px;
    background: #0d192a;
    color: #d8cfff;
    font-size: 0.52rem;
    overflow-wrap: anywhere;
  }

  .evidence-list,
  .compact-detail-list {
    display: grid;
    margin: 0;
    padding: 0;
    gap: 0.28rem;
    list-style: none;
  }

  .evidence-list li {
    color: #71819a;
    font-size: 0.54rem;
  }

  .evidence-list li::before { margin-right: 0.35rem; color: #64748b; content: "○"; }
  .evidence-list li.available { color: #b7c6dc; }
  .evidence-list li.available::before { color: #22c55e; content: "✓"; }

  .overview-code-preview {
    max-height: 190px;
    margin-top: 0.5rem;
    overflow: auto;
  }

  .overview-code-preview pre { margin: 0; font-size: 0.5rem; white-space: pre; }
  .compact-detail-list { margin-top: 0.5rem; }
  .compact-detail-list li { display: flex; justify-content: space-between; gap: 0.4rem; color: #8292ac; font-size: 0.54rem; }
  .selected-function-card > .overview-card-link { width: 100%; margin-top: 0.5rem; border-top: 1px solid #17243a; }

  .overview-bottom-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.5rem;
  }

  .compact-overview-card {
    display: grid;
    min-height: 165px;
    grid-template-rows: auto minmax(0, 1fr) auto;
  }

  .overview-data-list {
    display: grid;
    align-content: start;
    margin: 0;
    padding: 0.25rem 0.65rem;
    list-style: none;
  }

  .overview-data-list li {
    display: grid;
    grid-template-columns: minmax(55px, auto) minmax(0, 1fr) auto;
    align-items: center;
    gap: 0.4rem;
    min-height: 22px;
    border-bottom: 1px solid #142136;
    font-size: 0.52rem;
  }

  .overview-data-list li span {
    overflow: hidden;
    color: #b9c7da;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .overview-data-list li code { color: #6081aa; font-size: 0.47rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .overview-data-list li strong { color: #86efac; }
  .compact-overview-card > .overview-card-link { width: calc(100% - 1rem); margin: 0 0.5rem; border-top: 1px solid #17243a; }
  .overview-empty { margin: auto; padding: 1rem; color: #65758e; font-size: 0.58rem; text-align: center; }

  .comparison-preview-card > strong,
  .comparison-preview-card > p { margin: 0.6rem 0.7rem 0; }
  .comparison-preview-card > strong { color: #c4b5fd; font-size: 0.8rem; }
  .comparison-preview-card > p { color: #71819a; font-size: 0.55rem; }
  .comparison-preview-card > button { margin: 0.5rem 0.7rem; padding: 0.4rem; background: #6d28d9; color: white; font-size: 0.55rem; }

  @media (max-width: 1320px) {
    .overview-main-grid { grid-template-columns: minmax(235px, 0.9fr) minmax(330px, 1.15fr) minmax(285px, 1fr); }
    .overview-bottom-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }

  @media (max-width: 980px) {
    .overview-main-grid { grid-template-columns: 1fr; }
    .overview-main-grid > .overview-card { min-height: 330px; }
    .kpi-row { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .kpi-card-ring { grid-column: auto; }
  }

  /* Readability pass validated against the full-screen overview capture. */
  .brand { font-size: 0.86rem; }
  .new-analysis,
  .sidebar-nav button { font-size: 0.8rem; }
  .sidebar-status strong { font-size: 0.72rem; }
  .sidebar-status small { font-size: 0.65rem; }
  .workspace-header h1 { font-size: 1.28rem; }
  .workspace-header > div:first-child > span { font-size: 0.72rem; }
  .header-actions button { font-size: 0.72rem; }
  .workspace-tabs button { font-size: 0.72rem; }

  .kpi-card .detail-label { font-size: 0.66rem; }
  .kpi-card strong { font-size: 1.15rem; }
  .kpi-card span { font-size: 0.64rem; line-height: 1.3; }
  .kpi-card-ring { min-width: 145px; }

  .overview-card-header h2 { font-size: 0.8rem; }
  .overview-card-header span { font-size: 0.62rem; }
  .overview-card-link { font-size: 0.65rem; }
  .important-functions-card th { font-size: 0.6rem; }
  .important-functions-card td { font-size: 0.67rem; }
  .important-functions-card td > button { font-size: 0.68rem; }
  .important-functions-card td > code { font-size: 0.56rem; }
  .overview-graph-node strong { font-size: 0.63rem; }
  .overview-graph-node code { font-size: 0.54rem; }
  .overview-graph-legend { font-size: 0.58rem; }

  .selected-function-heading h2 { font-size: 1rem; }
  .selected-function-heading > div > code { font-size: 0.62rem; }
  .function-kind-badge { font-size: 0.6rem; }
  .overview-detail-tabs button { font-size: 0.62rem; }
  .mini-label { font-size: 0.62rem; }
  .prototype-line { font-size: 0.64rem; }
  .evidence-list li,
  .compact-detail-list li { font-size: 0.64rem; }
  .overview-code-preview pre { font-size: 0.62rem; }

  .overview-data-list li { min-height: 25px; font-size: 0.64rem; }
  .overview-data-list li code { font-size: 0.57rem; }
  .overview-empty { font-size: 0.67rem; line-height: 1.4; }
  .comparison-preview-card > strong { font-size: 0.9rem; }
  .comparison-preview-card > p,
  .comparison-preview-card > button { font-size: 0.65rem; }

  /* Second readability step requested after visual review. */
  .workspace-header p { font-size: 0.64rem; }
  .workspace-header h1 { font-size: 1.44rem; }
  .workspace-header > div:first-child > span { font-size: 0.82rem; }
  .workspace-tabs button { font-size: 0.82rem; }
  .header-actions button { font-size: 0.82rem; }

  .kpi-card .detail-label { font-size: 0.76rem; }
  .kpi-card strong { font-size: 1.34rem; }
  .kpi-card span { font-size: 0.74rem; }

  .overview-card-header h2 { font-size: 0.95rem; }
  .overview-card-header span { font-size: 0.72rem; }
  .overview-card-link { font-size: 0.76rem; }
  .important-functions-card th { font-size: 0.7rem; }
  .important-functions-card td { font-size: 0.78rem; }
  .important-functions-card td > button { font-size: 0.8rem; }
  .important-functions-card td > code { font-size: 0.66rem; }
  .overview-graph-node strong { font-size: 0.74rem; }
  .overview-graph-node code { font-size: 0.64rem; }
  .overview-graph-legend { font-size: 0.68rem; }

  .selected-function-heading h2 { font-size: 1.16rem; }
  .selected-function-heading > div > code { font-size: 0.72rem; }
  .function-kind-badge { font-size: 0.71rem; }
  .overview-detail-tabs button { font-size: 0.73rem; }
  .mini-label { font-size: 0.72rem; }
  .prototype-line { font-size: 0.75rem; }
  .evidence-list li,
  .compact-detail-list li { font-size: 0.75rem; }
  .overview-code-preview pre { font-size: 0.72rem; }

  .overview-data-list li { min-height: 29px; font-size: 0.75rem; }
  .overview-data-list li code { font-size: 0.67rem; }
  .overview-empty { font-size: 0.78rem; }
  .comparison-preview-card > p,
  .comparison-preview-card > button { font-size: 0.72rem; }

  /* Functions workspace: dense, readable and limited to one useful graph preview. */
  .function-explorer {
    grid-template-columns: minmax(430px, 0.9fr) minmax(680px, 2.1fr);
    gap: 0.8rem;
  }

  .function-list-heading h2 {
    margin: 0;
    font-size: 1.08rem;
  }

  .function-list-heading input {
    width: min(390px, 40vw);
    border-color: #293a55;
    background: #0b1423;
  }

  .function-table-wrap,
  .function-details {
    max-height: calc(100vh - 205px);
  }

  .function-table {
    table-layout: fixed;
    font-size: 0.72rem;
  }

  .function-table th:nth-child(1) { width: 28%; }
  .function-table th:nth-child(2) { width: 18%; }
  .function-table th:nth-child(3) { width: 13%; }
  .function-table th:nth-child(4) { width: 9%; text-align: center; }
  .function-table th:nth-child(5) { width: 32%; }

  .function-table tbody td {
    padding: 0.58rem 0.62rem;
    overflow: hidden;
    text-overflow: ellipsis;
    overflow-wrap: normal;
    white-space: nowrap;
  }

  .function-table tbody td:nth-child(4) { text-align: center; }

  .function-table-name {
    display: block;
    width: 100%;
    overflow: hidden;
    color: #f3f6fb;
    font-size: 0.76rem;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .function-details {
    padding: 0.85rem 1rem 1rem;
  }

  .function-details-header {
    padding-bottom: 0.7rem;
  }

  .function-details-header h3 {
    margin: 0.15rem 0 0.25rem;
    font-size: 1.18rem;
  }

  .function-details-header code { font-size: 0.7rem; }

  .function-metadata {
    margin: 0.65rem 0 0.2rem;
    gap: 0.35rem;
  }

  .function-metadata div {
    display: flex;
    min-height: 46px;
    flex-direction: column;
    justify-content: center;
    padding: 0.42rem 0.55rem;
  }

  .function-metadata dt { font-size: 0.65rem; }
  .function-metadata dd { margin-top: 0.18rem; font-size: 0.78rem; }
  .function-metadata dd code { font-size: 0.72rem; }

  .detail-tabs {
    margin-top: 0.55rem;
    padding-bottom: 0;
    gap: 0.7rem;
  }

  .detail-tabs button {
    padding: 0.42rem 0.1rem;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    font-size: 0.7rem;
  }

  .detail-tabs button:hover:not(.active),
  .detail-tabs button.active {
    border-bottom-color: #8b5cf6;
    background: transparent;
  }

  .function-overview-grid {
    display: grid;
    grid-template-columns: minmax(250px, 0.78fr) minmax(420px, 1.22fr);
    gap: 0.8rem;
    align-items: stretch;
  }

  .function-overview-primary {
    min-width: 0;
  }

  .function-prototype-card > code {
    display: block;
    padding: 0.65rem 0.75rem;
    border: 1px solid #25344c;
    border-radius: 6px;
    background: #101d30;
    color: #d8c8ff;
    font-size: 0.73rem;
    overflow-x: auto;
    white-space: nowrap;
  }

  .function-graph-preview {
    min-width: 0;
    padding-left: 0.8rem;
    border-left: 1px solid #1d2a40;
  }

  .function-section-heading > div:first-child span {
    color: #70819c;
    font-size: 0.62rem;
  }

  .function-graph-actions {
    display: flex;
    gap: 0.3rem;
  }

  .function-graph-actions button {
    white-space: nowrap;
  }

  .function-graph-scroll {
    width: 100%;
    min-height: 282px;
    overflow-x: auto;
    border: 1px solid #1d2a40;
    border-radius: 7px;
    background-color: #091423;
    background-image: radial-gradient(circle, #26344a 0.8px, transparent 0.8px);
    background-size: 17px 17px;
  }

  .function-graph-scroll .overview-graph-stage {
    margin: 0 auto;
    background: transparent;
  }

  .compact-rename-control {
    padding: 0.75rem;
    border: 1px solid #283954;
    border-radius: 7px;
    background: #0e1a2d;
  }

  .compact-rename-control .rename-heading h4 { margin-bottom: 0.15rem; }
  .compact-rename-control .rename-heading p { margin: 0 0 0.6rem; font-size: 0.7rem; }
  .compact-rename-control input { font-size: 0.75rem; }
  .compact-rename-control button { flex: 0 0 auto; padding: 0.5rem 0.75rem; font-size: 0.7rem; }

  @media (max-width: 1320px) {
    .function-explorer { grid-template-columns: minmax(370px, 0.9fr) minmax(580px, 2fr); }
    .function-overview-grid { grid-template-columns: 1fr; }
    .function-graph-preview { padding-left: 0; border-top: 1px solid #1d2a40; border-left: 0; }
  }

  @media (max-width: 980px) {
    .function-explorer { grid-template-columns: 1fr; }
    .function-list-heading { grid-column: 1; }
    .function-table-wrap { max-height: 400px; }
    .function-details { max-height: none; }
  }


</style>
