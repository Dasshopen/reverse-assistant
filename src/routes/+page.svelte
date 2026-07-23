<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open, save } from "@tauri-apps/plugin-dialog";

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

  let selectedFunction = $derived(
    importedExport?.functions.find(
      (func) => func.entry_address === selectedFunctionAddress,
    ) ?? null,
  );

  let importError = $state("");
  let isImporting = $state(false);

  let ghidraInstallationStatus = $state<GhidraInstallationStatus | null>(null);
  let ghidraConfigError = $state("");
  let isConfiguringGhidra = $state(false);
  let analyzeError = $state("");
  let isAnalyzing = $state(false);

  let analysisSource = $state<"none" | "automatic" | "manual">("none");
  let activeProjectId = $state<string | null>(null);

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

  let callGraphDirection = $state<CallGraphDirection>("outgoing");
  let callGraphDepth = $state(3);
  let callGraphResult = $state<CallGraphNeighborhood | null>(null);
  let callGraphError = $state("");
  let isLoadingCallGraph = $state(false);
  let callGraphRequestSeq = 0;

  let callGraphNodesByDepth = $derived.by(() => {
    if (!callGraphResult) return [];

    const groups: { depth: number; nodes: CallGraphNode[] }[] = [];

    for (const node of callGraphResult.nodes) {
      const currentGroup = groups.at(-1);

      if (currentGroup && currentGroup.depth === node.depth) {
        currentGroup.nodes.push(node);
      } else {
        groups.push({ depth: node.depth, nodes: [node] });
      }
    }

    return groups;
  });

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
  let selectedBsimResult = $derived(enrichedDetails?.bsim ?? null);

  $effect(() => {
    const address = selectedFunctionAddress;
    if (address === renameDraftAddress) return;
    renameDraftAddress = address;
    const func = selectedFunction;
    functionRenameDraft = func?.name ?? "";
    functionRenameError = "";
    functionRenameSuccess = "";
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

    try {
      const loaded = await invoke<LoadedProject>("open_project", { id });

      importedExport = loaded.export;
      selectedFunctionAddress = loaded.export.functions[0]?.entry_address ?? null;
      // A currently-available session (Ghidra project files genuinely
      // present right now, just re-verified by the backend) keeps
      // on-demand decompilation working, exactly like a fresh automatic
      // analysis. Anything else -- no session at all, or one whose Ghidra
      // project is unreachable this time -- behaves like a manual import.
      analysisSource = loaded.project.session_available ? "automatic" : "manual";
      activeProjectId = loaded.project.id;
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
      const installation = await invoke<GhidraInstallation>(
        "configure_ghidra_installation",
        { installDir },
      );

      ghidraInstallationStatus = { status: "valid", installation };
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

    isAnalyzing = true;

    try {
      const result = await invoke<AutomaticAnalysisResult>(
        "analyze_binary_with_ghidra",
        { binaryPath },
      );

      importedExport = result.imported.export;
      importSummary = result.imported.summary;
      selectedFunctionAddress =
        result.imported.export.functions[0]?.entry_address ?? null;
      analysisSource = "automatic";
      activeProjectId = result.saved_project?.id ?? null;
      identifications = new Map(
        result.identifications.map((identification) => [
          identification.entry_address,
          identification.candidates,
        ]),
      );
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
      selectedFunctionAddress =
        imported.export.functions[0]?.entry_address ?? null;
      analysisSource = "manual";
      activeProjectId = null;
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

<main class="container">
  <section class="panel">
    <p class="phase">Phase 7 — Ghidra Headless automation</p>

    <h1>Reverse Assistant</h1>

    <p class="description">
      Analyze a binary directly, or import an existing Ghidra JSON export.
    </p>

    <section class="saved-projects" aria-labelledby="saved-projects-title">
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
        <section class="project-comparison" aria-labelledby="project-comparison-title">
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
      {/if}
    </section>

    <section class="ghidra-setup" aria-labelledby="ghidra-setup-title">
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

    <h2 class="manual-import-title">Manual JSON import (debug)</h2>

    <form
      class="import-form"
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
      <p class="error" role="alert">{importError}</p>
    {/if}

    {#if importSummary}
      <section class="summary" aria-labelledby="summary-title">
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

    {#if importedExport}
      <section class="summary" aria-labelledby="program-overview-title">
        <h2 id="program-overview-title">Overview</h2>

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

      <section class="global-strings" aria-labelledby="global-strings-title">
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
                          disabled={fn.entry_address === selectedFunctionAddress}
                          onclick={() => {
                            selectedFunctionAddress = fn.entry_address;
                          }}
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
      <section class="global-strings" aria-labelledby="imports-title">
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
                      disabled={entry.entry_address === selectedFunctionAddress}
                      onclick={() => {
                        selectedFunctionAddress = entry.entry_address;
                      }}
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
      <section class="global-strings" aria-labelledby="external-entry-points-title">
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
                        disabled={entry.address === selectedFunctionAddress}
                        onclick={() => {
                          selectedFunctionAddress = entry.address;
                        }}
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

      <section class="global-strings" aria-labelledby="detected-types-title">
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
                                  disabled={usage.function_address === selectedFunctionAddress}
                                  onclick={() => {
                                    selectedFunctionAddress = usage.function_address;
                                  }}
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
      <section class="function-explorer" aria-labelledby="functions-title">
        <h2 id="functions-title">Functions</h2>

        {#if importedExport.functions.length === 0}
          <p>No functions were found in this export.</p>
        {:else}
          <ul class="function-list">
            {#each importedExport.functions as func (func.entry_address)}
              <li>
                <button
                  type="button"
                  class:active={func.entry_address === selectedFunctionAddress}
                  aria-pressed={func.entry_address === selectedFunctionAddress}
                  onclick={() => {
                    selectedFunctionAddress = func.entry_address;
                  }}
                >
                  <span>{func.name}</span>
                  <code>{func.entry_address}</code>
                </button>
              </li>
            {/each}
          </ul>

        {#if selectedFunction}
          <article
            class="function-details"
            aria-labelledby="function-details-title"
          >
            <header class="function-details-header">
              <div>
                <p class="detail-label">Selected function</p>
                <h3 id="function-details-title">{selectedFunction.name}</h3>
                <code>{selectedFunction.entry_address}</code>
              </div>

              <div class="function-flags">
                <span>{selectedFunction.is_external ? "External" : "Internal"}</span>

                {#if selectedFunction.is_thunk}
                  <span>Thunk</span>
                {/if}
              </div>
            </header>

            <dl class="function-metadata">
              <div>
                <dt>Return type</dt>
                <dd><code>{displayedReturnType}</code></dd>
              </div>

              <div>
                <dt>Parameters</dt>
                <dd>{displayedParameters.length}</dd>
              </div>

              <div>
                <dt>Calls</dt>
                <dd>{selectedFunction.calls.length}</dd>
              </div>

            <div>
                <dt>Strings</dt>
                <dd>{selectedFunction.strings.length}</dd>
              </div>

              {#if displayedCallingConvention}
                <div>
                  <dt>Calling convention</dt>
                  <dd><code>{displayedCallingConvention}</code></dd>
                </div>
              {/if}
            </dl>

            {#if analysisSource === "automatic" && activeProjectId && !selectedFunction.is_external}
              <section class="function-section ghidra-rename-control">
                <h4>Apply a function name to Ghidra</h4>
                <p>
                  This writes a user-confirmed name into the live Ghidra project, then refreshes
                  the local snapshot. It never applies FunctionID or BSim suggestions automatically.
                </p>
                <div>
                  <input type="text" maxlength="512" bind:value={functionRenameDraft} />
                  <button
                    type="button"
                    disabled={isApplyingFunctionRename || functionRenameDraft.trim() === selectedFunction.name}
                    onclick={applySelectedFunctionRename}
                  >
                    {isApplyingFunctionRename ? "Applying..." : "Apply rename"}
                  </button>
                </div>
                {#if functionRenameError}
                  <p class="error" role="alert">{functionRenameError}</p>
                {/if}
                {#if functionRenameSuccess}
                  <p class="status">{functionRenameSuccess}</p>
                {/if}
              </section>
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

            <section class="function-section">
              <h4>Graphe d'appels</h4>

              <div class="call-graph-controls">
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
                  <input
                    type="number"
                    min="1"
                    max="5"
                    bind:value={callGraphDepth}
                  />
                </label>
              </div>

              {#if isLoadingCallGraph}
                <p>Chargement du graphe d'appels...</p>
              {:else if callGraphError}
                <p class="error" role="alert">{callGraphError}</p>
              {:else if callGraphResult}
                <p class="call-graph-stats">
                  {callGraphResult.nodes.length} fonctions · {callGraphResult.edges.length} appels ·
                  profondeur atteinte {callGraphResult.depth_reached}
                </p>

                {#each callGraphNodesByDepth as group (group.depth)}
                  <div class="call-graph-depth-group">
                    <p class="detail-label">
                      {group.depth === 0 ? "Fonction sélectionnée" : `Niveau ${group.depth}`}
                    </p>

                    <ul class="call-graph-node-list">
                      {#each group.nodes as node (node.entry_address)}
                        <li>
                          <button
                            type="button"
                            class="call-graph-node"
                            disabled={node.entry_address === selectedFunctionAddress}
                            onclick={() => {
                              selectedFunctionAddress = node.entry_address;
                            }}
                          >
                            <span>
                              {node.name}
                              {#if node.is_external}<em>(externe)</em>{/if}
                              {#if node.is_thunk}<em>(thunk)</em>{/if}
                            </span>
                            <code>{node.entry_address}</code>
                          </button>
                        </li>
                      {/each}
                    </ul>
                  </div>
                {/each}
              {/if}
            </section>

            <section class="function-section">
            <h4>Parameters</h4>

              {#if displayedParameters.length === 0}
                <p>No parameters were identified.</p>
              {:else}
                <ul>
                  {#each displayedParameters as parameter}
                    <li>
                    <code>{parameter.data_type}</code>
                      <span>{parameter.name}</span>
                    </li>
                  {/each}
              </ul>
            {/if}
          </section>

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
      </article>
    {/if}
  {/if}
</section>
{/if}

    <div class="backend-check">
      <button type="button" class="secondary-button" onclick={checkBackendStatus}>
        Check Rust backend
      </button>

      {#if backendStatus}
        <p class="status">{backendStatus}</p>
      {/if}
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

  .container {
    min-height: 100vh;
    box-sizing: border-box;
    padding: 3rem 1.5rem;
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

  .function-explorer > h2,
  .function-explorer > p {
    grid-column: 1 / -1;
    margin: 0;
  }

  .function-list {
    display: grid;
    max-height: 720px;
    margin: 0;
    padding: 0;
    gap: 0.5rem;
    overflow-y: auto;
    list-style: none;
  }

  .function-list button {
    display: flex;
    width: 100%;
    min-width: 0;
    padding: 0.75rem;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    border: 1px solid #374151;
    border-radius: 0.5rem;
    background-color: #1f2937;
    color: #f9fafb;
    text-align: left;
    cursor: pointer;
  }

  .function-list button:hover {
    border-color: #60a5fa;
    background-color: #273449;
  }

  .function-list button.active {
    border-color: #3b82f6;
    background-color: #1e3a5f;
  }

  .function-list button span {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .function-list code {
    flex-shrink: 0;
    color: #93c5fd;
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

  .function-section {
    margin-top: 1.25rem;
  }

  .function-section h4 {
    margin: 0 0 0.75rem;
    color: #67e8f9;
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

  .call-graph-depth-group {
    margin-bottom: 1rem;
  }

  .call-graph-depth-group:last-child {
    margin-bottom: 0;
  }

  .call-graph-node-list {
    display: grid;
    margin: 0.35rem 0 0;
    padding: 0;
    gap: 0.5rem;
    list-style: none;
  }

  .call-graph-node-list li {
    display: contents;
  }

  .call-graph-node {
    display: flex;
    width: 100%;
    box-sizing: border-box;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    padding: 0.65rem;
    border: 1px solid #374151;
    border-radius: 0.5rem;
    background-color: #1f2937;
    color: #f9fafb;
    text-align: left;
    cursor: pointer;
    overflow-wrap: anywhere;
  }

  .call-graph-node:hover:not(:disabled) {
    border-color: #60a5fa;
    background-color: #273449;
  }

  .call-graph-node:disabled {
    border-color: #3b82f6;
    background-color: #1e3a5f;
    cursor: default;
    opacity: 1;
  }

  .call-graph-node em {
    margin-left: 0.35rem;
    color: #94a3b8;
    font-style: normal;
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

    .function-list {
    min-width: 0;
    overflow-x: hidden;
  }

  .function-list li {
    min-width: 0;
  }

  .function-list button {
    box-sizing: border-box;
    min-width: 0;
    max-width: 100%;
    overflow: hidden;
  }

  .function-list button span {
    flex: 1 1 auto;
  }

  .function-list code {
    flex: 0 0 auto;
    white-space: nowrap;
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

    .function-explorer > h2,
    .function-explorer > p {
      grid-column: 1;
    }

    .function-metadata {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }


</style>
