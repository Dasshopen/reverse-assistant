<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { open, save } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import SetupAssistant from "$lib/SetupAssistant.svelte";
  import ProgressRing from "$lib/ProgressRing.svelte";

  interface GhidraImportSummary {
    function_count: number;
    external_function_count: number;
    decompiled_function_count: number;
    call_count: number;
    string_count: number;
  }

  interface AnalysisProgress {
    stage: string;
    message: string;
    completed_percent: number | null;
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
  rtti_class_names: string[];
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

type SetupComponentState = "ready" | "missing" | "invalid";

interface SetupComponentStatus {
  id: string;
  label: string;
  state: SetupComponentState;
  version: string | null;
  path: string | null;
  detail: string;
  required: boolean;
}

interface SetupOverview {
  ready: boolean;
  managed_install_available: boolean;
  managed_root: string;
  components: SetupComponentStatus[];
}

interface DecompiledFunctionDetails {
  decompiled_code: string | null;
  return_type: string;
  parameters: FunctionParameter[];
  calling_convention: string;
  bsim: BsimQueryResult;
}

type InstructionFlowCategory =
  | "fall_through"
  | "unconditional_jump"
  | "conditional_jump"
  | "unconditional_call"
  | "conditional_call"
  | "terminator"
  | "other";

interface DisassembledInstruction {
  address: string;
  length: number;
  bytes: string;
  mnemonic: string;
  operands: string;
  flow_category: InstructionFlowCategory;
  fall_through_address: string | null;
  function_address: string;
  function_name: string;
}

interface FunctionDisassembly {
  instructions: DisassembledInstruction[];
}

interface BsimCandidate {
  name: string;
  executable: string;
  corpus: string;
  similarity: number;
  significance: number;
}

interface MergedBsimCandidate extends BsimCandidate {
  // Every distinct reference executable in the corpus that independently
  // matched this name at this address -- e.g. the same generic CRT
  // helper found identically in sqlite3.dll, zlib1.dll, lz4.dll and
  // xxhash.dll. Several unrelated libraries agreeing is itself
  // corroborating evidence, distinct from (and stronger than) any single
  // raw similarity/significance score.
  matchingExecutables: string[];
}

interface BsimCorpusSummary {
  id: string;
  name: string;
  origin: "built_in" | "custom" | "environment";
  enabled: boolean;
  available: boolean;
  path: string;
  size_bytes: number | null;
  libraries: string[];
  description: string;
  removable: boolean;
}

interface ArbitrationOutcome {
  chosen_name: string | null;
  reasoning: string;
  provider_label: string;
}

interface StoredArbitrationOutcome extends ArbitrationOutcome {
  entry_address: string;
}

interface GenerationOutcome {
  suggested_name: string | null;
  reasoning: string;
  provider_label: string;
}

interface StoredGenerationOutcome extends GenerationOutcome {
  entry_address: string;
}

interface AiProviderSummary {
  id: string;
  label: string;
  base_url: string;
  model: string;
  has_api_key: boolean;
  enabled: boolean;
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
  bsim_candidates: BsimCandidate[];
  bsim_scanned: boolean;
  bsim_message: string | null;
}

interface AutomaticRenameChoice {
  func: GhidraFunction;
  name: string;
  source: "rtti" | "function_id" | "bsim" | "arbitration" | "generation";
  scoreLabel: string;
  evidenceLabel: string;
  alternativeCount: number;
  decisionLabel: string;
  ambiguous: boolean;
}

interface AutomaticRenameRejection {
  func: GhidraFunction;
  candidateName: string;
  candidateDisplayName: string;
  source: "rtti" | "function_id" | "bsim";
  evidenceLabel: string;
  reason: string;
}

interface AutomaticRenameEvaluation {
  choices: AutomaticRenameChoice[];
  rejections: AutomaticRenameRejection[];
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
  let functionPage = $state(1);
  const functionPageSize = 15;
  let decompileCache = $state(new Map<string, DecompiledFunctionDetails>());
  let pendingDecompiles = $state(new Set<string>());
  let decompileErrors = $state(new Map<string, string>());
  let identifications = $state(new Map<string, FidCandidate[]>());
  let backgroundBsimResults = $state(new Map<string, BsimQueryResult>());
  let bsimRepetitionCounts = $state(new Map<string, number>());
  let identificationPage = $state(1);
  const identificationPageSize = 10;
  type IdentificationQueueFilter = "matched" | "unmatched" | "all";
  let identificationQueueFilter = $state<IdentificationQueueFilter>("matched");
  let identificationQueueSearch = $state("");
  let automaticIdentificationMode = $state(false);
  let automaticIdentificationPage = $state(1);
  const automaticIdentificationPageSize = 12;
  let ignoredIdentificationAddresses = $state(new Set<string>());
  let isApplyingAutomaticRenames = $state(false);
  let automaticRenameError = $state("");
  let automaticRenameSuccess = $state("");
  let graphNavigationHistory = $state<string[]>([]);
  let graphHistoryProgramSha: string | null = null;
  let identificationProgramSha: string | null = null;
  type BrowserSymbolFilter = "all" | "internal" | "external" | "unnamed";
  let browserSymbolFilter = $state<BrowserSymbolFilter>("all");
  let browserSearch = $state("");
  let browserPage = $state(1);
  const browserPageSize = 50;
  let browserHistory = $state<string[]>([]);
  let browserHistoryIndex = $state(-1);
  let browserHistoryProgramSha: string | null = null;
  let disassemblyCache = $state(new Map<string, FunctionDisassembly>());
  let pendingDisassemblies = $state(new Set<string>());
  let disassemblyErrors = $state(new Map<string, string>());
  let browserSymbolsCollapsed = $state(false);

  // "Programme entier" mode: a bounded, paginated, function-grouped listing
  // of every internal function's disassembly, as an alternative to viewing
  // one function at a time. Deliberately paged server-side (one Ghidra
  // request per page of functions) rather than fetched all at once -- a
  // real ~3,300-function DLL produced 250k+ instructions in testing, far
  // too much for one response or one renderable table.
  type CodeBrowserListingMode = "function" | "program";
  let codeBrowserListingMode = $state<CodeBrowserListingMode>("function");
  let programListingPage = $state(1);
  const programListingPageSize = 20;
  let programListingCache = $state(new Map<number, DisassembledInstruction[]>());
  let isLoadingProgramListingPage = $state(false);
  let programListingError = $state("");
  let programListingProgramSha: string | null = null;

  // Only internal functions have a disassemblable body; external imports
  // have none. Already sorted by ascending entry address per the export
  // contract, so paging through this in order reads like Ghidra's own
  // address-ordered Listing.
  let programListingFunctions = $derived(
    importedExport?.functions.filter((func) => !func.is_external) ?? [],
  );

  let programListingPageCount = $derived(
    Math.max(1, Math.ceil(programListingFunctions.length / programListingPageSize)),
  );

  let currentProgramListingPage = $derived(
    Math.min(programListingPage, programListingPageCount),
  );

  let paginatedProgramListingFunctions = $derived(
    programListingFunctions.slice(
      (currentProgramListingPage - 1) * programListingPageSize,
      currentProgramListingPage * programListingPageSize,
    ),
  );

  let currentProgramListingInstructions = $derived(
    programListingCache.get(currentProgramListingPage) ?? null,
  );

  // Ghidra has no single dedicated "program entry point" API -- confirmed by
  // checking a real ELF's bookmarks, external-entry-point order, and
  // PROGRAM_INFO options (none single it out). What genuinely identifies it
  // is convention: toolchains name the real entry symbol one of a handful of
  // well-known names depending on platform/compiler. Only ever resolves to a
  // function that's actually present -- never fabricated.
  const WELL_KNOWN_ENTRY_POINT_NAMES = [
    "_start",
    "entry",
    "WinMainCRTStartup",
    "mainCRTStartup",
    "__start",
  ];

  let programEntryPointAddress = $derived.by(() => {
    if (!importedExport) return null;
    for (const name of WELL_KNOWN_ENTRY_POINT_NAMES) {
      const match = importedExport.functions.find((func) => func.name === name);
      if (match) return match.entry_address;
    }
    return null;
  });

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

  let functionPageCount = $derived(
    Math.max(1, Math.ceil(filteredFunctions.length / functionPageSize)),
  );
  let currentFunctionPage = $derived(Math.min(functionPage, functionPageCount));
  let paginatedFunctions = $derived(
    filteredFunctions.slice(
      (currentFunctionPage - 1) * functionPageSize,
      currentFunctionPage * functionPageSize,
    ),
  );

  let browserFunctions = $derived.by(() => {
    if (!importedExport) return [];
    const query = browserSearch.trim().toLowerCase();
    return importedExport.functions.filter((func) => {
      if (browserSymbolFilter === "internal" && func.is_external) return false;
      if (browserSymbolFilter === "external" && !func.is_external) return false;
      if (browserSymbolFilter === "unnamed" && !isGeneratedFunctionName(func.name)) return false;
      return !query ||
        func.name.toLowerCase().includes(query) ||
        func.entry_address.toLowerCase().includes(query);
    });
  });
  let browserPageCount = $derived(
    Math.max(1, Math.ceil(browserFunctions.length / browserPageSize)),
  );
  let currentBrowserPage = $derived(Math.min(browserPage, browserPageCount));
  let paginatedBrowserFunctions = $derived(
    browserFunctions.slice(
      (currentBrowserPage - 1) * browserPageSize,
      currentBrowserPage * browserPageSize,
    ),
  );

  let unidentifiedFunctions = $derived(
    importedExport?.functions.filter(
      (func) => !func.is_external && isGeneratedFunctionName(func.name),
    ) ?? [],
  );
  // Every real class name confirmed anywhere in this binary via RTTI
  // (see rtti_class_names), aggregated once so any function's tied FID/
  // BSim candidates can be cross-referenced against it.
  let knownRealClassNames = $derived.by(() => {
    const names = new Set<string>();
    for (const func of importedExport?.functions ?? []) {
      for (const className of func.rtti_class_names) names.add(className);
    }
    return names;
  });
  let arbitrationTiedTotal = $derived.by(() =>
    unidentifiedFunctions.filter((func) => tiedCandidatesFor(func.entry_address).length > 0)
      .length,
  );
  let arbitrationTiedResolved = $derived.by(
    () =>
      unidentifiedFunctions.filter(
        (func) =>
          tiedCandidatesFor(func.entry_address).length > 0 &&
          (arbitrationResults.has(func.entry_address) ||
            arbitrationErrors.has(func.entry_address)),
      ).length,
  );
  // True only once BSim has actually finished scanning this function (not
  // merely "not scanned yet") and found nothing, together with FunctionID
  // and RTTI also finding nothing -- the generative agent is only worth
  // spending a real API call on once every cheaper/faster signal has
  // genuinely come up empty, not while a scan is still pending.
  function hasNoEvidenceAtAll(func: GhidraFunction): boolean {
    if (func.rtti_class_names.length > 0) return false;
    if (uniqueFidCandidates(identifications.get(func.entry_address) ?? []).length > 0) return false;
    const bsim = bsimResultForAddress(func.entry_address);
    if (bsim?.status !== "available") return false;
    return bsim.matches.length === 0;
  }
  let generationTotal = $derived.by(
    () => unidentifiedFunctions.filter((func) => hasNoEvidenceAtAll(func)).length,
  );
  let generationResolved = $derived.by(
    () =>
      unidentifiedFunctions.filter(
        (func) =>
          hasNoEvidenceAtAll(func) &&
          (generationResults.has(func.entry_address) || generationErrors.has(func.entry_address)),
      ).length,
  );
  let remainingIdentificationFunctions = $derived(
    unidentifiedFunctions.filter(
      (func) => !ignoredIdentificationAddresses.has(func.entry_address),
    ),
  );
  let matchedIdentificationCount = $derived(
    remainingIdentificationFunctions.filter((func) => hasIdentificationEvidence(func.entry_address)).length,
  );
  let unmatchedIdentificationCount = $derived(
    Math.max(0, remainingIdentificationFunctions.length - matchedIdentificationCount),
  );
  let identificationQueue = $derived.by(() => {
    const query = identificationQueueSearch.trim().toLowerCase();
    const filtered = remainingIdentificationFunctions.filter((func) => {
      const hasEvidence = hasIdentificationEvidence(func.entry_address);
      if (identificationQueueFilter === "matched" && !hasEvidence) return false;
      if (identificationQueueFilter === "unmatched" && hasEvidence) return false;
      if (!query) return true;
      const fidNames = identifications.get(func.entry_address)?.map((candidate) => candidate.name) ?? [];
      const bsimNames = bsimMatchesForAddress(func.entry_address).map((candidate) => candidate.name);
      return [func.name, func.entry_address, ...fidNames, ...bsimNames]
        .some((value) => value.toLowerCase().includes(query));
    });
    return sortIdentificationFunctions(filtered);
  });
  let identificationPageCount = $derived(
    Math.max(1, Math.ceil(identificationQueue.length / identificationPageSize)),
  );
  let currentIdentificationPage = $derived(
    Math.min(identificationPage, identificationPageCount),
  );
  let paginatedIdentificationQueue = $derived(
    identificationQueue.slice(
      (currentIdentificationPage - 1) * identificationPageSize,
      currentIdentificationPage * identificationPageSize,
    ),
  );
  let importError = $state("");
  let isImporting = $state(false);

  let ghidraInstallationStatus = $state<GhidraInstallationStatus | null>(null);
  let setupOverview = $state<SetupOverview | null>(null);
  let setupOverviewError = $state("");
  let bsimCorpora = $state<BsimCorpusSummary[]>([]);
  let bsimCorporaError = $state("");
  let isManagingBsimCorpus = $state(false);
  let aiProviders = $state<AiProviderSummary[]>([]);
  let aiProvidersError = $state("");
  let isManagingAiProvider = $state(false);
  let newAiProviderLabel = $state("");
  let newAiProviderBaseUrl = $state("");
  let newAiProviderApiKey = $state("");
  let newAiProviderModel = $state("");
  let ghidraConfigError = $state("");
  let isConfiguringGhidra = $state(false);
  let analyzeError = $state("");
  let isAnalyzing = $state(false);
  let analysisProgress = $state<AnalysisProgress | null>(null);
  let analysisProgressVisible = $state(false);
  let analysisProgressMinimized = $state(false);
  let analysisElapsedSeconds = $state(0);
  let analysisTargetName = $state("");
  let analysisTimer: ReturnType<typeof setInterval> | null = null;

  onMount(() => {
    let unlisten: UnlistenFn | undefined;
    listen<AnalysisProgress>("analysis-progress", (event) => {
      analysisProgress = event.payload;
    }).then((stop) => {
      unlisten = stop;
    });

    return () => {
      unlisten?.();
      if (analysisTimer !== null) clearInterval(analysisTimer);
    };
  });

  let analysisSource = $state<"none" | "automatic" | "manual">("none");
  let activeProjectId = $state<string | null>(null);
  type WorkspaceView =
    | "overview"
    | "browser"
    | "identification"
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
    { id: "browser", label: "Code Browser", icon: "{ }" },
    { id: "overview", label: "Aperçu", icon: "⌂" },
    { id: "identification", label: "Identification", icon: "✦" },
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
  type ComparisonView = "changed" | "matched" | "added" | "removed";
  let comparisonView = $state<ComparisonView>("changed");
  let comparisonSearch = $state("");
  let comparisonPage = $state(1);
  const comparisonPageSize = 12;

  let filteredComparisonMatches = $derived.by(() => {
    if (!projectComparison) return [];
    const query = comparisonSearch.trim().toLowerCase();
    return projectComparison.matches.filter((match) => {
      if (comparisonView === "changed" && match.changes.length === 0) return false;
      if (comparisonView !== "changed" && comparisonView !== "matched") return false;
      return (
        !query ||
        qualifiedFunctionName(match.function_a).toLowerCase().includes(query) ||
        qualifiedFunctionName(match.function_b).toLowerCase().includes(query) ||
        match.function_a.entry_address.toLowerCase().includes(query) ||
        match.function_b.entry_address.toLowerCase().includes(query)
      );
    });
  });

  let filteredComparisonAdded = $derived.by(() => {
    if (!projectComparison || comparisonView !== "added") return [];
    const query = comparisonSearch.trim().toLowerCase();
    return projectComparison.unmatched_b.filter(
      (func) =>
        !query ||
        qualifiedFunctionName(func).toLowerCase().includes(query) ||
        func.entry_address.toLowerCase().includes(query),
    );
  });

  let filteredComparisonRemoved = $derived.by(() => {
    if (!projectComparison || comparisonView !== "removed") return [];
    const query = comparisonSearch.trim().toLowerCase();
    return projectComparison.unmatched_a.filter(
      (func) =>
        !query ||
        qualifiedFunctionName(func).toLowerCase().includes(query) ||
        func.entry_address.toLowerCase().includes(query),
    );
  });

  let comparisonVisibleCount = $derived(
    comparisonView === "added"
      ? filteredComparisonAdded.length
      : comparisonView === "removed"
        ? filteredComparisonRemoved.length
        : filteredComparisonMatches.length,
  );
  let comparisonPageCount = $derived(
    Math.max(1, Math.ceil(comparisonVisibleCount / comparisonPageSize)),
  );
  let currentComparisonPage = $derived(
    Math.min(comparisonPage, comparisonPageCount),
  );

  let changedComparisonCount = $derived(
    projectComparison?.matches.filter((match) => match.changes.length > 0).length ?? 0,
  );

  let functionIdAnalysisAvailable = $state(false);
  let functionRenameDraft = $state("");
  let isApplyingFunctionRename = $state(false);
  let functionRenameError = $state("");
  let functionRenameSuccess = $state("");
  let renameDraftAddress: string | null = null;
  // Per-address, not per-selection: arbitration runs automatically in the
  // background across every tied function (see runBackgroundArbitration),
  // so results must survive switching which function is selected.
  let arbitrationResults = $state(new Map<string, ArbitrationOutcome>());
  let arbitrationErrors = $state(new Map<string, string>());
  let arbitratingAddresses = $state(new Set<string>());
  let isBackgroundArbitrating = $state(false);
  // Same per-address/background rationale as arbitration, for functions
  // with no FunctionID/BSim candidates at all -- see runBackgroundGeneration.
  let generationResults = $state(new Map<string, GenerationOutcome>());
  let generationErrors = $state(new Map<string, string>());
  let generatingAddresses = $state(new Set<string>());
  let isBackgroundGenerating = $state(false);

  // Ghidra's bundled FunctionID databases already discard matches below
  // 14.6. Keep that native threshold, then add the more important unique-name
  // margin check so equal-scored candidates are never presented as a winner.
  const automaticFidMinimumScore = 14.6;
  const automaticFidMinimumMargin = 3;
  const automaticBsimMinimumSimilarity = 0.85;
  const automaticBsimMinimumSignificance = 10;
  const automaticBsimMinimumMargin = 0.05;
  // Mirrors identification_corroboration::MINIMUM_CORROBORATING_REPETITIONS
  // (src-tauri/src/services/identification_corroboration.rs).
  const minimumCorroboratingRepetitions = 3;
  // Several unrelated reference libraries independently agreeing on the
  // exact same name at this address (e.g. a generic CRT helper found
  // identically in sqlite3.dll, zlib1.dll, lz4.dll and xxhash.dll) is
  // corroborating evidence a single raw similarity/significance score
  // cannot express on its own.
  const minimumCorroboratingBsimExecutables = 3;

  function isSafeAutomaticSymbolName(name: string): boolean {
    // The current Ghidra edit contract changes a symbol in its existing
    // namespace. Keep automatic writes conservative; decorated C++ names and
    // namespace syntax remain available for manual review instead.
    return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && name.length <= 200;
  }

  function normalizedAutomaticSymbolName(name: string): string | null {
    if (isSafeAutomaticSymbolName(name)) return name;

    const deletingDestructor = name.match(/^\?\?_G([^@]+)@(.+?)@@/);
    if (deletingDestructor) {
      const scope = deletingDestructor[2].split("@").filter(Boolean).reverse().join("_");
      return `${scope}_${deletingDestructor[1]}_deleting_destructor`;
    }

    const constructor = name.match(/^\?\?0([^@]+)@(.+?)@@(.*)$/);
    if (constructor) {
      const suffix = constructor[3];
      const scope = constructor[2].split("@").filter(Boolean).reverse().join("_");
      return `${scope}_${constructor[1]}_${suffix.includes("AEBV") ? "copy_constructor" : "constructor"}`;
    }

    if (/^\?\?2@/.test(name)) return "operator_new";
    if (/^\?\?3@/.test(name)) return "operator_delete";

    const globalFunction = name.match(/^\?([A-Za-z_][A-Za-z0-9_]*)@@/);
    if (globalFunction) return globalFunction[1];

    // BSim commonly returns already-demangled C++ names. Ghidra's flat rename
    // command cannot create namespaces here, so preserve every readable scope
    // component while converting separators and compiler markers to `_`.
    const flattened = name
      .replace(/::/g, "_")
      .replace(/\$/g, "_")
      .replace(/[^A-Za-z0-9_]+/g, "_")
      .replace(/_+/g, "_")
      .replace(/^_+|_+$/g, "");
    if (!flattened) return null;
    const safe = /^[0-9]/.test(flattened) ? `function_${flattened}` : flattened;
    return isSafeAutomaticSymbolName(safe) ? safe : null;
  }

  function reserveUniqueAutomaticName(
    baseName: string,
    entryAddress: string,
    reservedNames: Set<string>,
  ): string {
    let chosenName = baseName;
    if (reservedNames.has(chosenName)) {
      chosenName = `${baseName}_${entryAddress.replace(/^0x/i, "")}`;
    }
    let suffix = 2;
    while (reservedNames.has(chosenName)) {
      chosenName = `${baseName}_${entryAddress.replace(/^0x/i, "")}_${suffix}`;
      suffix += 1;
    }
    reservedNames.add(chosenName);
    return chosenName;
  }

  function identificationSourceLabel(
    source: "rtti" | "function_id" | "bsim" | "arbitration" | "generation",
  ): string {
    if (source === "rtti") return "RTTI";
    if (source === "arbitration") return "Agent IA (arbitrage)";
    if (source === "generation") return "Agent IA (invention)";
    return source === "function_id" ? "FunctionID" : "BSim";
  }

  function displayCandidateName(name: string): string {
    // Display-only decoding for common MSVC constructors/destructors. This is
    // never written back because correct C++ application also needs namespace
    // and overload support in the Ghidra edit contract.
    const deletingDestructor = name.match(/^\?\?_G([^@]+)@(.+?)@@/);
    if (deletingDestructor) {
      const scope = deletingDestructor[2].split("@").filter(Boolean).reverse().join("::");
      return `${scope}::${deletingDestructor[1]}::~${deletingDestructor[1]} (destructeur C++ décoré)`;
    }
    const special = name.match(/^\?\?([01])([^@]+)@(.+?)@@/);
    if (special) {
      const [, kind, className, rawScope] = special;
      const scope = rawScope.split("@").filter(Boolean).reverse().join("::");
      return kind === "0"
        ? `${scope}::${className}::${className} (nom C++ décoré)`
        : `${scope}::${className}::~${className} (nom C++ décoré)`;
    }
    const member = name.match(/^\?([^@]+)@([^@]+)@@/);
    if (member) return `${member[2]}::${member[1]} (nom C++ décoré)`;
    return name;
  }

  // Extracts "Namespace::ClassName" from a common MSVC mangled
  // constructor (??0) or destructor (??1 / ??_G scalar deleting
  // destructor) name -- the exact same real-name format RTTI
  // TypeDescriptor data uses (see RttiClassCollector.java's
  // demangleTypeDescriptorName on the Java side, which this must stay
  // consistent with). Returns null for shapes not recognized here rather
  // than guessing.
  function extractClassNameFromMangledMember(name: string): string | null {
    const match = name.match(/^\?\?(?:0|1|_G)([^@]+)@(.*?)@@/);
    if (!match) return null;
    const [, className, namespaceSegment] = match;
    if (!namespaceSegment) return className;
    const segments = namespaceSegment.split("@").filter(Boolean);
    segments.reverse();
    return [...segments, className].join("::");
  }

  // Whether a raw FID/BSim candidate name corresponds to a class
  // independently confirmed to exist somewhere else in this exact binary
  // via RTTI -- a real signal a researcher would use to discount FID's
  // fuzzy-matched candidates from libraries this binary shows no other
  // trace of using, without fabricating any new evidence.
  function isCorroboratedByRtti(candidateName: string, knownClassNames: Set<string>): boolean {
    const realName = extractClassNameFromMangledMember(candidateName) ?? candidateName;
    return knownClassNames.has(realName);
  }

  // A confident AI arbitration answer -- chosen only from a real, closed
  // set of tied candidates, never invented (see naming_arbitration.rs's
  // "a name outside the candidate list is rejected, not trusted") -- is
  // itself real evidence, not a suggestion that needs a manual click. Once
  // the agent commits to a name, it feeds into the same automatic pipeline
  // as RTTI/FunctionID/BSim instead of leaving the function stuck behind
  // whichever deterministic rejection triggered arbitration in the first
  // place.
  function arbitrationChoiceFor(
    func: GhidraFunction,
    reservedNames: Set<string>,
  ): AutomaticRenameChoice | null {
    const arbitration = arbitrationResults.get(func.entry_address);
    if (!arbitration?.chosen_name) return null;
    const normalizedName = normalizedAutomaticSymbolName(arbitration.chosen_name);
    if (!normalizedName) return null;
    const safeName = reserveUniqueAutomaticName(normalizedName, func.entry_address, reservedNames);
    return {
      func,
      name: safeName,
      source: "arbitration",
      scoreLabel: "agent IA",
      evidenceLabel: `${arbitration.provider_label} : ${arbitration.reasoning}`,
      alternativeCount: Math.max(0, tiedCandidatesFor(func.entry_address).length - 1),
      decisionLabel: "Choisi par l'agent IA parmi les candidats ex æquo réels, à partir du contexte (appelants, appelés, chaînes)",
      ambiguous: false,
    };
  }

  function uniqueFidCandidates(candidates: FidCandidate[]): FidCandidate[] {
    const bestByName = new Map<string, FidCandidate>();
    for (const candidate of candidates) {
      if (isGeneratedFunctionName(candidate.name)) continue;
      const previous = bestByName.get(candidate.name);
      if (!previous || candidate.overall_score > previous.overall_score) {
        bestByName.set(candidate.name, candidate);
      }
    }
    return [...bestByName.values()].sort((a, b) => b.overall_score - a.overall_score);
  }

  function uniqueBsimCandidates(candidates: BsimCandidate[]): MergedBsimCandidate[] {
    const bestByName = new Map<string, MergedBsimCandidate>();
    for (const candidate of candidates) {
      if (isGeneratedFunctionName(candidate.name)) continue;
      const previous = bestByName.get(candidate.name);
      const matchingExecutables = previous
        ? [...new Set([...previous.matchingExecutables, candidate.executable])]
        : [candidate.executable];
      const corpora = previous
        ? [...new Set([...previous.corpus.split(" + "), candidate.corpus])].join(" + ")
        : candidate.corpus;

      if (
        !previous ||
        candidate.similarity > previous.similarity ||
        (candidate.similarity === previous.similarity && candidate.significance > previous.significance)
      ) {
        bestByName.set(candidate.name, { ...candidate, corpus: corpora, matchingExecutables });
      } else {
        bestByName.set(candidate.name, { ...previous, corpus: corpora, matchingExecutables });
      }
    }
    return [...bestByName.values()].sort(
      (a, b) => b.similarity - a.similarity || b.significance - a.significance,
    );
  }

  function bsimMatchesForAddress(entryAddress: string): MergedBsimCandidate[] {
    const result = bsimResultForAddress(entryAddress);
    return result?.status === "available" ? uniqueBsimCandidates(result.matches) : [];
  }

  function hasIdentificationEvidence(entryAddress: string): boolean {
    return (identifications.get(entryAddress)?.length ?? 0) > 0 ||
      bsimMatchesForAddress(entryAddress).length > 0;
  }

  function identificationEvidenceScore(func: GhidraFunction): number {
    const fidScore = uniqueFidCandidates(identifications.get(func.entry_address) ?? [])[0]?.overall_score ?? 0;
    const bsim = bsimMatchesForAddress(func.entry_address)[0];
    const bsimScore = bsim ? bsim.similarity * 100 + bsim.significance : 0;
    return Math.max(fidScore, bsimScore);
  }

  function sortIdentificationFunctions(functions: GhidraFunction[]): GhidraFunction[] {
    return [...functions].sort((a, b) => {
      const evidenceDifference = Number(hasIdentificationEvidence(b.entry_address)) -
        Number(hasIdentificationEvidence(a.entry_address));
      if (evidenceDifference !== 0) return evidenceDifference;
      const scoreDifference = identificationEvidenceScore(b) - identificationEvidenceScore(a);
      if (Math.abs(scoreDifference) > 0.0001) return scoreDifference;
      return a.entry_address.localeCompare(b.entry_address);
    });
  }

  let automaticRenameEvaluation = $derived.by<AutomaticRenameEvaluation>(() => {
    const choices: AutomaticRenameChoice[] = [];
    const rejections: AutomaticRenameRejection[] = [];
    const reservedNames = new Set(
      (importedExport?.functions ?? [])
        .filter((func) => !isGeneratedFunctionName(func.name))
        .map((func) => func.name),
    );

    for (const func of unidentifiedFunctions) {
      // Ground truth from the binary's own MSVC RTTI metadata (vtable ->
      // RTTICompleteObjectLocator -> TypeDescriptor) takes priority over
      // FID/BSim's fuzzy signature matching -- it is a verified fact about
      // this exact binary, never a guess.
      if (func.rtti_class_names.length === 1) {
        const normalizedName = normalizedAutomaticSymbolName(func.rtti_class_names[0]);
        if (normalizedName) {
          const safeName = reserveUniqueAutomaticName(normalizedName, func.entry_address, reservedNames);
          choices.push({
            func,
            name: safeName,
            source: "rtti",
            scoreLabel: "RTTI",
            evidenceLabel: `Classe confirmée par les métadonnées RTTI du binaire : ${func.rtti_class_names[0]}`,
            alternativeCount: 0,
            decisionLabel: "Confirmé par RTTI — donnée réelle du binaire, pas une estimation",
            ambiguous: false,
          });
          continue;
        }
      }
      if (func.rtti_class_names.length > 1) {
        // Several real classes genuinely share this exact function (the
        // compiler/linker folded their destructors together) -- every name
        // in the list is equally real and RTTI-confirmed, so there is no
        // more evidence left to gather. Like a researcher who has already
        // exhausted the evidence, auto mode commits to one (the first,
        // alphabetically, as RttiClassCollector already sorts them) instead
        // of blocking on a choice that has no more-correct answer.
        const normalizedName = normalizedAutomaticSymbolName(func.rtti_class_names[0]);
        if (normalizedName) {
          const safeName = reserveUniqueAutomaticName(normalizedName, func.entry_address, reservedNames);
          choices.push({
            func,
            name: safeName,
            source: "rtti",
            scoreLabel: "RTTI",
            evidenceLabel: `${func.rtti_class_names.length} classes confirmées par RTTI, toutes également réelles : ${func.rtti_class_names.join(", ")}`,
            alternativeCount: func.rtti_class_names.length - 1,
            decisionLabel: "Fonction réellement partagée par plusieurs classes (destructeurs fusionnés par le compilateur) — première classe retenue, confirmée par RTTI comme les autres",
            ambiguous: true,
          });
          continue;
        }
      }

      // FunctionID and BSim found nothing at all for this function -- there
      // is no candidate to select between (arbitration doesn't apply), only
      // the generative agent's own invention from real context. This is
      // never treated the same as verified evidence: it's still put in
      // "auto" (per explicit request -- the user shouldn't have to click
      // each one by hand), but always as its own visibly distinct source,
      // carrying the agent's own reasoning so it's clear *why* it chose
      // this name, not just that it did.
      if (hasNoEvidenceAtAll(func)) {
        const generation = generationResults.get(func.entry_address);
        if (generation?.suggested_name) {
          const normalizedName = normalizedAutomaticSymbolName(generation.suggested_name);
          if (normalizedName) {
            const safeName = reserveUniqueAutomaticName(normalizedName, func.entry_address, reservedNames);
            choices.push({
              func,
              name: safeName,
              source: "generation",
              scoreLabel: "invention IA",
              evidenceLabel: `${generation.provider_label} : ${generation.reasoning}`,
              alternativeCount: 0,
              decisionLabel: "Aucune preuve FunctionID/BSim -- nom inventé par l'agent IA à partir du pseudocode, des appelants/appelés et des chaînes",
              ambiguous: true,
            });
          }
        }
        continue;
      }

      const fidCandidates = uniqueFidCandidates(identifications.get(func.entry_address) ?? []);
      const bestFid = fidCandidates[0];
      const bsim = bsimResultForAddress(func.entry_address);
      const bsimCandidates = bsim?.status === "available"
        ? uniqueBsimCandidates(bsim.matches)
        : [];
      const bestBsim = bsimCandidates[0];
      const bsimIsStrong = bestBsim !== undefined &&
        bestBsim.similarity >= automaticBsimMinimumSimilarity &&
        bestBsim.significance >= automaticBsimMinimumSignificance;
      const corroboratedFid = bsimIsStrong
        ? fidCandidates.find((candidate) => {
            const fidName = normalizedAutomaticSymbolName(candidate.name);
            const bsimName = normalizedAutomaticSymbolName(bestBsim.name) ?? bestBsim.name;
            return fidName !== null && fidName.toLowerCase() === bsimName.toLowerCase();
          })
        : undefined;
      // Among candidates tied at the top FID score, narrow to whichever
      // are independently confirmed elsewhere in this binary via RTTI --
      // the same reasoning wired into the arbitration agent
      // (tiedCandidatesFor), applied here too so it benefits functions
      // that never even reach arbitration.
      const topFidScore = bestFid?.overall_score;
      const tiedFid = topFidScore === undefined
        ? []
        : fidCandidates.filter((candidate) => Math.abs(candidate.overall_score - topFidScore) < 0.0001);
      const rttiCorroboratedFid = tiedFid.length > 1
        ? tiedFid.filter((candidate) => isCorroboratedByRtti(candidate.name, knownRealClassNames))
        : [];
      const rttiNarrowedFid = rttiCorroboratedFid.length === 1 ? rttiCorroboratedFid[0] : undefined;
      const selectedFid = corroboratedFid ?? rttiNarrowedFid ?? bestFid;
      let fidRejection: AutomaticRenameRejection | null = null;

      if (selectedFid) {
        const runnerUp = fidCandidates.find((candidate) => candidate.name !== selectedFid.name);
        const margin = runnerUp ? selectedFid.overall_score - runnerUp.overall_score : null;
        const isAmbiguous = corroboratedFid === undefined && rttiNarrowedFid === undefined &&
          margin !== null && margin < automaticFidMinimumMargin;
        const normalizedName = normalizedAutomaticSymbolName(selectedFid.name);
        let reason = "";
        if (!normalizedName) {
          reason = "Nom C++ impossible à convertir sans perdre son sens.";
        } else if (selectedFid.overall_score < automaticFidMinimumScore) {
          reason = `Score ${selectedFid.overall_score.toFixed(1)} trop faible (minimum automatique : ${automaticFidMinimumScore.toFixed(1)}).`;
        }

        if (!reason) {
          const safeName = reserveUniqueAutomaticName(
            normalizedName as string,
            func.entry_address,
            reservedNames,
          );
          choices.push({
            func,
            name: safeName,
            source: "function_id",
            scoreLabel: `score ${selectedFid.overall_score.toFixed(1)}`,
            evidenceLabel: corroboratedFid && bestBsim
              ? `${selectedFid.library_family} ${selectedFid.library_version} · confirmé par ${bestBsim.corpus} (BSim ${bestBsim.similarity.toFixed(3)})`
              : rttiNarrowedFid
              ? `${selectedFid.library_family} ${selectedFid.library_version} · seul candidat parmi ${tiedFid.length} confirmé par RTTI ailleurs dans ce binaire`
              : `${selectedFid.library_family} ${selectedFid.library_version} · ${selectedFid.match_mode}`,
            alternativeCount: Math.max(0, fidCandidates.length - 1),
            decisionLabel: corroboratedFid
              ? "FunctionID et BSim proposent le même nom"
              : rttiNarrowedFid
              ? `${tiedFid.length} noms ex æquo, mais un seul confirmé ailleurs dans ce binaire via RTTI`
              : isAmbiguous
              ? `${fidCandidates.length} noms ex æquo : premier choix FunctionID nettoyé, ambiguïté conservée`
              : margin === null
              ? "Candidat unique au-dessus du seuil de sécurité"
              : `Marge de ${margin.toFixed(1)} points sur le deuxième candidat`,
            ambiguous: isAmbiguous,
          });
          continue;
        }

        fidRejection = {
          func,
          candidateName: selectedFid.name,
          candidateDisplayName: displayCandidateName(selectedFid.name),
          source: "function_id",
          evidenceLabel: `score ${selectedFid.overall_score.toFixed(1)} · ${selectedFid.library_family} ${selectedFid.library_version}`,
          reason,
        };
      }

      // A rejected FunctionID result does not hide an independently strong
      // BSim result. BSim can rescue it, under its own strict rules.
      if (bestBsim) {
        const runnerUp = bsimCandidates[1];
        const margin = runnerUp ? bestBsim.similarity - runnerUp.similarity : null;
        const normalizedBsimName = normalizedAutomaticSymbolName(bestBsim.name);
        // A match repeated at several distinct addresses in this same
        // binary corroborates it even when BSim's own significance score
        // (which penalises small/generic code) falls under the safety
        // threshold on its own -- see identification_corroboration.rs.
        const repetitionCount = bsimRepetitionCounts.get(bestBsim.name) ?? 0;
        const corroboratedByRepetition = repetitionCount >= minimumCorroboratingRepetitions;
        // Several unrelated reference libraries independently agreeing on
        // the exact same name at this one address is a different, equally
        // real signal -- e.g. a generic CRT helper found identically in
        // sqlite3.dll, zlib1.dll, lz4.dll and xxhash.dll.
        const corroboratedByCrossLibraryAgreement =
          bestBsim.matchingExecutables.length >= minimumCorroboratingBsimExecutables;
        const isCorroborated = corroboratedByRepetition || corroboratedByCrossLibraryAgreement;
        const rescuedBySimilarity =
          bestBsim.similarity < automaticBsimMinimumSimilarity && corroboratedByCrossLibraryAgreement;
        const rescuedBySignificance =
          bestBsim.significance < automaticBsimMinimumSignificance && isCorroborated;
        let reason = "";
        if (!normalizedBsimName) {
          reason = "Nom C++ impossible à nettoyer sans perdre son sens.";
        } else if (bestBsim.similarity < automaticBsimMinimumSimilarity && !rescuedBySimilarity) {
          reason = `Similarité ${bestBsim.similarity.toFixed(3)} trop faible (minimum : ${automaticBsimMinimumSimilarity.toFixed(2)}).`;
        } else if (bestBsim.significance < automaticBsimMinimumSignificance && !rescuedBySignificance) {
          reason = `Significativité ${bestBsim.significance.toFixed(1)} trop faible (minimum : ${automaticBsimMinimumSignificance.toFixed(1)}) et ce nom n'apparaît pas ailleurs dans le binaire ni dans plusieurs bibliothèques du corpus pour corroborer la correspondance.`;
        } else if (margin !== null && margin < automaticBsimMinimumMargin) {
          reason = `Plusieurs noms BSim sont trop proches (marge ${margin.toFixed(3)}).`;
        }

        if (!reason) {
          const safeName = reserveUniqueAutomaticName(
            normalizedBsimName as string,
            func.entry_address,
            reservedNames,
          );
          const corroborationLabel = corroboratedByCrossLibraryAgreement
            ? `confirmé par ${bestBsim.matchingExecutables.length} bibliothèques du corpus (${bestBsim.matchingExecutables.join(", ")})`
            : corroboratedByRepetition
            ? `même correspondance à ${repetitionCount} autres adresses de ce binaire`
            : null;
          choices.push({
            func,
            name: safeName,
            source: "bsim",
            scoreLabel: `similarité ${bestBsim.similarity.toFixed(3)}`,
            evidenceLabel: corroborationLabel
              ? `${bestBsim.corpus} · ${corroborationLabel}`
              : `${bestBsim.corpus} · ${bestBsim.executable} · significativité ${bestBsim.significance.toFixed(1)}`,
            alternativeCount: Math.max(0, bsimCandidates.length - 1),
            decisionLabel: corroborationLabel
              ? `Corroboré : ${corroborationLabel}`
              : margin === null
              ? "Candidat unique au-dessus des seuils de sécurité"
              : `Marge de ${margin.toFixed(3)} sur le deuxième candidat`,
            ambiguous: false,
          });
          continue;
        }

        const bsimArbitrationChoice = arbitrationChoiceFor(func, reservedNames);
        if (bsimArbitrationChoice) {
          choices.push(bsimArbitrationChoice);
          continue;
        }

        rejections.push({
          func,
          candidateName: bestBsim.name,
          candidateDisplayName: displayCandidateName(bestBsim.name),
          source: "bsim",
          evidenceLabel: `similarité ${bestBsim.similarity.toFixed(3)} · significativité ${bestBsim.significance.toFixed(1)}`,
          reason,
        });
        continue;
      }

      if (fidRejection) {
        const fidArbitrationChoice = arbitrationChoiceFor(func, reservedNames);
        if (fidArbitrationChoice) {
          choices.push(fidArbitrationChoice);
        } else {
          rejections.push(fidRejection);
        }
      }
    }

    return { choices, rejections };
  });
  let automaticRenameCandidates = $derived(automaticRenameEvaluation.choices);
  let automaticRenameRejections = $derived(automaticRenameEvaluation.rejections);
  let automaticAmbiguousChoiceCount = $derived(
    automaticRenameCandidates.filter((choice) => choice.ambiguous).length,
  );
  let automaticRenameWithoutEvidenceCount = $derived(
    Math.max(0, unidentifiedFunctions.length - automaticRenameCandidates.length - automaticRenameRejections.length),
  );
  // Shown in their own section, separate from the evidence-backed table --
  // see the comment in automaticRenameEvaluation on why an invented name is
  // never blended in with RTTI/FunctionID/BSim/arbitration choices, even
  // though it's still included in the same bulk "apply" action.
  let automaticRenameGenerationCandidates = $derived(
    automaticRenameCandidates.filter((choice) => choice.source === "generation"),
  );
  let automaticRenameCandidatesWithEvidence = $derived(
    automaticRenameCandidates.filter((choice) => choice.source !== "generation"),
  );
  let automaticIdentificationPageCount = $derived(
    Math.max(
      1,
      Math.ceil(automaticRenameCandidatesWithEvidence.length / automaticIdentificationPageSize),
    ),
  );
  let currentAutomaticIdentificationPage = $derived(
    Math.min(automaticIdentificationPage, automaticIdentificationPageCount),
  );
  let paginatedAutomaticRenameCandidates = $derived(
    automaticRenameCandidatesWithEvidence.slice(
      (currentAutomaticIdentificationPage - 1) * automaticIdentificationPageSize,
      currentAutomaticIdentificationPage * automaticIdentificationPageSize,
    ),
  );

  let selectedIdentificationCandidates = $derived(
    selectedFunctionAddress
      ? uniqueFidCandidates(identifications.get(selectedFunctionAddress) ?? [])
      : [],
  );
  let selectedIdentificationTopTieCount = $derived.by(() => {
    const topScore = selectedIdentificationCandidates[0]?.overall_score;
    if (topScore === undefined) return 0;
    return selectedIdentificationCandidates.filter(
      (candidate) => Math.abs(candidate.overall_score - topScore) < 0.0001,
    ).length;
  });
  // Ties from either identification method (FunctionID or BSim) that the
  // arbitration agent was actually queued for -- see tiedCandidatesFor.
  let selectedTiedCandidates = $derived(
    selectedFunction ? tiedCandidatesFor(selectedFunction.entry_address) : [],
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
    const candidates = uniqueFidCandidates(identifications.get(entryAddress) ?? []);
    if (candidates.length === 0) return null;
    if (
      candidates.length > 1 &&
      Math.abs(candidates[0].overall_score - candidates[1].overall_score) < 0.0001
    ) return null;
    return candidates[0];
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
  let globalStringsPage = $state(1);
  const globalStringsPageSize = 12;

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
  let globalStringsPageCount = $derived(
    Math.max(1, Math.ceil(filteredGlobalStrings.length / globalStringsPageSize)),
  );
  let currentGlobalStringsPage = $derived(
    Math.min(globalStringsPage, globalStringsPageCount),
  );
  let paginatedGlobalStrings = $derived(
    filteredGlobalStrings.slice(
      (currentGlobalStringsPage - 1) * globalStringsPageSize,
      currentGlobalStringsPage * globalStringsPageSize,
    ),
  );

  let imports = $state<ImportView[] | null>(null);
  let importsError = $state("");
  let isLoadingImports = $state(false);
  let importsSearch = $state("");
  let importsPage = $state(1);
  let ioWorkspaceTab = $state<"imports" | "exports" | "libraries">("imports");
  const ioPageSize = 12;

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
  let importsPageCount = $derived(
    Math.max(1, Math.ceil(filteredImports.length / ioPageSize)),
  );
  let currentImportsPage = $derived(Math.min(importsPage, importsPageCount));
  let paginatedImports = $derived(
    filteredImports.slice(
      (currentImportsPage - 1) * ioPageSize,
      currentImportsPage * ioPageSize,
    ),
  );

  let externalEntryPoints = $state<ExternalEntryPoint[] | null>(null);
  let externalEntryPointsError = $state("");
  let isLoadingExternalEntryPoints = $state(false);
  let externalEntryPointsSearch = $state("");
  let externalEntryPointsFunctionsOnly = $state(true);
  let externalEntryPointsPage = $state(1);

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
  let externalEntryPointsPageCount = $derived(
    Math.max(1, Math.ceil(filteredExternalEntryPoints.length / ioPageSize)),
  );
  let currentExternalEntryPointsPage = $derived(
    Math.min(externalEntryPointsPage, externalEntryPointsPageCount),
  );
  let paginatedExternalEntryPoints = $derived(
    filteredExternalEntryPoints.slice(
      (currentExternalEntryPointsPage - 1) * ioPageSize,
      currentExternalEntryPointsPage * ioPageSize,
    ),
  );

  let detectedTypes = $state<DetectedType[] | null>(null);
  let detectedTypesError = $state("");
  let isLoadingDetectedTypes = $state(false);
  let detectedTypesSearch = $state("");
  let detectedTypesKindFilter = $state<DetectedTypeKind | "all">("all");
  let expandedDetectedTypeKey = $state<string | null>(null);
  let detectedTypesPage = $state(1);
  const detectedTypesPageSize = 10;

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
  let detectedTypesPageCount = $derived(
    Math.max(1, Math.ceil(filteredDetectedTypes.length / detectedTypesPageSize)),
  );
  let currentDetectedTypesPage = $derived(
    Math.min(detectedTypesPage, detectedTypesPageCount),
  );
  let paginatedDetectedTypes = $derived(
    filteredDetectedTypes.slice(
      (currentDetectedTypesPage - 1) * detectedTypesPageSize,
      currentDetectedTypesPage * detectedTypesPageSize,
    ),
  );
  let selectedDetectedType = $derived(
    filteredDetectedTypes.find(
      (type) => `${type.category}|${type.name}` === expandedDetectedTypeKey,
    ) ?? paginatedDetectedTypes[0] ?? null,
  );

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
    { id: "evidence", label: "Preuves & renommage" },
    { id: "strings", label: "Chaînes" },
    { id: "calls", label: "Appels" },
  ];

  let callGraphDirection = $state<CallGraphDirection>("outgoing");
  let callGraphDepth = $state(3);
  let graphViewMode = $state<"2d" | "3d">("2d");
  let graph2dZoom = $state(1);
  let graph2dPanX = $state(0);
  let graph2dPanY = $state(0);
  let graphFunctionSearch = $state("");
  let graphFunctionPage = $state(1);
  const graphFunctionPageSize = 12;
  let graph3dYaw = $state(-0.35);
  let graph3dPitch = $state(0.28);
  let graph3dZoom = $state(1);
  let graphInspectedFunctionAddress = $state<string | null>(null);
  let graphNodeOffsets = $state(new Map<string, { x: number; y: number }>());
  let graphNodeDrag = $state<{
    address: string;
    pointerId: number;
    startX: number;
    startY: number;
    offsetX: number;
    offsetY: number;
    moved: boolean;
  } | null>(null);
  let graphPanDrag = $state<{
    pointerId: number;
    startX: number;
    startY: number;
    scrollLeft: number;
    scrollTop: number;
    panX: number;
    panY: number;
  } | null>(null);
  let graph3dDrag = $state<{
    pointerId: number;
    startX: number;
    startY: number;
    startYaw: number;
    startPitch: number;
  } | null>(null);
  let callGraphResult = $state<CallGraphNeighborhood | null>(null);
  let callGraphError = $state("");
  let isLoadingCallGraph = $state(false);
  let callGraphRequestSeq = 0;

  const graphCanvasWidth = 1120;
  const graphNodeWidth = 184;
  const graphNodeHeight = 62;
  const graph3dHeight = 620;
  const graph3dNodeWidth = 160;
  const graph3dNodeHeight = 54;

  let filteredGraphFunctions = $derived.by(() => {
    if (!importedExport) return [];
    const query = graphFunctionSearch.trim().toLowerCase();
    if (!query) return importedExport.functions;
    return importedExport.functions.filter(
      (func) =>
        func.name.toLowerCase().includes(query) ||
        func.entry_address.toLowerCase().includes(query),
    );
  });
  let graphFunctionPageCount = $derived(
    Math.max(1, Math.ceil(filteredGraphFunctions.length / graphFunctionPageSize)),
  );
  let currentGraphFunctionPage = $derived(
    Math.min(graphFunctionPage, graphFunctionPageCount),
  );
  let paginatedGraphFunctions = $derived(
    filteredGraphFunctions.slice(
      (currentGraphFunctionPage - 1) * graphFunctionPageSize,
      currentGraphFunctionPage * graphFunctionPageSize,
    ),
  );
  let graphInspectedFunction = $derived(
    importedExport?.functions.find(
      (func) => func.entry_address === graphInspectedFunctionAddress,
    ) ?? selectedFunction,
  );

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
        x:
          Math.round(
            ((index + 1) * graphCanvasWidth) / (group.length + 1) -
              graphNodeWidth / 2,
          ) + (graphNodeOffsets.get(node.entry_address)?.x ?? 0),
        y:
          38 +
          depth * 142 +
          (graphNodeOffsets.get(node.entry_address)?.y ?? 0),
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

  let graph3dLayout = $derived.by(() => {
    if (!callGraphResult) return { nodes: [], edges: [] };
    const groups = new Map<number, CallGraphNode[]>();
    for (const node of callGraphResult.nodes) {
      const group = groups.get(node.depth) ?? [];
      group.push(node);
      groups.set(node.depth, group);
    }

    const cosYaw = Math.cos(graph3dYaw);
    const sinYaw = Math.sin(graph3dYaw);
    const cosPitch = Math.cos(graph3dPitch);
    const sinPitch = Math.sin(graph3dPitch);
    const centerDepth = callGraphResult.depth_reached / 2;

    const nodes = [...groups.entries()].flatMap(([depth, group]) =>
      group.map((node, index) => {
        const angle = group.length === 1 ? 0 : (index / group.length) * Math.PI * 2;
        const radius = depth === 0 ? 0 : Math.max(150, group.length * 36);
        const x = Math.sin(angle) * radius;
        const y = (depth - centerDepth) * 170;
        const z = Math.cos(angle) * radius;
        const rotatedX = x * cosYaw - z * sinYaw;
        const yawZ = x * sinYaw + z * cosYaw;
        const rotatedY = y * cosPitch - yawZ * sinPitch;
        const rotatedZ = y * sinPitch + yawZ * cosPitch;
        const perspective = 900 / Math.max(420, 900 + rotatedZ);
        return {
          ...node,
          x:
            graphCanvasWidth / 2 +
            rotatedX * perspective * graph3dZoom +
            (graphNodeOffsets.get(node.entry_address)?.x ?? 0),
          y:
            graph3dHeight / 2 +
            rotatedY * perspective * graph3dZoom +
            (graphNodeOffsets.get(node.entry_address)?.y ?? 0),
          z: rotatedZ,
          scale: perspective * graph3dZoom,
        };
      }),
    );
    const positions = new Map(nodes.map((node) => [node.entry_address, node]));
    const edges = callGraphResult.edges.flatMap((edge) => {
      const from = positions.get(edge.from);
      const to = positions.get(edge.to);
      return from && to ? [{ ...edge, fromNode: from, toNode: to }] : [];
    });
    return { nodes: [...nodes].sort((a, b) => b.z - a.z), edges };
  });

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

  let isDisassemblingSelected = $derived(
    selectedFunctionAddress !== null &&
      pendingDisassemblies.has(selectedFunctionAddress),
  );

  let selectedDisassemblyError = $derived(
    selectedFunctionAddress === null
      ? ""
      : (disassemblyErrors.get(selectedFunctionAddress) ?? ""),
  );

  let selectedDisassembly = $derived(
    selectedFunctionAddress === null
      ? null
      : (disassemblyCache.get(selectedFunctionAddress) ?? null),
  );

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
  let selectedBsimResult = $derived(
    enrichedDetails?.bsim ??
      (selectedFunctionAddress ? backgroundBsimResults.get(selectedFunctionAddress) : null) ??
      null,
  );

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
      graphInspectedFunctionAddress = null;
      graphNodeOffsets = new Map();
      graph2dPanX = 0;
      graph2dPanY = 0;
    }
  });

  $effect(() => {
    const currentProgramSha = importedExport?.program.sha256 ?? null;
    if (currentProgramSha !== identificationProgramSha) {
      identificationProgramSha = currentProgramSha;
      ignoredIdentificationAddresses = new Set();
      identificationPage = 1;
      identificationQueueFilter = "matched";
      identificationQueueSearch = "";
      automaticIdentificationMode = false;
      automaticIdentificationPage = 1;
      automaticRenameError = "";
      automaticRenameSuccess = "";
    }
  });

  $effect(() => {
    const currentProgramSha = importedExport?.program.sha256 ?? null;
    if (currentProgramSha !== browserHistoryProgramSha) {
      browserHistoryProgramSha = currentProgramSha;
      browserHistory = [];
      browserHistoryIndex = -1;
      browserSearch = "";
      browserSymbolFilter = "all";
      browserPage = 1;
      disassemblyCache = new Map();
      pendingDisassemblies = new Set();
      disassemblyErrors = new Map();
    }
  });

  $effect(() => {
    if (activeWorkspaceView !== "identification") return;
    const queue = identificationQueue;
    if (queue.length === 0) return;
    if (!queue.some((func) => func.entry_address === selectedFunctionAddress)) {
      selectedFunctionAddress = queue[0].entry_address;
    }
  });

  $effect(() => {
    refreshEnvironmentConfiguration();
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

  function installIdentificationEvidence(items: FunctionIdentification[]) {
    identifications = new Map(
      items.map((identification) => [identification.entry_address, identification.candidates]),
    );
    backgroundBsimResults = new Map(
      items
        .filter((identification) => identification.bsim_scanned)
        .map((identification) => [
          identification.entry_address,
          {
            status: "available" as const,
            matches: identification.bsim_candidates,
            message: identification.bsim_message,
          },
        ]),
    );
    void refreshBsimRepetitionCorroboration(items);
    void runBackgroundArbitration();
    void runBackgroundGeneration();
  }

  async function refreshBsimRepetitionCorroboration(items: FunctionIdentification[]) {
    try {
      const counts = await invoke<Record<string, number>>(
        "compute_bsim_repetition_corroboration",
        { identifications: items },
      );
      bsimRepetitionCounts = new Map(Object.entries(counts));
    } catch (error) {
      // Best-effort enhancement: a failure here just means no repetition
      // corroboration is available yet -- the existing thresholds still
      // apply on their own, nothing else breaks.
      console.error("BSim repetition corroboration failed", error);
    }
  }

  function bsimResultForAddress(entryAddress: string): BsimQueryResult | undefined {
    return decompileCache.get(entryAddress)?.bsim ?? backgroundBsimResults.get(entryAddress);
  }

  async function runBackgroundBsimScan(projectId: string): Promise<boolean> {
    try {
      const evidence = await invoke<FunctionIdentification[]>("scan_project_with_bsim", {
        projectId,
      });
      installIdentificationEvidence(evidence);
      return true;
    } catch (error) {
      console.error("Background BSim scan failed", error);
      analyzeError = `Le balayage BSim en arrière-plan a échoué : ${String(error)}`;
      analysisProgress = {
        stage: "error",
        message: "Le balayage BSim n’a pas pu se terminer.",
        completed_percent: null,
      };
      analysisProgressMinimized = false;
      analysisProgressVisible = true;
      return false;
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
    backgroundBsimResults = new Map();
    functionIdAnalysisAvailable = false;

    try {
      const loaded = await invoke<LoadedProject>("open_project", { id });

      importedExport = loaded.export;
      selectedFunctionAddress = initialFunctionAddress(loaded.export);
      // Restore any arbitration answers already spent in a previous
      // session *before* installing evidence -- runBackgroundArbitration
      // (triggered from within installIdentificationEvidence) skips any
      // address already present here, so a real AI call is never re-spent
      // on a tie that was already resolved.
      try {
        const storedArbitration = await invoke<StoredArbitrationOutcome[]>(
          "get_arbitration_results",
          { projectId: id },
        );
        arbitrationResults = new Map(
          storedArbitration.map((stored) => [
            stored.entry_address,
            {
              chosen_name: stored.chosen_name,
              reasoning: stored.reasoning,
              provider_label: stored.provider_label,
            },
          ]),
        );
      } catch (error) {
        console.error("Failed to load stored arbitration results", error);
      }
      // Same rationale as arbitration, for generative suggestions.
      try {
        const storedGeneration = await invoke<StoredGenerationOutcome[]>(
          "get_generation_results",
          { projectId: id },
        );
        generationResults = new Map(
          storedGeneration.map((stored) => [
            stored.entry_address,
            {
              suggested_name: stored.suggested_name,
              reasoning: stored.reasoning,
              provider_label: stored.provider_label,
            },
          ]),
        );
      } catch (error) {
        console.error("Failed to load stored generation results", error);
      }
      installIdentificationEvidence(loaded.identifications ?? []);
      functionIdAnalysisAvailable = loaded.identifications !== null;
      // A currently-available session (Ghidra project files genuinely
      // present right now, just re-verified by the backend) keeps
      // on-demand decompilation working, exactly like a fresh automatic
      // analysis. Anything else -- no session at all, or one whose Ghidra
      // project is unreachable this time -- behaves like a manual import.
      analysisSource = loaded.project.session_available ? "automatic" : "manual";
      activeProjectId = loaded.project.id;
      activeWorkspaceView = "overview";
      const scannedAddresses = new Set(
        (loaded.identifications ?? [])
          .filter((identification) => identification.bsim_scanned)
          .map((identification) => identification.entry_address),
      );
      const needsBsimScan = loaded.project.session_available && loaded.export.functions.some(
        (func) => !func.is_external && isGeneratedFunctionName(func.name) && !scannedAddresses.has(func.entry_address),
      );
      if (needsBsimScan) {
        analysisTargetName = loaded.export.program.name;
        analysisProgressMinimized = true;
        analysisProgressVisible = true;
        void runBackgroundBsimScan(loaded.project.id).then((completed) => {
          if (completed) {
            setTimeout(() => {
              analysisProgressVisible = false;
            }, 1200);
          }
        });
      }
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
      comparisonView = "changed";
      comparisonSearch = "";
      comparisonPage = 1;
    } catch (error) {
      projectComparisonError = String(error);
    } finally {
      isComparingProjects = false;
    }
  }

  function clearProjectComparison() {
    projectComparison = null;
    projectComparisonError = "";
    comparisonSearch = "";
    comparisonPage = 1;
  }

  function swapComparisonProjects() {
    const previousA = comparisonProjectAId;
    comparisonProjectAId = comparisonProjectBId;
    comparisonProjectBId = previousA;
    clearProjectComparison();
  }

  function selectComparisonView(view: ComparisonView) {
    comparisonView = view;
    comparisonPage = 1;
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
    switch (kind) {
      case "return_type":
        return "Type de retour";
      case "parameters":
        return "Paramètres";
      case "thunk_status":
        return "Statut thunk";
      case "external_status":
        return "Statut externe";
      case "outgoing_call_count":
        return "Appels sortants";
    }
  }

  function formatUnmatchedReason(reason: UnmatchedReason): string {
    switch (reason) {
      case "auto_generated_name":
        return "Nom automatique Ghidra : pas d'appariement fiable";
      case "ambiguous_name":
        return "Nom ambigu présent plusieurs fois";
      case "no_candidate":
        return "Aucun symbole unique correspondant";
    }
  }

  function displayFilesystemPath(path: string): string {
    return path.startsWith("\\\\?\\") ? path.slice(4) : path;
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

  function isGeneratedFunctionName(name: string): boolean {
    return /^(?:thunk_)?FUN_[0-9a-f]+$/i.test(name) || /^sub_[0-9a-f]+$/i.test(name);
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

  // Disassembly is only fetched for the Code Browser tab -- unlike
  // pseudocode, an instruction listing has no use elsewhere in the app yet,
  // so there is no reason to pay for a Ghidra round trip when the user is
  // looking at the Functions or Graph tabs instead.
  $effect(() => {
    const func = selectedFunction;

    if (
      activeWorkspaceView !== "browser" ||
      !func ||
      analysisSource !== "automatic" ||
      func.is_external
    )
      return;
    if (
      disassemblyCache.has(func.entry_address) ||
      pendingDisassemblies.has(func.entry_address)
    )
      return;

    requestDisassembly(func.entry_address);
  });

  $effect(() => {
    const currentProgramSha = importedExport?.program.sha256 ?? null;
    if (currentProgramSha !== programListingProgramSha) {
      programListingProgramSha = currentProgramSha;
      programListingPage = 1;
      programListingCache = new Map();
      programListingError = "";
    }
  });

  $effect(() => {
    if (
      activeWorkspaceView !== "browser" ||
      codeBrowserListingMode !== "program" ||
      analysisSource !== "automatic"
    )
      return;

    const page = currentProgramListingPage;
    if (programListingCache.has(page) || isLoadingProgramListingPage) return;

    const addresses = paginatedProgramListingFunctions.map((func) => func.entry_address);
    if (addresses.length === 0) return;

    requestProgramListingPage(page, addresses);
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

  async function requestDisassembly(entryAddress: string) {
    pendingDisassemblies = new Set(pendingDisassemblies).add(entryAddress);

    const errorsWithoutCurrentAddress = new Map(disassemblyErrors);
    errorsWithoutCurrentAddress.delete(entryAddress);
    disassemblyErrors = errorsWithoutCurrentAddress;

    try {
      const disassembly = await invoke<FunctionDisassembly>(
        "disassemble_function",
        { entryAddress },
      );

      disassemblyCache = new Map(disassemblyCache).set(entryAddress, disassembly);
    } catch (error) {
      disassemblyErrors = new Map(disassemblyErrors).set(entryAddress, String(error));
    } finally {
      const remainingDisassemblies = new Set(pendingDisassemblies);
      remainingDisassemblies.delete(entryAddress);
      pendingDisassemblies = remainingDisassemblies;
    }
  }

  async function requestProgramListingPage(page: number, entryAddresses: string[]) {
    isLoadingProgramListingPage = true;
    programListingError = "";

    try {
      const disassembly = await invoke<FunctionDisassembly>("disassemble_functions", {
        entryAddresses,
      });

      programListingCache = new Map(programListingCache).set(
        page,
        disassembly.instructions,
      );
    } catch (error) {
      programListingError = String(error);
    } finally {
      isLoadingProgramListingPage = false;
    }
  }

  // Code Browser back/forward: a real index-based history (not a push-only
  // stack like the graph's) so forward navigation works after going back,
  // matching what "back"/"forward" mean in a real code browser.
  function openInBrowser(entryAddress: string | null) {
    if (!entryAddress) return;

    if (browserHistory[browserHistoryIndex] !== entryAddress) {
      const truncated = browserHistory.slice(0, browserHistoryIndex + 1);
      browserHistory = [...truncated, entryAddress];
      browserHistoryIndex = browserHistory.length - 1;
    }

    selectedFunctionAddress = entryAddress;
    activeWorkspaceView = "browser";
  }

  function browserGoBack() {
    if (browserHistoryIndex <= 0) return;
    browserHistoryIndex -= 1;
    selectedFunctionAddress = browserHistory[browserHistoryIndex];
  }

  function browserGoForward() {
    if (browserHistoryIndex >= browserHistory.length - 1) return;
    browserHistoryIndex += 1;
    selectedFunctionAddress = browserHistory[browserHistoryIndex];
  }

  async function applySelectedFunctionRename(): Promise<boolean> {
    if (!selectedFunction || !activeProjectId || analysisSource !== "automatic") {
      functionRenameError = "Open a live saved project before applying a rename.";
      return false;
    }
    const newName = functionRenameDraft.trim();
    if (!newName || newName === selectedFunction.name) {
      functionRenameError = "Enter a different non-empty function name.";
      return false;
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
      return true;
    } catch (error) {
      functionRenameError = String(error);
      return false;
    } finally {
      isApplyingFunctionRename = false;
    }
  }

  async function applyIdentificationRenameAndNext() {
    if (!selectedFunction) return;
    const queueBeforeRename = identificationQueue;
    const currentIndex = queueBeforeRename.findIndex(
      (func) => func.entry_address === selectedFunction?.entry_address,
    );
    const nextAddress =
      queueBeforeRename[currentIndex + 1]?.entry_address ??
      queueBeforeRename[currentIndex - 1]?.entry_address ??
      null;
    if (await applySelectedFunctionRename()) {
      selectedFunctionAddress = nextAddress;
    }
  }

  function ignoreIdentificationAndNext() {
    if (!selectedFunction) return;
    const currentAddress = selectedFunction.entry_address;
    const currentIndex = identificationQueue.findIndex(
      (func) => func.entry_address === currentAddress,
    );
    const nextAddress =
      identificationQueue[currentIndex + 1]?.entry_address ??
      identificationQueue[currentIndex - 1]?.entry_address ??
      null;
    ignoredIdentificationAddresses = new Set(ignoredIdentificationAddresses).add(currentAddress);
    selectedFunctionAddress = nextAddress;
  }

  async function applyAutomaticFunctionRenames() {
    if (!activeProjectId || analysisSource !== "automatic") {
      automaticRenameError = "Le mode automatique demande un projet Ghidra local actif.";
      return;
    }
    const batch = automaticRenameCandidates.slice(0, 500);
    if (batch.length === 0) return;
    if (!window.confirm(
      `Appliquer ${batch.length} proposition(s) nettoyée(s) dans Ghidra ? ${automaticAmbiguousChoiceCount} choix sont marqués comme ambigus : le premier résultat FunctionID nettoyé sera utilisé, comme affiché dans le tableau.`,
    )) return;

    automaticRenameError = "";
    automaticRenameSuccess = "";
    isApplyingAutomaticRenames = true;
    try {
      const result = await invoke<ApplyRenamesResult>("apply_function_renames", {
        projectId: activeProjectId,
        renames: batch.map(({ func, name }) => ({
          entry_address: func.entry_address,
          new_name: name,
        })),
      });
      importedExport = result.imported.export;
      importSummary = result.imported.summary;
      decompileCache = new Map();
      decompileErrors = new Map();
      automaticRenameSuccess = `${result.applied.length} fonction(s) renommée(s) dans Ghidra.`;
      selectedFunctionAddress = null;
      await requestProjectList();
    } catch (error) {
      automaticRenameError = String(error);
    } finally {
      isApplyingAutomaticRenames = false;
    }
  }

  function selectFunctionRenameSuggestion(name: string) {
    functionRenameDraft = name;
    functionRenameError = "";
    functionRenameSuccess = "";
  }

  function tiedCandidatesFor(entryAddress: string): { name: string; source_label: string }[] {
    // RTTI already gives the real, verified answer for this function --
    // either one confirmed class name or the real set of classes the
    // compiler/linker folded together (both auto-resolved directly, see
    // automaticRenameEvaluation). Either way, arbitration has nothing to
    // add and would just spend a real API call on an already-known answer.
    const rttiClassNames = importedExport?.functions.find(
      (candidate) => candidate.entry_address === entryAddress,
    )?.rtti_class_names;
    if (rttiClassNames && rttiClassNames.length > 0) return [];

    const fidCandidates = uniqueFidCandidates(identifications.get(entryAddress) ?? []);
    const topFidScore = fidCandidates[0]?.overall_score;
    const tiedFid = topFidScore === undefined
      ? []
      : fidCandidates.filter(
          (candidate) => Math.abs(candidate.overall_score - topFidScore) < 0.0001,
        );

    if (tiedFid.length >= 2) {
      // A researcher wouldn't weigh all tied candidates equally: narrow to
      // whichever are independently confirmed to exist somewhere else in
      // this exact binary via RTTI, discounting FID's fuzzy-matched noise
      // from libraries this binary shows no other trace of using. Only
      // narrows when that leaves a strictly smaller, non-empty set --
      // otherwise the full tied set is used, unchanged.
      const corroborated = tiedFid.filter((candidate) =>
        isCorroboratedByRtti(candidate.name, knownRealClassNames),
      );
      const isNarrowed = corroborated.length > 0 && corroborated.length < tiedFid.length;
      const narrowed = isNarrowed ? corroborated : tiedFid;
      if (narrowed.length >= 2) {
        return narrowed.map((candidate) => ({
          name: candidate.name,
          source_label: isNarrowed
            ? `FunctionID (${candidate.library_family} ${candidate.library_version}) — corroboré par RTTI ailleurs dans ce binaire`
            : `FunctionID (${candidate.library_family} ${candidate.library_version})`,
        }));
      }
    }

    // No usable FunctionID tie -- several genuinely different library
    // functions can still compile to byte-identical code and tie at the
    // exact same BSim similarity/significance (see
    // identification_corroboration.rs's clean-winner rule: a tied address
    // never corroborates any one of the tied names by repetition alone).
    // Same shape of ambiguity as FunctionID's tied candidates, just from a
    // different identification method -- just as suited to the same
    // context-based arbitration.
    const bsim = bsimResultForAddress(entryAddress);
    const bsimCandidates = bsim?.status === "available" ? uniqueBsimCandidates(bsim.matches) : [];
    const topSimilarity = bsimCandidates[0]?.similarity;
    const tiedBsim = topSimilarity === undefined
      ? []
      : bsimCandidates.filter(
          (candidate) => topSimilarity - candidate.similarity < automaticBsimMinimumMargin,
        );
    if (tiedBsim.length >= 2) {
      return tiedBsim.map((candidate) => ({
        name: candidate.name,
        source_label: `BSim (${candidate.executable}, similarité ${candidate.similarity.toFixed(3)})`,
      }));
    }

    return [];
  }

  async function arbitrateFunction(entryAddress: string): Promise<void> {
    const candidates = tiedCandidatesFor(entryAddress);
    if (candidates.length === 0) return;

    arbitratingAddresses = new Set(arbitratingAddresses).add(entryAddress);
    const errorsWithoutThisAddress = new Map(arbitrationErrors);
    errorsWithoutThisAddress.delete(entryAddress);
    arbitrationErrors = errorsWithoutThisAddress;

    try {
      const result = await invoke<ArbitrationOutcome>("arbitrate_identification_tie", {
        entryAddress,
        candidates,
      });
      arbitrationResults = new Map(arbitrationResults).set(entryAddress, result);
      // Best-effort: a real AI answer must never be re-spent on a reopen.
      // A failure to persist it doesn't affect this session (it's already
      // in arbitrationResults above), only whether it survives a restart.
      if (activeProjectId) {
        const projectId = activeProjectId;
        void invoke("save_arbitration_result", { projectId, entryAddress, outcome: result }).catch(
          (error) => console.error("Failed to persist the arbitration result", error),
        );
      }
    } catch (error) {
      arbitrationErrors = new Map(arbitrationErrors).set(entryAddress, String(error));
    } finally {
      const remaining = new Set(arbitratingAddresses);
      remaining.delete(entryAddress);
      arbitratingAddresses = remaining;
    }
  }

  async function requestArbitration() {
    if (!selectedFunction) return;
    await arbitrateFunction(selectedFunction.entry_address);
  }

  // Runs automatically once an AI provider is enabled -- one call at a
  // time (never in parallel), both to keep real API cost/rate under
  // control and because it mirrors every other Ghidra-adjacent queue in
  // this app. Already-resolved or already-failed functions are skipped,
  // so reopening a project never re-spends real API calls on the same
  // tie twice.
  async function runBackgroundArbitration() {
    if (isBackgroundArbitrating) return;
    if (!aiProviders.some((provider) => provider.enabled)) return;

    const pending = unidentifiedFunctions
      .map((func) => func.entry_address)
      .filter(
        (entryAddress) =>
          !arbitrationResults.has(entryAddress) &&
          !arbitrationErrors.has(entryAddress) &&
          tiedCandidatesFor(entryAddress).length > 0,
      );
    if (pending.length === 0) return;

    isBackgroundArbitrating = true;
    try {
      for (const entryAddress of pending) {
        await arbitrateFunction(entryAddress);
      }
    } finally {
      isBackgroundArbitrating = false;
    }
  }

  // Same shape as arbitrateFunction, for functions with zero FunctionID/
  // BSim candidates (nothing to select between, see naming_generation.rs).
  // The result is deliberately never fed into automaticRenameEvaluation --
  // an invented name needs a human to look at it before it's applied,
  // unlike RTTI/FunctionID/BSim/arbitration choices which are all backed
  // by a real, independently-found candidate.
  async function generateSuggestionFor(entryAddress: string): Promise<void> {
    generatingAddresses = new Set(generatingAddresses).add(entryAddress);
    const errorsWithoutThisAddress = new Map(generationErrors);
    errorsWithoutThisAddress.delete(entryAddress);
    generationErrors = errorsWithoutThisAddress;

    try {
      const result = await invoke<GenerationOutcome>("generate_identification_suggestion", {
        entryAddress,
      });
      generationResults = new Map(generationResults).set(entryAddress, result);
      if (activeProjectId) {
        const projectId = activeProjectId;
        void invoke("save_generation_result", { projectId, entryAddress, outcome: result }).catch(
          (error) => console.error("Failed to persist the generation result", error),
        );
      }
    } catch (error) {
      generationErrors = new Map(generationErrors).set(entryAddress, String(error));
    } finally {
      const remaining = new Set(generatingAddresses);
      remaining.delete(entryAddress);
      generatingAddresses = remaining;
    }
  }

  async function requestGeneration() {
    if (!selectedFunction) return;
    await generateSuggestionFor(selectedFunction.entry_address);
  }

  // Mirrors runBackgroundArbitration: sequential, one real API call at a
  // time, gated on an enabled provider, skipping anything already resolved
  // or already failed so a reopen never re-spends a call on the same
  // function twice.
  async function runBackgroundGeneration() {
    if (isBackgroundGenerating) return;
    if (!aiProviders.some((provider) => provider.enabled)) return;

    const pending = unidentifiedFunctions
      .filter(
        (func) =>
          hasNoEvidenceAtAll(func) &&
          !generationResults.has(func.entry_address) &&
          !generationErrors.has(func.entry_address),
      )
      .map((func) => func.entry_address);
    if (pending.length === 0) return;

    isBackgroundGenerating = true;
    try {
      for (const entryAddress of pending) {
        await generateSuggestionFor(entryAddress);
      }
    } finally {
      isBackgroundGenerating = false;
    }
  }

  function selectIdentificationEvidenceFirst() {
    const selectedHasEvidence = selectedFunctionAddress !== null &&
      hasIdentificationEvidence(selectedFunctionAddress);
    if (selectedHasEvidence) return;

    const firstWithEvidence = identificationQueue.find((func) =>
      hasIdentificationEvidence(func.entry_address)
    );
    if (firstWithEvidence) selectedFunctionAddress = firstWithEvidence.entry_address;
  }

  function reviewIdentificationFunction(entryAddress: string) {
    automaticIdentificationMode = false;
    identificationQueueFilter = "matched";
    identificationQueueSearch = "";
    const matched = sortIdentificationFunctions(
      remainingIdentificationFunctions.filter((func) => hasIdentificationEvidence(func.entry_address)),
    );
    const index = matched.findIndex((func) => func.entry_address === entryAddress);
    identificationPage = index < 0 ? 1 : Math.floor(index / identificationPageSize) + 1;
    openFunction(entryAddress, false);
  }

  function selectWorkspaceView(view: WorkspaceView) {
    activeWorkspaceView = view;
    if (view === "identification") selectIdentificationEvidenceFirst();
  }

  function openFunction(entryAddress: string | null, navigateToFunctions = true) {
    if (!entryAddress) return;
    selectedFunctionAddress = entryAddress;
    if (navigateToFunctions) activeWorkspaceView = "functions";
  }

  const HEX_ADDRESS_IN_TEXT = /0x[0-9a-f]+/;

  // A jump/call instruction's operand is Ghidra's own formatted target
  // address (e.g. "0x00400550" for `CALL 0x00400550`) -- only surfaced as
  // a clickable function reference when it resolves to a real function
  // entry in this export, not whenever the text merely looks like an
  // address (e.g. a local jump into the middle of the current function,
  // which isn't a separately browsable unit with the data we have).
  function disasmTarget(
    instruction: DisassembledInstruction,
  ): { address: string; name: string } | null {
    const isBranch =
      instruction.flow_category === "unconditional_call" ||
      instruction.flow_category === "conditional_call" ||
      instruction.flow_category === "unconditional_jump" ||
      instruction.flow_category === "conditional_jump";

    if (!isBranch || !importedExport) return null;

    const match = instruction.operands.match(HEX_ADDRESS_IN_TEXT);
    if (!match) return null;

    const address = match[0];
    const targetFunction = importedExport.functions.find(
      (func) => func.entry_address === address,
    );

    return targetFunction ? { address, name: targetFunction.name } : null;
  }

  function navigateWithinGraph(entryAddress: string) {
    const isCurrentRoot = selectedFunctionAddress === entryAddress;
    if (selectedFunctionAddress && selectedFunctionAddress !== entryAddress) {
      graphNavigationHistory = [...graphNavigationHistory, selectedFunctionAddress];
    }
    graphInspectedFunctionAddress = entryAddress;
    graphNodeOffsets = new Map();
    graph2dPanX = 0;
    graph2dPanY = 0;
    openFunction(entryAddress, false);
    if (isCurrentRoot && analysisSource !== "none") {
      void requestCallGraph(entryAddress, callGraphDirection, callGraphDepth);
    }
  }

  function navigateBackInGraph() {
    const previousAddress = graphNavigationHistory.at(-1);
    if (!previousAddress) return;
    graphNavigationHistory = graphNavigationHistory.slice(0, -1);
    graphInspectedFunctionAddress = previousAddress;
    graphNodeOffsets = new Map();
    graph2dPanX = 0;
    graph2dPanY = 0;
    openFunction(previousAddress, false);
  }

  function inspectGraphFunction(entryAddress: string) {
    graphInspectedFunctionAddress = entryAddress;
  }

  function resetGraphNodePositions() {
    graphNodeOffsets = new Map();
  }

  function handleGraphNodePointerDown(event: PointerEvent, entryAddress: string) {
    if (event.button !== 0) return;
    event.stopPropagation();
    const offset = graphNodeOffsets.get(entryAddress) ?? { x: 0, y: 0 };
    graphNodeDrag = {
      address: entryAddress,
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      offsetX: offset.x,
      offsetY: offset.y,
      moved: false,
    };
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  }

  function handleGraphNodePointerMove(event: PointerEvent) {
    if (!graphNodeDrag || graphNodeDrag.pointerId !== event.pointerId) return;
    event.stopPropagation();
    const coordinateScale = graphViewMode === "2d" ? graph2dZoom : 1;
    const deltaX = (event.clientX - graphNodeDrag.startX) / coordinateScale;
    const deltaY = (event.clientY - graphNodeDrag.startY) / coordinateScale;
    const moved = graphNodeDrag.moved || Math.hypot(deltaX, deltaY) > 4;
    graphNodeOffsets = new Map(graphNodeOffsets).set(graphNodeDrag.address, {
      x: graphNodeDrag.offsetX + deltaX,
      y: graphNodeDrag.offsetY + deltaY,
    });
    graphNodeDrag = { ...graphNodeDrag, moved };
  }

  function handleGraphNodePointerUp(event: PointerEvent) {
    if (!graphNodeDrag || graphNodeDrag.pointerId !== event.pointerId) return;
    event.stopPropagation();
    const { address, moved } = graphNodeDrag;
    graphNodeDrag = null;
    if (!moved) inspectGraphFunction(address);
  }

  function handleGraphPanPointerDown(event: PointerEvent) {
    if (event.button !== 2) return;
    event.preventDefault();
    const container = event.currentTarget as HTMLElement;
    graphPanDrag = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      scrollLeft: container.scrollLeft,
      scrollTop: container.scrollTop,
      panX: graph2dPanX,
      panY: graph2dPanY,
    };
    container.setPointerCapture(event.pointerId);
  }

  function handleGraphPanPointerMove(event: PointerEvent) {
    if (!graphPanDrag || graphPanDrag.pointerId !== event.pointerId) return;
    event.preventDefault();
    const container = event.currentTarget as HTMLElement;
    if (graphViewMode === "2d") {
      graph2dPanX = graphPanDrag.panX + (event.clientX - graphPanDrag.startX);
      graph2dPanY = graphPanDrag.panY + (event.clientY - graphPanDrag.startY);
    } else {
      container.scrollLeft = graphPanDrag.scrollLeft - (event.clientX - graphPanDrag.startX);
      container.scrollTop = graphPanDrag.scrollTop - (event.clientY - graphPanDrag.startY);
    }
  }

  function handleGraphPanPointerUp(event: PointerEvent) {
    if (graphPanDrag?.pointerId === event.pointerId) graphPanDrag = null;
  }

  function handleGraphStageWheel(event: WheelEvent) {
    if (graphViewMode !== "2d") return;
    event.preventDefault();
    graph2dZoom = Math.max(
      0.5,
      Math.min(2, graph2dZoom - event.deltaY * 0.0012),
    );
  }

  function resetGraph2dZoom() {
    graph2dZoom = 1;
    graph2dPanX = 0;
    graph2dPanY = 0;
  }

  function resetGraph3dView() {
    graph3dYaw = -0.35;
    graph3dPitch = 0.28;
    graph3dZoom = 1;
  }

  function handleGraph3dPointerDown(event: PointerEvent) {
    if (event.button !== 0) return;
    if ((event.target as HTMLElement).closest("button")) return;
    graph3dDrag = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      startYaw: graph3dYaw,
      startPitch: graph3dPitch,
    };
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  }

  function handleGraph3dPointerMove(event: PointerEvent) {
    if (!graph3dDrag || graph3dDrag.pointerId !== event.pointerId) return;
    graph3dYaw = graph3dDrag.startYaw + (event.clientX - graph3dDrag.startX) * 0.008;
    graph3dPitch = Math.max(
      -1.2,
      Math.min(1.2, graph3dDrag.startPitch - (event.clientY - graph3dDrag.startY) * 0.006),
    );
  }

  function handleGraph3dPointerUp(event: PointerEvent) {
    if (graph3dDrag?.pointerId === event.pointerId) graph3dDrag = null;
  }

  function handleGraph3dWheel(event: WheelEvent) {
    event.preventDefault();
    graph3dZoom = Math.max(0.55, Math.min(1.8, graph3dZoom - event.deltaY * 0.001));
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

  async function loadSetupOverview() {
    setupOverviewError = "";
    try {
      setupOverview = await invoke<SetupOverview>("get_setup_overview");
    } catch (error) {
      setupOverview = null;
      setupOverviewError = String(error);
    }
  }

  async function loadBsimCorpora() {
    bsimCorporaError = "";
    try {
      bsimCorpora = await invoke<BsimCorpusSummary[]>("list_bsim_corpora");
    } catch (error) {
      bsimCorpora = [];
      bsimCorporaError = String(error);
    }
  }

  async function addPersonalBsimCorpus() {
    if (isManagingBsimCorpus) return;
    bsimCorporaError = "";
    try {
      const selected = await open({
        title: "Ajouter une base BSim Ghidra (.mv.db)",
        multiple: false,
        directory: false,
        filters: [{ name: "Base BSim Ghidra", extensions: ["db"] }],
      });
      if (typeof selected !== "string") return;
      isManagingBsimCorpus = true;
      await invoke("import_bsim_corpus", { path: selected });
      await loadBsimCorpora();
    } catch (error) {
      bsimCorporaError = String(error);
    } finally {
      isManagingBsimCorpus = false;
    }
  }

  async function addBsimReferenceLibrary() {
    if (isManagingBsimCorpus) return;
    bsimCorporaError = "";
    try {
      const selected = await open({
        title: "Ajouter une bibliothèque de référence à BSim",
        multiple: false,
        directory: false,
      });
      if (typeof selected !== "string") return;
      isManagingBsimCorpus = true;
      await invoke("add_bsim_reference_library", { path: selected });
      await loadBsimCorpora();
    } catch (error) {
      bsimCorporaError = String(error);
    } finally {
      isManagingBsimCorpus = false;
    }
  }

  async function toggleBsimCorpus(corpus: BsimCorpusSummary) {
    if (corpus.origin !== "custom" || isManagingBsimCorpus) return;
    isManagingBsimCorpus = true;
    bsimCorporaError = "";
    try {
      await invoke("set_bsim_corpus_enabled", { id: corpus.id, enabled: !corpus.enabled });
      await loadBsimCorpora();
    } catch (error) {
      bsimCorporaError = String(error);
    } finally {
      isManagingBsimCorpus = false;
    }
  }

  async function deleteBsimCorpus(corpus: BsimCorpusSummary) {
    if (!corpus.removable || isManagingBsimCorpus) return;
    if (!confirm(`Supprimer le corpus local « ${corpus.name} » ? Le fichier d’origine ne sera pas touché.`)) return;
    isManagingBsimCorpus = true;
    bsimCorporaError = "";
    try {
      await invoke("remove_bsim_corpus", { id: corpus.id });
      await loadBsimCorpora();
    } catch (error) {
      bsimCorporaError = String(error);
    } finally {
      isManagingBsimCorpus = false;
    }
  }

  async function loadAiProviders() {
    aiProvidersError = "";
    try {
      aiProviders = await invoke<AiProviderSummary[]>("list_ai_providers");
    } catch (error) {
      aiProviders = [];
      aiProvidersError = String(error);
    }
  }

  async function addAiProvider() {
    if (isManagingAiProvider) return;
    aiProvidersError = "";
    isManagingAiProvider = true;
    try {
      await invoke("add_ai_provider", {
        label: newAiProviderLabel,
        baseUrl: newAiProviderBaseUrl,
        apiKey: newAiProviderApiKey.trim().length > 0 ? newAiProviderApiKey : null,
        model: newAiProviderModel,
      });
      newAiProviderLabel = "";
      newAiProviderBaseUrl = "";
      newAiProviderApiKey = "";
      newAiProviderModel = "";
      await loadAiProviders();
      void runBackgroundArbitration();
      void runBackgroundGeneration();
    } catch (error) {
      aiProvidersError = String(error);
    } finally {
      isManagingAiProvider = false;
    }
  }

  async function toggleAiProvider(provider: AiProviderSummary) {
    if (isManagingAiProvider) return;
    isManagingAiProvider = true;
    aiProvidersError = "";
    try {
      await invoke("set_ai_provider_enabled", { id: provider.id, enabled: !provider.enabled });
      await loadAiProviders();
      void runBackgroundArbitration();
      void runBackgroundGeneration();
    } catch (error) {
      aiProvidersError = String(error);
    } finally {
      isManagingAiProvider = false;
    }
  }

  async function deleteAiProvider(provider: AiProviderSummary) {
    if (isManagingAiProvider) return;
    if (!confirm(`Supprimer le fournisseur « ${provider.label} » ? Sa clé, si elle existe, sera effacée localement.`)) return;
    isManagingAiProvider = true;
    aiProvidersError = "";
    try {
      await invoke("remove_ai_provider", { id: provider.id });
      await loadAiProviders();
    } catch (error) {
      aiProvidersError = String(error);
    } finally {
      isManagingAiProvider = false;
    }
  }

  function formatFileSize(size: number | null) {
    if (size === null) return "taille inconnue";
    if (size < 1024 * 1024) return `${Math.max(1, Math.round(size / 1024))} Ko`;
    return `${(size / (1024 * 1024)).toFixed(1)} Mo`;
  }

  async function refreshEnvironmentConfiguration() {
    await Promise.all([
      loadGhidraInstallationStatus(),
      loadSetupOverview(),
      loadBsimCorpora(),
      loadAiProviders(),
    ]);
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
      await refreshEnvironmentConfiguration();
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

  function formatAnalysisElapsed(totalSeconds: number): string {
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return minutes > 0 ? `${minutes} min ${seconds.toString().padStart(2, "0")} s` : `${seconds} s`;
  }

  function startAnalysisProgress() {
    if (analysisTimer !== null) clearInterval(analysisTimer);
    analysisElapsedSeconds = 0;
    analysisProgressMinimized = false;
    analysisProgressVisible = true;
    analysisProgress = {
      stage: "prepare",
      message: "Préparation de l’analyse locale…",
      completed_percent: 1,
    };
    analysisTimer = setInterval(() => {
      analysisElapsedSeconds += 1;
    }, 1000);
  }

  function stopAnalysisTimer() {
    if (analysisTimer !== null) {
      clearInterval(analysisTimer);
      analysisTimer = null;
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
    analysisTargetName = binaryPath.split(/[\\/]/).pop() ?? binaryPath;

    isAnalyzing = true;
    startAnalysisProgress();

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
      installIdentificationEvidence(result.identifications);
      functionIdAnalysisAvailable = true;
      // The backend auto-saves every completed analysis as a local
      // project -- refresh the list so it shows up right away.
      requestProjectList();
      analysisProgress = {
        stage: "complete",
        message: "Analyse terminée. Le projet est prêt.",
        completed_percent: 100,
      };
      await new Promise((resolve) => setTimeout(resolve, 850));
      analysisProgressVisible = false;
      if (result.saved_project?.id) {
        analysisProgressMinimized = true;
        analysisProgressVisible = true;
        void runBackgroundBsimScan(result.saved_project.id).then((completed) => {
          if (completed) {
            setTimeout(() => {
              analysisProgressVisible = false;
            }, 1200);
          }
        });
      }
    } catch (error) {
      analyzeError = String(error);
      analysisProgress = {
        stage: "error",
        message: "L’analyse n’a pas pu être terminée.",
        completed_percent: null,
      };
    } finally {
      isAnalyzing = false;
      stopAnalysisTimer();
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
  <SetupAssistant onready={refreshEnvironmentConfiguration} />
  {#if analysisProgressVisible && analysisProgress}
    {#if analysisProgressMinimized}
      <button
        type="button"
        class="analysis-progress-minimized"
        onclick={() => (analysisProgressMinimized = false)}
        aria-label="Afficher la progression de l’analyse"
      >
        <span class:complete={analysisProgress.stage === "complete"}></span>
        <strong>{analysisProgress.stage === "complete" ? "Analyse terminée" : "Analyse en cours"}</strong>
        <small>{formatAnalysisElapsed(analysisElapsedSeconds)}</small>
      </button>
    {:else}
      <aside class="analysis-progress-panel" aria-live="polite" aria-label="Progression de l’analyse">
        <header>
          <div>
            <p>ANALYSE LOCALE</p>
            <h2>{analysisTargetName || "Binaire sélectionné"}</h2>
          </div>
          {#if isAnalyzing}
            <button
              type="button"
              class="analysis-progress-collapse"
              onclick={() => (analysisProgressMinimized = true)}
            >Réduire</button>
          {:else}
            <button
              type="button"
              class="analysis-progress-collapse"
              onclick={() => (analysisProgressVisible = false)}
            >Fermer</button>
          {/if}
        </header>

        <div
          class="analysis-progress-track"
          class:indeterminate={analysisProgress.completed_percent === null && analysisProgress.stage !== "error"}
          class:failed={analysisProgress.stage === "error"}
          role="progressbar"
          aria-label="Progression de l’analyse"
          aria-valuemin="0"
          aria-valuemax="100"
          aria-valuenow={analysisProgress.completed_percent ?? undefined}
        >
          <span style:width={analysisProgress.completed_percent !== null ? `${analysisProgress.completed_percent}%` : undefined}></span>
        </div>

        <div class="analysis-progress-copy">
          <strong>{analysisProgress.message}</strong>
          <span>{formatAnalysisElapsed(analysisElapsedSeconds)}</span>
        </div>

        {#if analysisProgress.completed_percent !== null}
          <small>{analysisProgress.completed_percent}% terminé</small>
        {:else if analysisProgress.stage === "error"}
          <small class="analysis-progress-error">{analyzeError}</small>
        {:else}
          <small>Ghidra ne fournit pas de pourcentage fiable pour cette étape. L’analyse continue normalement.</small>
        {/if}
      </aside>
    {/if}
  {/if}
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
            onclick={() => selectWorkspaceView(view.id)}
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
          <header class="comparison-workspace-header">
            <div>
              <p class="detail-label">Analyse différentielle locale</p>
              <h2 id="project-comparison-title">Comparer deux analyses</h2>
              <p>Repère les fonctions modifiées, ajoutées ou supprimées entre deux projets sauvegardés.</p>
            </div>
            <span>Aucune donnée ne quitte cette machine</span>
          </header>

          <div class="comparison-project-picker">
            <label>
              <span>VERSION A · RÉFÉRENCE</span>
              <select bind:value={comparisonProjectAId} onchange={clearProjectComparison}>
                <option value="">Choisir un projet…</option>
                {#each savedProjects as project (project.id)}
                  <option value={project.id} disabled={project.id === comparisonProjectBId}>
                    {project.name} — {project.program_name} ({project.function_count} fonctions)
                  </option>
                {/each}
              </select>
            </label>

            <button type="button" class="comparison-swap" onclick={swapComparisonProjects} title="Inverser les versions">⇄</button>

            <label>
              <span>VERSION B · CIBLE</span>
              <select bind:value={comparisonProjectBId} onchange={clearProjectComparison}>
                <option value="">Choisir un projet…</option>
                {#each savedProjects as project (project.id)}
                  <option value={project.id} disabled={project.id === comparisonProjectAId}>
                    {project.name} — {project.program_name} ({project.function_count} fonctions)
                  </option>
                {/each}
              </select>
            </label>

            <button type="button" class="comparison-run" disabled={isComparingProjects || !comparisonProjectAId || !comparisonProjectBId} onclick={compareSavedProjects}>
              {isComparingProjects ? "Comparaison…" : "Comparer"}
            </button>
          </div>

          {#if projectComparisonError}
            <p class="error" role="alert">{projectComparisonError}</p>
          {/if}

          {#if projectComparison}
            <div class="project-comparison-result">
              <div class="comparison-result-context">
                <span><strong>{comparisonProjectName(comparisonProjectAId)}</strong> → <strong>{comparisonProjectName(comparisonProjectBId)}</strong></span>
                <small>{projectComparison.same_binary ? "Même binaire : appariement par adresse autorisé" : "Binaires différents : appariement par symbole unique uniquement"}</small>
              </div>

              <dl class="comparison-kpis">
                <div class="matched"><dt>Fonctions communes</dt><dd>{projectComparison.matches.length}</dd><span>appariées avec une preuve</span></div>
                <div class="changed"><dt>Modifiées</dt><dd>{changedComparisonCount}</dd><span>métadonnées différentes</span></div>
                <div class="added"><dt>Ajoutées dans B</dt><dd>+{projectComparison.unmatched_b.length}</dd><span>absentes de la référence</span></div>
                <div class="removed"><dt>Supprimées de A</dt><dd>−{projectComparison.unmatched_a.length}</dd><span>absentes de la cible</span></div>
              </dl>

              <div class="comparison-browser">
                <nav class="comparison-tabs" aria-label="Catégorie de différences">
                  <button type="button" class:active={comparisonView === "changed"} onclick={() => selectComparisonView("changed")}>Modifiées <span>{changedComparisonCount}</span></button>
                  <button type="button" class:active={comparisonView === "added"} onclick={() => selectComparisonView("added")}>Ajoutées <span>{projectComparison.unmatched_b.length}</span></button>
                  <button type="button" class:active={comparisonView === "removed"} onclick={() => selectComparisonView("removed")}>Supprimées <span>{projectComparison.unmatched_a.length}</span></button>
                  <button type="button" class:active={comparisonView === "matched"} onclick={() => selectComparisonView("matched")}>Communes <span>{projectComparison.matches.length}</span></button>
                </nav>

                <div class="comparison-search-row">
                  <input type="search" placeholder="Rechercher une fonction ou une adresse…" bind:value={comparisonSearch} oninput={() => (comparisonPage = 1)} />
                  <span>{comparisonVisibleCount} résultat{comparisonVisibleCount > 1 ? "s" : ""}</span>
                </div>

                <div class="comparison-table-header">
                  <span>Fonction</span><span>Version A</span><span>Version B</span><span>Preuve / différences</span>
                </div>

                {#if comparisonVisibleCount === 0}
                  <div class="comparison-no-result"><strong>Aucun résultat dans cette catégorie</strong><span>Modifie la recherche ou choisis un autre type de différence.</span></div>
                {:else if comparisonView === "changed" || comparisonView === "matched"}
                  <ul class="comparison-rows">
                    {#each filteredComparisonMatches.slice((currentComparisonPage - 1) * comparisonPageSize, currentComparisonPage * comparisonPageSize) as match (`${match.function_a.entry_address}-${match.function_b.entry_address}`)}
                      <li class:changed={match.changes.length > 0}>
                        <div><strong>{qualifiedFunctionName(match.function_b)}</strong><small>{match.changes.length > 0 ? `${match.changes.length} modification(s)` : "Inchangée"}</small></div>
                        <code>{match.function_a.entry_address}</code>
                        <code>{match.function_b.entry_address}</code>
                        <div class="comparison-evidence">
                          <small>{match.method === "symbol_name" ? "Symbole unique" : "Même adresse"}{match.same_address ? " · adresse stable" : ""}</small>
                          {#if match.changes.length > 0}
                            {#each match.changes as change}
                              <span><strong>{formatChangeKind(change.kind)}</strong><code>{change.before || "∅"}</code><b>→</b><code>{change.after || "∅"}</code></span>
                            {/each}
                          {/if}
                        </div>
                      </li>
                    {/each}
                  </ul>
                {:else}
                  <ul class="comparison-rows comparison-single-side">
                    {#each (comparisonView === "added" ? filteredComparisonAdded : filteredComparisonRemoved).slice((currentComparisonPage - 1) * comparisonPageSize, currentComparisonPage * comparisonPageSize) as functionRef (functionRef.entry_address)}
                      <li class:added={comparisonView === "added"} class:removed={comparisonView === "removed"}>
                        <div><strong>{qualifiedFunctionName(functionRef)}</strong><small>{comparisonView === "added" ? "Ajoutée dans la version B" : "Supprimée de la version A"}</small></div>
                        <code>{comparisonView === "removed" ? functionRef.entry_address : "—"}</code>
                        <code>{comparisonView === "added" ? functionRef.entry_address : "—"}</code>
                        <div class="comparison-evidence"><small>{formatUnmatchedReason(functionRef.reason)}</small></div>
                      </li>
                    {/each}
                  </ul>
                {/if}

                <nav class="comparison-pagination" aria-label="Pagination des différences">
                  <button type="button" disabled={currentComparisonPage === 1} onclick={() => (comparisonPage = Math.max(1, currentComparisonPage - 1))}>← Précédente</button>
                  <span>Page {currentComparisonPage} sur {comparisonPageCount}</span>
                  <button type="button" disabled={currentComparisonPage === comparisonPageCount} onclick={() => (comparisonPage = Math.min(comparisonPageCount, currentComparisonPage + 1))}>Suivante →</button>
                </nav>
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
      class="settings-workspace"
      class:view-hidden={activeWorkspaceView !== "settings"}
      aria-labelledby="settings-workspace-title"
    >
      <header class="settings-workspace-header">
        <div><p class="detail-label">Configuration locale</p><h2 id="settings-workspace-title">Paramètres</h2><p>Contrôle l’environnement d’analyse et les outils avancés de cette installation.</p></div>
        <span class:ready={setupOverview?.ready}>{setupOverview?.ready ? "Environnement prêt" : "Configuration requise"}</span>
      </header>

      <section class="settings-section environment-settings">
        <header><div><h3>Environnement d’analyse</h3><p>État réel des composants vérifié par le backend local.</p></div><button type="button" class="secondary-button" onclick={refreshEnvironmentConfiguration}>Actualiser</button></header>
        {#if setupOverview}
          <div class="settings-components-grid">
            {#each setupOverview.components as component (component.id)}
              <article class:ready={component.state === "ready"} class:missing={component.state === "missing"} class:invalid={component.state === "invalid"}>
                <span class="settings-component-indicator"></span>
                <div><strong>{component.label}</strong><small>{component.version ?? (component.required ? "Requis" : "Optionnel")}</small></div>
                <b>{component.state === "ready" ? "Prêt" : component.state === "missing" ? "Absent" : "Invalide"}</b>
                <p>{component.detail}</p>
                {#if component.path}<code title={displayFilesystemPath(component.path)}>{displayFilesystemPath(component.path)}</code>{/if}
              </article>
            {/each}
          </div>
          <div class="settings-managed-root"><span>Répertoire géré par l’application</span><code>{displayFilesystemPath(setupOverview.managed_root)}</code></div>
        {:else if setupOverviewError}
          <p class="error" role="alert">{setupOverviewError}</p>
        {:else}
          <p>Vérification de l’environnement…</p>
        {/if}
      </section>

      <section class="settings-section ghidra-settings-card">
        <header><div><h3>Installation Ghidra</h3><p>Installation utilisée pour l’analyse headless, la décompilation et les modifications.</p></div><span class:ready={ghidraInstallationStatus?.status === "valid"}>{ghidraInstallationStatus?.status === "valid" ? "Configurée" : "Non disponible"}</span></header>
        {#if ghidraInstallationStatus?.status === "valid"}
          <dl>
            <div><dt>Version</dt><dd>{ghidraInstallationStatus.installation.version_label}</dd></div>
            <div><dt>Dossier d’installation</dt><dd><code title={displayFilesystemPath(ghidraInstallationStatus.installation.install_dir)}>{displayFilesystemPath(ghidraInstallationStatus.installation.install_dir)}</code></dd></div>
            <div><dt>Extensions utilisateur</dt><dd><code title={displayFilesystemPath(ghidraInstallationStatus.installation.extensions_dir)}>{displayFilesystemPath(ghidraInstallationStatus.installation.extensions_dir)}</code></dd></div>
          </dl>
          <div class="settings-actions"><button type="button" class="secondary-button" onclick={selectGhidraInstallDir}>Changer d’installation</button><button type="button" disabled={isAnalyzing} onclick={selectAndAnalyzeBinary}>{isAnalyzing ? "Analyse en cours…" : "Tester avec un binaire"}</button></div>
        {:else}
          {#if ghidraInstallationStatus?.status === "invalid"}<p class="settings-inline-error">{ghidraInstallationStatus.reason}</p>{/if}
          <div class="settings-actions"><button type="button" disabled={isConfiguringGhidra} onclick={selectGhidraInstallDir}>{isConfiguringGhidra ? "Configuration…" : "Choisir une installation Ghidra"}</button></div>
        {/if}
      </section>

      <section class="settings-section bsim-corpora-card">
        <header>
          <div>
            <h3>Corpus de reconnaissance BSim</h3>
            <p>Les corpus actifs sont interrogés ensemble lors de la décompilation d’une fonction.</p>
          </div>
          <div class="bsim-header-actions">
            <button type="button" disabled={isManagingBsimCorpus} onclick={addBsimReferenceLibrary}>
              {isManagingBsimCorpus ? "Analyse en cours…" : "+ Ajouter une bibliothèque"}
            </button>
            <button type="button" class="secondary-button" disabled={isManagingBsimCorpus} onclick={addPersonalBsimCorpus}>
              Importer une base .mv.db
            </button>
          </div>
        </header>
        <div class="bsim-corpus-list">
          {#each bsimCorpora as corpus (corpus.id)}
            <article class:disabled={!corpus.enabled} class:unavailable={!corpus.available}>
              <div class="bsim-corpus-state" class:active={corpus.enabled && corpus.available}></div>
              <div class="bsim-corpus-copy">
                <div class="bsim-corpus-heading">
                  <strong>{corpus.name}</strong>
                  <span>{corpus.origin === "built_in" ? "Fourni" : corpus.origin === "environment" ? "Environnement" : "Personnel"}</span>
                  <small>{formatFileSize(corpus.size_bytes)}</small>
                </div>
                <p>{corpus.description}</p>
                {#if corpus.libraries.length > 0}
                  <div class="bsim-library-tags">
                    {#each corpus.libraries as library}<span>{library}</span>{/each}
                  </div>
                {/if}
                <code title={displayFilesystemPath(corpus.path)}>{displayFilesystemPath(corpus.path)}</code>
              </div>
              <div class="bsim-corpus-actions">
                <b class:ready={corpus.enabled && corpus.available}>
                  {!corpus.available ? "Fichier absent" : corpus.enabled ? "Actif" : "Désactivé"}
                </b>
                {#if corpus.origin === "custom"}
                  <button type="button" class="secondary-button" disabled={isManagingBsimCorpus || !corpus.available} onclick={() => toggleBsimCorpus(corpus)}>{corpus.enabled ? "Désactiver" : "Activer"}</button>
                  <button type="button" class="danger-button" disabled={isManagingBsimCorpus} onclick={() => deleteBsimCorpus(corpus)}>Supprimer</button>
                {/if}
              </div>
            </article>
          {:else}
            <p class="bsim-corpus-empty">Aucun corpus BSim n’est disponible.</p>
          {/each}
        </div>
        <footer>
          <p><strong>Bibliothèque personnelle :</strong> choisis directement une DLL, un ELF ou un autre binaire. Ghidra l’analyse localement et construit sa base de signatures. L’import <code>.mv.db</code> reste disponible pour les corpus BSim déjà préparés.</p>
        </footer>
        {#if bsimCorporaError}<p class="settings-inline-error" role="alert">{bsimCorporaError}</p>{/if}
      </section>

      <section class="settings-section ai-providers-card">
        <header>
          <div>
            <h3>Fournisseurs IA</h3>
            <p>Un ou plusieurs fournisseurs peuvent être configurés en même temps — local (ex. Ollama), API distante (OpenAI, Mistral…), ou tout autre serveur compatible.</p>
          </div>
        </header>
        <div class="ai-provider-list">
          {#each aiProviders as provider (provider.id)}
            <article class:disabled={!provider.enabled}>
              <div class="ai-provider-state" class:active={provider.enabled}></div>
              <div class="ai-provider-copy">
                <div class="ai-provider-heading">
                  <strong>{provider.label}</strong>
                  <small>{provider.model}</small>
                </div>
                <code>{provider.base_url}</code>
                <span class="ai-provider-key-state">{provider.has_api_key ? "Clé API configurée" : "Sans clé (local)"}</span>
              </div>
              <div class="ai-provider-actions">
                <b class:ready={provider.enabled}>{provider.enabled ? "Actif" : "Désactivé"}</b>
                <button type="button" class="secondary-button" disabled={isManagingAiProvider} onclick={() => toggleAiProvider(provider)}>{provider.enabled ? "Désactiver" : "Activer"}</button>
                <button type="button" class="danger-button" disabled={isManagingAiProvider} onclick={() => deleteAiProvider(provider)}>Supprimer</button>
              </div>
            </article>
          {:else}
            <p class="ai-provider-empty">Aucun fournisseur IA n’est configuré — les agents IA resteront inactifs tant qu’aucun n’est ajouté.</p>
          {/each}
        </div>
        <form class="ai-provider-form" onsubmit={(event) => { event.preventDefault(); addAiProvider(); }}>
          <input type="text" placeholder="Nom (ex. OpenAI, Ollama local)" bind:value={newAiProviderLabel} required />
          <input type="text" placeholder="Adresse (ex. https://api.openai.com/v1 ou http://localhost:11434/v1)" bind:value={newAiProviderBaseUrl} required />
          <input type="text" placeholder="Modèle (ex. gpt-4o-mini, llama3.1)" bind:value={newAiProviderModel} required />
          <input type="password" placeholder="Clé API (laisser vide pour un modèle local)" bind:value={newAiProviderApiKey} />
          <button type="submit" disabled={isManagingAiProvider}>{isManagingAiProvider ? "Ajout…" : "+ Ajouter"}</button>
        </form>
        {#if aiProvidersError}<p class="settings-inline-error" role="alert">{aiProvidersError}</p>{/if}
      </section>

      <details class="settings-section settings-advanced">
        <summary><div><h3>Outils avancés</h3><p>Import JSON de diagnostic et vérification directe du backend Rust.</p></div><span>Développer</span></summary>
        <div class="settings-advanced-content">
          <article>
            <div><h4>Import manuel d’un export Ghidra</h4><p>Réservé au débogage ou à la reprise d’un export JSON existant. Le projet sera ouvert en mode snapshot.</p></div>
            <form class="settings-import-form" onsubmit={(event) => { event.preventDefault(); importGhidraExport(); }}>
              <div class="path-picker"><input id="export-path" type="text" bind:value={exportPath} placeholder="Aucun export JSON sélectionné" readonly /><button type="button" class="secondary-button" onclick={selectGhidraExport}>Parcourir…</button></div>
              <button type="submit" disabled={isImporting}>{isImporting ? "Import…" : "Importer le JSON"}</button>
            </form>
          </article>
          <article>
            <div><h4>Connexion au backend</h4><p>Envoie une commande légère à la couche Rust pour vérifier que Tauri communique correctement.</p></div>
            <div class="settings-backend-check"><button type="button" class="secondary-button" onclick={checkBackendStatus}>Tester le backend Rust</button>{#if backendStatus}<span>{backendStatus}</span>{/if}</div>
          </article>
        </div>
      </details>

      {#if ghidraConfigError}
        <p class="error" role="alert">{ghidraConfigError}</p>
      {/if}

      {#if analyzeError}
        <p class="error" role="alert">{analyzeError}</p>
      {/if}

      {#if importError}<p class="error" role="alert">{importError}</p>{/if}
    </section>

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
        class="reports-workspace"
        class:view-hidden={activeWorkspaceView !== "reports"}
        aria-labelledby="reports-workspace-title"
      >
        <header class="reports-workspace-header">
          <div>
            <p class="detail-label">Documentation de l’analyse</p>
            <h2 id="reports-workspace-title">Rapports</h2>
            <p>Génère un document PDF autonome à partir des données actuellement sauvegardées.</p>
          </div>
          <span>Génération 100 % locale</span>
        </header>

        {#if pdfReportError}
          <p class="error" role="alert">{pdfReportError}</p>
        {/if}

        {#if isLoadingProgramOverview}
          <p>Préparation du contenu du rapport…</p>
        {:else if programOverviewError}
          <p class="error" role="alert">{programOverviewError}</p>
        {:else if programOverview}
          <div class="reports-main-grid">
            <article class="report-export-card">
              <div class="report-document-icon" aria-hidden="true"><span>PDF</span></div>
              <div class="report-export-copy">
                <p class="detail-label">Rapport d’analyse technique</p>
                <h3>{importedExport.program.name}</h3>
                <span>{importedExport.program.format} · {importedExport.program.architecture}</span>
                <code title={importedExport.program.sha256}>SHA-256 · {importedExport.program.sha256}</code>
                <p>Document paginé contenant les métadonnées essentielles du programme, ses dépendances et les éléments détectés par Ghidra.</p>
              </div>
              <button type="button" disabled={isExportingPdfReport} onclick={exportPdfReport}>
                {isExportingPdfReport ? "Génération du PDF…" : "Générer le rapport PDF"}
              </button>
            </article>

            <article class="report-status-card" class:success={pdfReportResult !== null}>
              {#if pdfReportResult}
                <div class="report-status-heading"><span>✓</span><div><p>Dernier rapport généré</p><strong>{pdfReportResult.page_count} page{pdfReportResult.page_count > 1 ? "s" : ""}</strong></div></div>
                <dl>
                  <div><dt>Fonctions incluses</dt><dd>{pdfReportResult.function_count_included}</dd></div>
                  <div><dt>Chaînes incluses</dt><dd>{pdfReportResult.string_count_included}</dd></div>
                  <div><dt>Types inclus</dt><dd>{pdfReportResult.type_count_included}</dd></div>
                </dl>
                <div class="report-saved-path"><span>Fichier enregistré</span><code>{pdfReportResult.path}</code></div>
              {:else}
                <div class="report-status-placeholder">
                  <span aria-hidden="true">▤</span>
                  <strong>Aucun rapport généré pendant cette session</strong>
                  <p>Choisis l’emplacement du fichier avec le bouton de génération. Le PDF ne sera envoyé vers aucun service externe.</p>
                </div>
              {/if}
            </article>
          </div>

          <section class="report-content-card">
            <header><div><p class="detail-label">Contenu réel du document</p><h3>Ce qui sera inclus</h3></div><span>Rapport volontairement borné pour rester lisible</span></header>
            <div class="report-content-grid">
              <article><span class="report-section-icon">◎</span><div><strong>Vue générale</strong><p>Format, architecture, SHA-256 et statistiques globales.</p></div><b>Complet</b></article>
              <article><span class="report-section-icon">⇄</span><div><strong>Dépendances et imports</strong><p>{programOverview.required_library_count} bibliothèque{programOverview.required_library_count > 1 ? "s" : ""} requise{programOverview.required_library_count > 1 ? "s" : ""} · {programOverview.external_function_count} imports.</p></div><b>Complet</b></article>
              <article><span class="report-section-icon">ƒ</span><div><strong>Fonctions et prototypes</strong><p>Adresse, paramètres, retour, appels et statut externe/thunk.</p></div><b>{Math.min(programOverview.function_count, 250)} / {programOverview.function_count}</b></article>
              <article><span class="report-section-icon">”</span><div><strong>Chaînes de caractères</strong><p>Adresse, valeur et nombre réel de références Ghidra.</p></div><b>{Math.min(programOverview.string_count, 150)} / {programOverview.string_count}</b></article>
              <article><span class="report-section-icon">◇</span><div><strong>Structures et types</strong><p>Taille, champs, usages et indicateurs opaque/anonyme.</p></div><b>{Math.min(programOverview.detected_type_count, 150)} / {programOverview.detected_type_count}</b></article>
              <article class="not-included"><span class="report-section-icon">⌁</span><div><strong>Pseudocode complet</strong><p>Le code décompilé reste consultable dans l’application mais n’est pas intégré à ce rapport synthétique.</p></div><b>Non inclus</b></article>
            </div>
          </section>

          <section class="report-highlights">
            <article><span>Fonctions</span><strong>{programOverview.function_count.toLocaleString()}</strong><small>{programOverview.internal_function_count} internes · {programOverview.external_function_count} externes</small></article>
            <article><span>Sites d’appel</span><strong>{programOverview.call_site_count.toLocaleString()}</strong><small>{programOverview.most_used_function ? `${programOverview.most_used_function.name} est la plus appelée` : "Aucune fonction dominante"}</small></article>
            <article><span>Références de chaînes</span><strong>{programOverview.total_string_reference_count.toLocaleString()}</strong><small>{programOverview.string_count} chaînes distinctes</small></article>
            <article><span>Types détectés</span><strong>{programOverview.detected_type_count.toLocaleString()}</strong><small>{programOverview.struct_count} structures · {programOverview.enum_count} enums</small></article>
          </section>
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
        class="data-workspace strings-workspace"
        class:view-hidden={activeWorkspaceView !== "strings"}
        aria-labelledby="global-strings-title"
      >
        <header class="data-workspace-header">
          <div><p class="detail-label">Analyse globale</p><h2 id="global-strings-title">Chaînes de caractères</h2><span>Texte détecté dans le programme et fonctions qui le référencent.</span></div>
          <dl>
            <div><dt>Chaînes</dt><dd>{globalStrings?.length ?? 0}</dd></div>
            <div><dt>Références</dt><dd>{programOverview?.total_string_reference_count ?? 0}</dd></div>
            <div><dt>Plus référencée</dt><dd>{programOverview?.most_referenced_string?.reference_count ?? 0}</dd></div>
          </dl>
        </header>

        <div class="data-toolbar">
          <input
            type="search"
            placeholder="Rechercher dans le contenu d'une chaîne…"
            bind:value={globalStringsSearch}
            oninput={() => (globalStringsPage = 1)}
          />
          <span>{filteredGlobalStrings.length} résultat(s)</span>
        </div>

        {#if isLoadingGlobalStrings}
          <p>Loading strings...</p>
        {:else if globalStringsError}
          <p class="error" role="alert">{globalStringsError}</p>
        {:else if globalStrings}
          {#if filteredGlobalStrings.length === 0}
            <p class="data-empty">Aucune chaîne ne correspond à cette recherche.</p>
          {:else}
            <div class="data-table-card">
              <table class="strings-table">
                <thead><tr><th>Adresse</th><th>Contenu</th><th>Références</th><th>Fonctions</th></tr></thead>
                <tbody>
                  {#each paginatedGlobalStrings as entry (entry.address)}
                    <tr>
                      <td><code>{entry.address}</code></td>
                      <td><span title={entry.value}>{entry.value}</span></td>
                      <td><strong>{entry.reference_count}</strong></td>
                      <td>
                        <div class="data-function-chips">
                          {#each entry.referencing_functions.slice(0, 3) as fn (fn.entry_address)}
                            <button type="button" onclick={() => openFunction(fn.entry_address)}>{fn.name}</button>
                          {/each}
                          {#if entry.referencing_functions.length > 3}<em>+{entry.referencing_functions.length - 3}</em>{/if}
                          {#if entry.referencing_functions.length === 0}<span>Non attribuée</span>{/if}
                        </div>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
              <nav class="data-pagination" aria-label="Pages des chaînes">
                <button type="button" disabled={currentGlobalStringsPage === 1} onclick={() => (globalStringsPage = Math.max(1, currentGlobalStringsPage - 1))}>← Précédente</button>
                <span>Page {currentGlobalStringsPage} sur {globalStringsPageCount}</span>
                <button type="button" disabled={currentGlobalStringsPage === globalStringsPageCount} onclick={() => (globalStringsPage = Math.min(globalStringsPageCount, currentGlobalStringsPage + 1))}>Suivante →</button>
              </nav>
            </div>
          {/if}
        {/if}
      </section>
    {/if}

    {#if importedExport}
      <section
        class="data-workspace io-workspace"
        class:view-hidden={activeWorkspaceView !== "imports"}
        aria-labelledby="imports-title"
      >
        <header class="data-workspace-header">
          <div><p class="detail-label">Frontières du programme</p><h2 id="imports-title">Imports, exports et bibliothèques</h2><span>Fonctions externes utilisées, points d'entrée exposés et dépendances déclarées.</span></div>
          <dl>
            <div><dt>Imports</dt><dd>{imports?.length ?? 0}</dd></div>
            <div><dt>Exports</dt><dd>{externalEntryPoints?.length ?? 0}</dd></div>
            <div><dt>Bibliothèques</dt><dd>{importedExport.program.required_libraries.length}</dd></div>
          </dl>
        </header>

        <nav class="data-subtabs" aria-label="Sections des imports et exports">
          <button type="button" class:active={ioWorkspaceTab === "imports"} onclick={() => (ioWorkspaceTab = "imports")}>Imports <span>{imports?.length ?? 0}</span></button>
          <button type="button" class:active={ioWorkspaceTab === "exports"} onclick={() => (ioWorkspaceTab = "exports")}>Exports <span>{externalEntryPoints?.length ?? 0}</span></button>
          <button type="button" class:active={ioWorkspaceTab === "libraries"} onclick={() => (ioWorkspaceTab = "libraries")}>Bibliothèques <span>{importedExport.program.required_libraries.length}</span></button>
        </nav>

        {#if ioWorkspaceTab === "imports"}
          <div class="data-toolbar"><input type="search" placeholder="Rechercher un import ou une bibliothèque…" bind:value={importsSearch} oninput={() => (importsPage = 1)} /><span>{filteredImports.length} résultat(s)</span></div>
          {#if isLoadingImports}<p>Chargement des imports…</p>{:else if importsError}<p class="error" role="alert">{importsError}</p>{:else if filteredImports.length === 0}<p class="data-empty">Aucun import ne correspond à cette recherche.</p>{:else}
            <div class="data-table-card">
              <table class="io-table"><thead><tr><th>Adresse</th><th>Fonction</th><th>Bibliothèque</th><th>Utilisée par</th><th></th></tr></thead><tbody>
                {#each paginatedImports as entry (entry.entry_address)}<tr><td><code>{entry.entry_address}</code></td><td><strong>{entry.name}</strong></td><td>{entry.library ?? "Non attribuée"}</td><td><span>{entry.used_by_function_count} fonction(s)</span></td><td><button type="button" onclick={() => openFunction(entry.entry_address)}>Ouvrir</button></td></tr>{/each}
              </tbody></table>
              <nav class="data-pagination"><button type="button" disabled={currentImportsPage === 1} onclick={() => (importsPage = Math.max(1, currentImportsPage - 1))}>← Précédente</button><span>Page {currentImportsPage} sur {importsPageCount}</span><button type="button" disabled={currentImportsPage === importsPageCount} onclick={() => (importsPage = Math.min(importsPageCount, currentImportsPage + 1))}>Suivante →</button></nav>
            </div>
          {/if}
        {:else if ioWorkspaceTab === "exports"}
          <div class="data-toolbar">
            <input type="search" placeholder="Rechercher un point d'entrée…" bind:value={externalEntryPointsSearch} oninput={() => (externalEntryPointsPage = 1)} />
            <label><input type="checkbox" bind:checked={externalEntryPointsFunctionsOnly} onchange={() => (externalEntryPointsPage = 1)} /> Fonctions uniquement</label>
          </div>
          {#if isLoadingExternalEntryPoints}<p>Chargement des exports…</p>{:else if externalEntryPointsError}<p class="error" role="alert">{externalEntryPointsError}</p>{:else if filteredExternalEntryPoints.length === 0}<p class="data-empty">Aucun point d'entrée ne correspond.</p>{:else}
            <div class="data-table-card">
              <table class="io-table exports-table"><thead><tr><th>Adresse</th><th>Nom</th><th>Type</th><th></th></tr></thead><tbody>
                {#each paginatedExternalEntryPoints as entry (entry.address)}<tr><td><code>{entry.address}</code></td><td><strong>{entry.name ?? "(anonyme)"}</strong></td><td><span class="data-kind-badge">{entry.kind === "function" ? "Fonction" : entry.kind === "data" ? "Donnée" : "Inconnu"}</span></td><td>{#if entry.kind === "function"}<button type="button" onclick={() => openFunction(entry.address)}>Ouvrir</button>{/if}</td></tr>{/each}
              </tbody></table>
              <nav class="data-pagination"><button type="button" disabled={currentExternalEntryPointsPage === 1} onclick={() => (externalEntryPointsPage = Math.max(1, currentExternalEntryPointsPage - 1))}>← Précédente</button><span>Page {currentExternalEntryPointsPage} sur {externalEntryPointsPageCount}</span><button type="button" disabled={currentExternalEntryPointsPage === externalEntryPointsPageCount} onclick={() => (externalEntryPointsPage = Math.min(externalEntryPointsPageCount, currentExternalEntryPointsPage + 1))}>Suivante →</button></nav>
            </div>
          {/if}
        {:else}
          <div class="libraries-grid">
            {#if importedExport.program.required_libraries.length === 0}<p class="data-empty">Aucune bibliothèque requise n'est déclarée dans ce binaire.</p>{:else}
              {#each importedExport.program.required_libraries as library (library)}
                <article><span aria-hidden="true">◇</span><div><strong>{library}</strong><small>{imports?.filter((entry) => entry.library?.toLowerCase() === library.toLowerCase()).length ?? 0} import(s) attribué(s) directement</small></div></article>
              {/each}
            {/if}
          </div>
        {/if}
      </section>
    {/if}

    {#if importedExport}
      <section
        class="data-workspace types-workspace"
        class:view-hidden={activeWorkspaceView !== "types"}
        aria-labelledby="detected-types-title"
      >
        <header class="data-workspace-header">
          <div><p class="detail-label">Modèle de données</p><h2 id="detected-types-title">Structures et types détectés</h2><span>Types réellement utilisés par les signatures ou les données globales.</span></div>
          <dl>
            <div><dt>Structures</dt><dd>{programOverview?.struct_count ?? 0}</dd></div>
            <div><dt>Enums</dt><dd>{programOverview?.enum_count ?? 0}</dd></div>
            <div><dt>Opaques</dt><dd>{programOverview?.opaque_type_count ?? 0}</dd></div>
          </dl>
        </header>

        <div class="data-toolbar">
          <input type="search" placeholder="Rechercher un type…" bind:value={detectedTypesSearch} oninput={() => { detectedTypesPage = 1; expandedDetectedTypeKey = null; }} />
          <select bind:value={detectedTypesKindFilter} onchange={() => { detectedTypesPage = 1; expandedDetectedTypeKey = null; }}>
            <option value="all">Tous les types</option><option value="struct">Structures</option><option value="union">Unions</option><option value="enum">Enums</option><option value="typedef">Typedefs</option>
          </select>
          <span>{filteredDetectedTypes.length} résultat(s)</span>
        </div>

        {#if isLoadingDetectedTypes}
          <p>Loading detected types...</p>
        {:else if detectedTypesError}
          <p class="error" role="alert">{detectedTypesError}</p>
        {:else if detectedTypes}
          {#if filteredDetectedTypes.length === 0}
            <p class="data-empty">Aucun type ne correspond à ces filtres.</p>
          {:else}
            <div class="types-layout">
              <aside class="types-list-card">
                <ul>
                  {#each paginatedDetectedTypes as type (`${type.category}|${type.name}`)}
                    {@const typeKey = `${type.category}|${type.name}`}
                    <li><button type="button" class:active={selectedDetectedType === type} onclick={() => (expandedDetectedTypeKey = typeKey)}><span><small>{type.kind}</small><strong>{type.name}</strong></span><span><b>{formatTypeSize(type.size)}</b><em>{type.usages.length} usage(s)</em></span></button></li>
                  {/each}
                </ul>
                <nav class="data-pagination compact"><button type="button" disabled={currentDetectedTypesPage === 1} onclick={() => { detectedTypesPage = Math.max(1, currentDetectedTypesPage - 1); expandedDetectedTypeKey = null; }}>←</button><span>{currentDetectedTypesPage} / {detectedTypesPageCount}</span><button type="button" disabled={currentDetectedTypesPage === detectedTypesPageCount} onclick={() => { detectedTypesPage = Math.min(detectedTypesPageCount, currentDetectedTypesPage + 1); expandedDetectedTypeKey = null; }}>→</button></nav>
              </aside>

              {#if selectedDetectedType}
                <article class="type-detail-card">
                  <header><div><span class="data-kind-badge">{selectedDetectedType.kind}</span><h3>{selectedDetectedType.name}</h3><code>{selectedDetectedType.category}</code></div><dl><div><dt>Taille</dt><dd>{formatTypeSize(selectedDetectedType.size)}</dd></div><div><dt>Champs</dt><dd>{selectedDetectedType.fields.length}</dd></div><div><dt>Usages</dt><dd>{selectedDetectedType.usages.length}</dd></div></dl></header>
                  <div class="type-detail-grid">
                    <section><h4>Définition</h4>
                      {#if selectedDetectedType.kind === "typedef"}<p>Alias de <code>{selectedDetectedType.target_type_name}</code></p>
                      {:else if selectedDetectedType.kind === "enum"}<table><thead><tr><th>Nom</th><th>Valeur</th></tr></thead><tbody>{#each selectedDetectedType.enum_values as value (value.name)}<tr><td><code>{value.name}</code></td><td>{value.value}</td></tr>{/each}</tbody></table>
                      {:else if selectedDetectedType.fields.length > 0}<table><thead><tr><th>Offset</th><th>Champ</th><th>Type</th></tr></thead><tbody>{#each selectedDetectedType.fields as field (`${field.offset}-${field.name}`)}<tr><td>+{field.offset}</td><td><code>{field.name ?? "(anonyme)"}</code></td><td>{field.data_type}</td></tr>{/each}</tbody></table>
                      {:else}<p>{selectedDetectedType.is_opaque ? "Type opaque : sa définition interne n'est pas disponible." : "Aucun champ connu."}</p>{/if}
                    </section>
                    <section><h4>Utilisé dans</h4>
                      {#if selectedDetectedType.usages.length === 0}<p>Aucun usage direct : type inclus par dépendance.</p>{:else}<ul class="type-usage-list">{#each selectedDetectedType.usages.slice(0, 20) as usage, index (index)}<li>{#if usage.kind === "global_data"}<span>Donnée globale</span><code>{usage.data_label ?? usage.data_address}</code>{:else}<span>{usage.kind === "function_parameter" ? `Paramètre ${usage.parameter_name ?? ""}` : "Type de retour"}</span><button type="button" onclick={() => openFunction(usage.function_address)}>{usage.function_name}</button>{/if}</li>{/each}</ul>{/if}
                    </section>
                  </div>
                </article>
              {/if}
            </div>
          {/if}
        {/if}
      </section>
    {/if}

    {#if importedExport}
      <section
        class="identification-workspace"
        class:view-hidden={activeWorkspaceView !== "identification"}
        aria-labelledby="identification-title"
      >
        <header class="identification-header">
          <div>
            <p class="detail-label">Fonction principale</p>
            <h2 id="identification-title">Identifier et renommer les fonctions</h2>
            <p>Examine les preuves, choisis un nom, puis avance dans la file sans quitter cet écran.</p>
          </div>
          <dl>
            <div><dt>Non nommées</dt><dd>{unidentifiedFunctions.length}</dd></div>
            <div><dt>Avec FunctionID</dt><dd>{unidentifiedFunctions.filter((func) => (identifications.get(func.entry_address)?.length ?? 0) > 0).length}</dd></div>
            <div><dt>Avec BSim</dt><dd>{unidentifiedFunctions.filter((func) => (backgroundBsimResults.get(func.entry_address)?.matches.length ?? 0) > 0).length}</dd></div>
            <div><dt>Ignorées</dt><dd>{ignoredIdentificationAddresses.size}</dd></div>
          </dl>
        </header>

        <section class="identification-mode-switch">
          <div>
            <strong>{automaticIdentificationMode ? "Choix automatique activé" : "Validation manuelle activée"}</strong>
            <span>{automaticIdentificationMode ? "L'application retient la meilleure preuve disponible et prépare le lot." : "Tu examines et confirmes chaque fonction une par une."}</span>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={automaticIdentificationMode}
            class:active={automaticIdentificationMode}
            onclick={() => {
              automaticIdentificationMode = !automaticIdentificationMode;
              automaticIdentificationPage = 1;
              if (!automaticIdentificationMode) selectIdentificationEvidenceFirst();
            }}
          ><span></span><b>Choix automatique</b></button>
        </section>

        {#if automaticIdentificationMode}
          <section class="automatic-rename-panel">
            <div>
              <strong>{automaticRenameCandidates.length} proposition(s) nettoyée(s) peuvent être appliquées</strong>
              <span>
                {automaticAmbiguousChoiceCount} choix ambigu(s) clairement signalé(s)
                {#if automaticRenameGenerationCandidates.length > 0}
                  (dont {automaticRenameGenerationCandidates.length} inventé(s) par IA, voir plus bas)
                {/if} ·
                {automaticRenameWithoutEvidenceCount} fonction(s) sans preuve exploitable.
              </span>
            </div>
            <button
              type="button"
              disabled={isApplyingAutomaticRenames || automaticRenameCandidates.length === 0 || analysisSource !== "automatic" || !activeProjectId}
              onclick={applyAutomaticFunctionRenames}
            >{isApplyingAutomaticRenames ? "Application en cours…" : `Appliquer les propositions (${Math.min(automaticRenameCandidates.length, 500)})`}</button>
          </section>
          {#if automaticRenameError}<p class="error identification-message" role="alert">{automaticRenameError}</p>{/if}
          {#if automaticRenameSuccess}<p class="status identification-message">{automaticRenameSuccess}</p>{/if}

          {#if automaticRenameCandidatesWithEvidence.length > 0}
          <section class="automatic-choice-preview">
            <header>
              <div><h3>Choix préparés</h3><span>Chaque ligne conserve la preuve utilisée avant l'écriture dans Ghidra.</span></div>
              <small>Page {currentAutomaticIdentificationPage} sur {automaticIdentificationPageCount}</small>
            </header>
            {#if paginatedAutomaticRenameCandidates.length > 0}
              <table>
                <thead><tr><th>Fonction actuelle</th><th>Nom choisi</th><th>Preuve</th><th>Autres choix</th></tr></thead>
                <tbody>
                  {#each paginatedAutomaticRenameCandidates as item (item.func.entry_address)}
                    <tr>
                      <td><strong>{item.func.name}</strong><code>{item.func.entry_address}</code></td>
                      <td>{item.name}</td>
                      <td><span>{identificationSourceLabel(item.source)} · {item.scoreLabel}</span><small>{item.evidenceLabel}</small><small class="automatic-decision-reason">✓ {item.decisionLabel}</small></td>
                      <td>{item.alternativeCount === 0 ? "Aucun" : `${item.alternativeCount} moins bien classé(s)`}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {:else}
              <div class="no-automatic-choice"><strong>Aucun nom automatique disponible</strong><span>Repasse en validation manuelle pour examiner le pseudocode des fonctions restantes.</span></div>
            {/if}
            <nav class="identification-pagination" aria-label="Pages des choix automatiques">
              <button type="button" disabled={currentAutomaticIdentificationPage === 1} onclick={() => (automaticIdentificationPage = Math.max(1, currentAutomaticIdentificationPage - 1))}>←</button>
              <span>{currentAutomaticIdentificationPage} / {automaticIdentificationPageCount}</span>
              <button type="button" disabled={currentAutomaticIdentificationPage === automaticIdentificationPageCount} onclick={() => (automaticIdentificationPage = Math.min(automaticIdentificationPageCount, currentAutomaticIdentificationPage + 1))}>→</button>
            </nav>
          </section>
          {/if}

          {#if automaticRenameGenerationCandidates.length > 0}
          <section class="automatic-choice-preview generation-choice-preview">
            <header>
              <div>
                <h3>Propositions par IA générative</h3>
                <span>Aucune preuve FunctionID/BSim pour ces fonctions — l'agent a inventé un nom à partir du pseudocode, des appelants/appelés et des chaînes. Ce sont des propositions, pas des faits vérifiés : relis le raisonnement avant de leur faire confiance.</span>
              </div>
            </header>
            <div class="generation-choice-list">
              {#each automaticRenameGenerationCandidates as item (item.func.entry_address)}
                <article class="generation-choice-item">
                  <div><strong>{item.func.name}</strong><code>{item.func.entry_address}</code></div>
                  <div class="generation-choice-name">→ <b>{item.name}</b></div>
                  <p class="generation-choice-reasoning">{item.evidenceLabel}</p>
                </article>
              {/each}
            </div>
          </section>
          {/if}

          {#if automaticRenameRejections.length > 0}
            <details class="automatic-rejections" open>
              <summary>
                <span><strong>{automaticRenameRejections.length} proposition(s) à vérifier manuellement</strong><small>Score insuffisant, ambiguïté ou nom nécessitant une validation</small></span>
                <b>Voir les raisons</b>
              </summary>
              <div class="automatic-rejection-list">
                {#each automaticRenameRejections as item (item.func.entry_address)}
                  <article>
                    <div><strong>{item.func.name}</strong><code>{item.func.entry_address}</code></div>
                    <div><span>{item.candidateDisplayName}</span>{#if item.candidateName && item.candidateDisplayName !== item.candidateName}<code title="Nom brut FunctionID">{item.candidateName}</code>{/if}</div>
                    <div><small>{identificationSourceLabel(item.source)} · {item.evidenceLabel}</small><b>{item.reason}</b></div>
                    <button type="button" onclick={() => reviewIdentificationFunction(item.func.entry_address)}>Vérifier manuellement</button>
                  </article>
                {/each}
              </div>
            </details>
          {/if}
        {:else if remainingIdentificationFunctions.length === 0}
          <div class="identification-complete">
            <span aria-hidden="true">✓</span>
            <h3>La file est terminée</h3>
            <p>Toutes les fonctions génériques ont été renommées ou ignorées pour cette session.</p>
          </div>
        {:else}
          <div class="identification-layout">
            <aside class="identification-queue">
              <header>
                <div><strong>File de renommage</strong><span>{remainingIdentificationFunctions.length} restante(s) · {identificationQueue.length} affichée(s)</span></div>
                <small>Page {currentIdentificationPage} sur {identificationPageCount}</small>
              </header>
              {#if arbitrationTiedTotal > 0}
                <p class="arbitration-queue-status">
                  {#if isBackgroundArbitrating}
                    Arbitrage IA en arrière-plan : {arbitrationTiedResolved} / {arbitrationTiedTotal} traité(e)s…
                  {:else if arbitrationTiedResolved < arbitrationTiedTotal}
                    {arbitrationTiedTotal - arbitrationTiedResolved} fonction(s) ambiguë(s) en attente d'arbitrage IA.
                  {:else}
                    Arbitrage IA terminé : {arbitrationTiedTotal} fonction(s) traitée(s).
                  {/if}
                </p>
              {/if}
              {#if generationTotal > 0}
                <p class="arbitration-queue-status generation-queue-status">
                  {#if isBackgroundGenerating}
                    Génération IA en arrière-plan : {generationResolved} / {generationTotal} traitée(s)…
                  {:else if generationResolved < generationTotal}
                    {generationTotal - generationResolved} fonction(s) sans preuve en attente de suggestion IA.
                  {:else}
                    Génération IA terminée : {generationTotal} fonction(s) traitée(s).
                  {/if}
                </p>
              {/if}
              <div class="identification-queue-tools">
                <div role="group" aria-label="Filtrer la file de renommage">
                  <button type="button" class:active={identificationQueueFilter === "matched"} onclick={() => { identificationQueueFilter = "matched"; identificationPage = 1; }}>Avec proposition <b>{matchedIdentificationCount}</b></button>
                  <button type="button" class:active={identificationQueueFilter === "unmatched"} onclick={() => { identificationQueueFilter = "unmatched"; identificationPage = 1; }}>Sans correspondance <b>{unmatchedIdentificationCount}</b></button>
                  <button type="button" class:active={identificationQueueFilter === "all"} onclick={() => { identificationQueueFilter = "all"; identificationPage = 1; }}>Toutes <b>{remainingIdentificationFunctions.length}</b></button>
                </div>
                <input type="search" placeholder="Nom, adresse ou proposition…" bind:value={identificationQueueSearch} oninput={() => (identificationPage = 1)} />
              </div>
              <ol>
                {#each paginatedIdentificationQueue as func (func.entry_address)}
                  {@const candidate = topIdentificationFor(func.entry_address)}
                  {@const topBsimCandidate = bsimMatchesForAddress(func.entry_address)[0]}
                  {@const evidenceCandidates = uniqueFidCandidates(identifications.get(func.entry_address) ?? [])}
                  {@const topEvidenceScore = evidenceCandidates[0]?.overall_score}
                  {@const tiedEvidenceCount = topEvidenceScore === undefined ? 0 : evidenceCandidates.filter((item) => Math.abs(item.overall_score - topEvidenceScore) < 0.0001).length}
                  {@const automaticChoice = automaticRenameCandidates.find((choice) => choice.func.entry_address === func.entry_address)}
                  <li>
                    <button
                      type="button"
                      class:active={func.entry_address === selectedFunctionAddress}
                      onclick={() => openFunction(func.entry_address, false)}
                    >
                      <span><strong>{func.name}</strong><code>{func.entry_address}</code></span>
                      {#if tiedEvidenceCount > 1}
                        <span class="queue-candidate ambiguous"><small>{tiedEvidenceCount} noms ex æquo</small><b>{automaticChoice?.name ?? "Choix manuel requis"}</b></span>
                      {:else if candidate}
                        <span class="queue-candidate"><small>Proposition nettoyée</small><b>{automaticChoice?.name ?? normalizedAutomaticSymbolName(candidate.name) ?? candidate.name}</b></span>
                      {:else if topBsimCandidate}
                        <span class="queue-candidate"><small>BSim · {topBsimCandidate.similarity.toFixed(3)}</small><b>{automaticChoice?.name ?? normalizedAutomaticSymbolName(topBsimCandidate.name) ?? topBsimCandidate.name}</b></span>
                      {:else}
                        <span class="queue-no-evidence">Sans correspondance</span>
                      {/if}
                    </button>
                  </li>
                {/each}
              </ol>
              {#if identificationQueue.length === 0}
                <p class="identification-queue-empty">Aucune fonction ne correspond à ce filtre.</p>
              {/if}
              <nav class="identification-pagination" aria-label="Pages de la file de renommage">
                <button type="button" disabled={currentIdentificationPage === 1} onclick={() => (identificationPage = Math.max(1, currentIdentificationPage - 1))}>←</button>
                <span>{currentIdentificationPage} / {identificationPageCount}</span>
                <button type="button" disabled={currentIdentificationPage === identificationPageCount} onclick={() => (identificationPage = Math.min(identificationPageCount, currentIdentificationPage + 1))}>→</button>
              </nav>
            </aside>

            {#if selectedFunction && isGeneratedFunctionName(selectedFunction.name)}
              <article class="identification-review">
                <header>
                  <div><p class="detail-label">Fonction à identifier</p><h3>{selectedFunction.name}</h3><code>{selectedFunction.entry_address}</code></div>
                  <span class="review-position">{unidentifiedFunctions.length} fonction(s) encore non nommée(s)</span>
                </header>

                <div class="identification-review-grid">
                  <section class="identification-evidence">
                    <div class="review-section-heading"><h4>Propositions et preuves</h4><span>Clique sur une proposition pour la choisir</span></div>

                    {#if selectedFunction.rtti_class_names.length > 0}
                      {@const rttiSuggestedName = normalizedAutomaticSymbolName(selectedFunction.rtti_class_names[0]) ?? selectedFunction.rtti_class_names[0]}
                      <div class="evidence-source-group rtti-evidence-group">
                        <h5>RTTI (confirmé par le binaire)</h5>
                        {#if selectedFunction.rtti_class_names.length === 1}
                          <button type="button" class:selected={functionRenameDraft === rttiSuggestedName} onclick={() => selectFunctionRenameSuggestion(rttiSuggestedName)}>
                            <span><strong>{selectedFunction.rtti_class_names[0]}</strong><small>Classe réelle confirmée par les métadonnées RTTI du binaire (vtable → TypeDescriptor)</small></span>
                          </button>
                        {:else}
                          <p class="rtti-shared-note">
                            Cette fonction est réellement partagée par {selectedFunction.rtti_class_names.length} classes — le compilateur/l'éditeur de liens a fusionné leurs destructeurs, identiques au niveau machine. Confirmé par les métadonnées RTTI du binaire, ce n'est pas une ambiguïté à résoudre — choisis celle qui te semble la plus pertinente pour ce renommage :
                          </p>
                          {#each selectedFunction.rtti_class_names as className}
                            {@const rttiClassSuggestedName = normalizedAutomaticSymbolName(className) ?? className}
                            <button type="button" class:selected={functionRenameDraft === rttiClassSuggestedName} onclick={() => selectFunctionRenameSuggestion(rttiClassSuggestedName)}>
                              <span><strong>{className}</strong><small>Une des {selectedFunction.rtti_class_names.length} classes réelles confirmées pour cette fonction partagée</small></span>
                            </button>
                          {/each}
                        {/if}
                      </div>
                    {/if}

                    {#if selectedTiedCandidates.length > 1}
                      {@const currentResult = arbitrationResults.get(selectedFunction.entry_address)}
                      {@const currentError = arbitrationErrors.get(selectedFunction.entry_address)}
                      {@const isRunning = arbitratingAddresses.has(selectedFunction.entry_address)}
                      {@const tiedFromBsim = selectedTiedCandidates[0]?.source_label.startsWith("BSim")}
                      <div class="evidence-source-group arbitration-evidence-group">
                        <h5>Agent d'arbitrage IA
                          <span>
                            {selectedTiedCandidates.length} noms ex æquo ({tiedFromBsim ? "BSim" : "FunctionID"} reconnaît la forme, mais ne peut pas choisir le nom exact) — un agent IA tranche à partir du contexte réel (appelants, appelés, chaînes).
                          </span>
                        </h5>
                        <div class="arbitration-panel">
                          {#if isRunning}
                            <p class="arbitration-status">L'agent d'arbitrage réfléchit…</p>
                          {:else if currentResult}
                            {@const chosenName = currentResult.chosen_name}
                            {@const chosenDisplayName = chosenName ? displayCandidateName(chosenName) : null}
                            {@const chosenSafeName = chosenName ? (normalizedAutomaticSymbolName(chosenName) ?? chosenName) : null}
                            <div class="arbitration-result">
                              {#if chosenDisplayName && chosenSafeName}
                                <strong>Choix de l'agent : {chosenDisplayName}</strong>
                                <button type="button" class="link-button" onclick={() => selectFunctionRenameSuggestion(chosenSafeName)}>Utiliser ce nom ({chosenSafeName})</button>
                              {:else}
                                <strong>L'agent reste incertain</strong>
                              {/if}
                              <p>{currentResult.reasoning}</p>
                              <small>Fournisseur : {currentResult.provider_label}</small>
                            </div>
                          {:else if currentError}
                            <p class="settings-inline-error" role="alert">{currentError}</p>
                            <button type="button" class="secondary-button" onclick={requestArbitration}>Réessayer</button>
                          {:else if aiProviders.some((provider) => provider.enabled)}
                            <p class="arbitration-status">En attente de son tour dans la file d'arbitrage automatique…</p>
                          {:else}
                            <p class="arbitration-status">Aucun fournisseur IA activé — configure-le dans Réglages pour que l'arbitrage se fasse automatiquement, ou lance-le manuellement.</p>
                            <button type="button" class="secondary-button" onclick={requestArbitration}>Demander à l'agent d'arbitrage</button>
                          {/if}
                        </div>
                      </div>
                    {/if}

                    {#if selectedIdentificationCandidates.length > 0}
                      <div class="evidence-source-group">
                        <h5>FunctionID
                          {#if selectedIdentificationTopTieCount > 1}
                            <span>
                              {selectedIdentificationTopTieCount} noms ex æquo : FunctionID reconnaît la forme, mais ne peut pas choisir le nom exact.
                              {#if selectedFunction.rtti_class_names.length > 0}
                                RTTI a déjà donné la vraie réponse ci-dessus — cette égalité n'a plus besoin d'être résolue.
                              {/if}
                            </span>
                          {/if}
                        </h5>
                        <details
                          class="fid-raw-candidates"
                          open={!(selectedIdentificationTopTieCount > 1 && !!arbitrationResults.get(selectedFunction.entry_address)?.chosen_name)}
                        >
                          <summary>
                            {selectedIdentificationTopTieCount > 1 && arbitrationResults.get(selectedFunction.entry_address)?.chosen_name
                              ? `Voir les ${selectedIdentificationCandidates.length} candidats FunctionID bruts`
                              : `${selectedIdentificationCandidates.length} candidat(s) FunctionID`}
                          </summary>
                          {#each selectedIdentificationCandidates as candidate}
                          {@const displayedName = displayCandidateName(candidate.name)}
                          {@const automaticChoice = automaticRenameCandidates.find((choice) => choice.func.entry_address === selectedFunction.entry_address && choice.source === "function_id")}
                          {@const proposedName = automaticChoice && candidate.name === selectedIdentificationCandidates[0]?.name ? automaticChoice.name : (normalizedAutomaticSymbolName(candidate.name) ?? candidate.name)}
                          {@const corroborated = isCorroboratedByRtti(candidate.name, knownRealClassNames)}
                          <button type="button" class:selected={functionRenameDraft === proposedName} onclick={() => selectFunctionRenameSuggestion(proposedName)}>
                            <span>
                              <strong>{displayedName}</strong>
                              {#if corroborated}<span class="rtti-corroboration-badge">confirmé par RTTI ailleurs</span>{/if}
                              <small>Nom propre proposé : {proposedName}</small>
                              <small>{candidate.library_family} {candidate.library_version} {candidate.library_variant}</small>
                            </span>
                            <span><code>score {candidate.overall_score.toFixed(1)}</code><small>{candidate.match_mode}</small></span>
                          </button>
                          {/each}
                        </details>
                      </div>
                    {/if}

                    {#if selectedBsimResult?.status === "available" && selectedBsimResult.matches.length > 0}
                      {@const mergedBsimCandidates = uniqueBsimCandidates(selectedBsimResult.matches)}
                      <div class="evidence-source-group">
                        <h5>BSim</h5>
                        {#each mergedBsimCandidates as candidate}
                          {@const automaticChoice = automaticRenameCandidates.find((choice) => choice.func.entry_address === selectedFunction.entry_address && choice.source === "bsim")}
                          {@const proposedName = automaticChoice && candidate.name === mergedBsimCandidates[0]?.name ? automaticChoice.name : (normalizedAutomaticSymbolName(candidate.name) ?? candidate.name)}
                          <button type="button" class:selected={functionRenameDraft === proposedName} onclick={() => selectFunctionRenameSuggestion(proposedName)}>
                            <span>
                              <strong>{candidate.name}</strong>
                              <small>Nom propre proposé : {proposedName}</small>
                              <small>
                                {candidate.corpus}
                                {#if candidate.matchingExecutables.length > 1}
                                  · confirmé par {candidate.matchingExecutables.length} bibliothèques ({candidate.matchingExecutables.join(", ")})
                                {:else}
                                  · {candidate.executable}
                                {/if}
                              </small>
                            </span>
                            <span><code>{candidate.similarity.toFixed(3)}</code><small>significativité {candidate.significance.toFixed(1)}</small></span>
                          </button>
                        {/each}
                      </div>
                    {/if}

                    {#if selectedIdentificationCandidates.length === 0 && (selectedBsimResult?.matches.length ?? 0) === 0}
                      {#if hasNoEvidenceAtAll(selectedFunction)}
                        {@const currentResult = generationResults.get(selectedFunction.entry_address)}
                        {@const currentError = generationErrors.get(selectedFunction.entry_address)}
                        {@const isRunning = generatingAddresses.has(selectedFunction.entry_address)}
                        <div class="evidence-source-group generation-evidence-group">
                          <h5>Suggestion IA (aucune preuve automatique)
                            <span>
                              FunctionID et BSim n'ont trouvé aucun candidat pour cette fonction — un agent IA propose un nom à partir du contexte réel (pseudocode, appelants, appelés, chaînes), sans aucune garantie : c'est une invention, pas une preuve, à valider toi-même avant d'appliquer.
                            </span>
                          </h5>
                          <div class="arbitration-panel generation-panel">
                            {#if isRunning}
                              <p class="arbitration-status">L'agent réfléchit…</p>
                            {:else if currentResult}
                              {@const suggestedName = currentResult.suggested_name}
                              {@const suggestedDisplayName = suggestedName ? displayCandidateName(suggestedName) : null}
                              {@const suggestedSafeName = suggestedName ? (normalizedAutomaticSymbolName(suggestedName) ?? suggestedName) : null}
                              <div class="arbitration-result">
                                {#if suggestedDisplayName && suggestedSafeName}
                                  <strong>Suggestion de l'agent : {suggestedDisplayName}</strong>
                                  <button type="button" class="link-button" onclick={() => selectFunctionRenameSuggestion(suggestedSafeName)}>Utiliser ce nom ({suggestedSafeName})</button>
                                {:else}
                                  <strong>L'agent n'a proposé aucun nom</strong>
                                {/if}
                                <p>{currentResult.reasoning}</p>
                                <small>Fournisseur : {currentResult.provider_label}</small>
                              </div>
                            {:else if currentError}
                              <p class="settings-inline-error" role="alert">{currentError}</p>
                              <button type="button" class="secondary-button" onclick={requestGeneration}>Réessayer</button>
                            {:else if aiProviders.some((provider) => provider.enabled)}
                              <p class="arbitration-status">En attente de son tour dans la file de génération automatique…</p>
                            {:else}
                              <p class="arbitration-status">Aucun fournisseur IA activé — configure-le dans Réglages pour que la suggestion se fasse automatiquement, ou lance-la manuellement.</p>
                              <button type="button" class="secondary-button" onclick={requestGeneration}>Demander une suggestion à l'agent</button>
                            {/if}
                          </div>
                        </div>
                      {:else}
                        <div class="no-identification-evidence"><strong>Aucune preuve automatique disponible</strong><span>Tu peux lire le pseudocode et saisir un nom manuellement, ou ignorer cette fonction.</span></div>
                      {/if}
                    {/if}
                  </section>

                  <section class="identification-code">
                    <div class="review-section-heading"><h4>Pseudocode de contrôle</h4><span>{selectedPrototype}</span></div>
                    {#if isDecompilingSelected}
                      <p>Ghidra décompile cette fonction…</p>
                    {:else if selectedDecompileError}
                      <p class="error" role="alert">{selectedDecompileError}</p>
                    {:else if selectedDecompiledCode}
                      <pre><code>{selectedDecompiledCode}</code></pre>
                    {:else}
                      <p>Aucun pseudocode disponible.</p>
                    {/if}
                  </section>
                </div>

                <footer class="identification-actions">
                  <div>
                    <label for="identification-name">Nom retenu</label>
                    <input id="identification-name" type="text" maxlength="512" bind:value={functionRenameDraft} />
                  </div>
                  <button type="button" class="ignore-action" onclick={ignoreIdentificationAndNext}>Ignorer pour l'instant</button>
                  <button
                    type="button"
                    class="apply-next-action"
                    disabled={isApplyingFunctionRename || functionRenameDraft.trim() === selectedFunction.name || analysisSource !== "automatic" || !activeProjectId}
                    onclick={applyIdentificationRenameAndNext}
                  >{isApplyingFunctionRename ? "Application…" : "Renommer et suivante →"}</button>
                </footer>
                {#if functionRenameError}<p class="error identification-message" role="alert">{functionRenameError}</p>{/if}
                {#if functionRenameSuccess}<p class="status identification-message">{functionRenameSuccess}</p>{/if}
              </article>
            {/if}
          </div>
        {/if}
      </section>
    {/if}

    {#if importedExport}
      <section
        class="code-browser"
        class:view-hidden={activeWorkspaceView !== "browser"}
        aria-labelledby="code-browser-title"
      >
        <header class="section-toolbar">
          <div>
            <p class="detail-label">Navigation, désassemblage et pseudocode</p>
            <h2 id="code-browser-title">Code Browser</h2>
          </div>
          <div class="code-browser-nav">
            <button
              type="button"
              title={programEntryPointAddress ? `Aller à ${programEntryPointAddress}` : "Point d'entrée non identifié"}
              onclick={() => openInBrowser(programEntryPointAddress)}
              disabled={!programEntryPointAddress}
            >
              ⌂ Origine
            </button>
            <button type="button" onclick={browserGoBack} disabled={browserHistoryIndex <= 0}>
              ← Précédent
            </button>
            <button
              type="button"
              onclick={browserGoForward}
              disabled={browserHistoryIndex >= browserHistory.length - 1}
            >
              Suivant →
            </button>
            <button
              type="button"
              class="secondary-button"
              onclick={() => (browserSymbolsCollapsed = !browserSymbolsCollapsed)}
            >
              {browserSymbolsCollapsed ? "» Symboles" : "« Masquer les symboles"}
            </button>
          </div>
        </header>

        <div class="code-browser-layout" class:symbols-collapsed={browserSymbolsCollapsed}>
          {#if !browserSymbolsCollapsed}
            <aside class="code-browser-symbols">
              <div class="code-browser-symbols-controls">
                <input type="search" placeholder="Rechercher…" bind:value={browserSearch} />
                <select bind:value={browserSymbolFilter}>
                  <option value="all">Tous</option>
                  <option value="internal">Internes</option>
                  <option value="external">Externes</option>
                  <option value="unnamed">Non identifiées</option>
                </select>
              </div>

              <ul class="code-browser-symbol-list">
                {#each paginatedBrowserFunctions as func (func.entry_address)}
                  <li>
                    <button
                      type="button"
                      class:active={func.entry_address === selectedFunctionAddress}
                      onclick={() => openInBrowser(func.entry_address)}
                    >
                      <span>{func.name}</span>
                      <code>{func.entry_address}</code>
                    </button>
                  </li>
                {/each}
              </ul>

              <div class="code-browser-pagination">
                <button
                  type="button"
                  disabled={currentBrowserPage <= 1}
                  onclick={() => (browserPage = currentBrowserPage - 1)}
                >‹</button>
                <span>Page {currentBrowserPage} / {browserPageCount} ({browserFunctions.length})</span>
                <button
                  type="button"
                  disabled={currentBrowserPage >= browserPageCount}
                  onclick={() => (browserPage = currentBrowserPage + 1)}
                >›</button>
              </div>
            </aside>
          {/if}

          <div class="code-browser-listing">
            <div class="code-browser-listing-heading">
              <p class="detail-label">
                Désassemblage{#if codeBrowserListingMode === "function" && selectedFunction} — {selectedFunction.name}{/if}
              </p>
              <div class="code-browser-listing-mode">
                <button
                  type="button"
                  class:active={codeBrowserListingMode === "function"}
                  onclick={() => (codeBrowserListingMode = "function")}
                >
                  Fonction sélectionnée
                </button>
                <button
                  type="button"
                  class:active={codeBrowserListingMode === "program"}
                  onclick={() => (codeBrowserListingMode = "program")}
                >
                  Programme entier
                </button>
              </div>
            </div>

            {#if codeBrowserListingMode === "function"}
              {#if !selectedFunction}
                <p>Sélectionne une fonction dans la liste.</p>
              {:else if selectedFunction.is_external}
                <p>Fonction externe — pas de désassemblage local disponible.</p>
              {:else if isDisassemblingSelected}
                <p>Désassemblage en cours…</p>
              {:else if selectedDisassemblyError}
                <p class="error" role="alert">{selectedDisassemblyError}</p>
              {:else if selectedDisassembly}
                <div class="code-browser-listing-scroll">
                  <table class="disasm-table">
                    <tbody>
                      {#each selectedDisassembly.instructions as instruction (instruction.address)}
                        {@const target = disasmTarget(instruction)}
                        <tr class={`flow-${instruction.flow_category}`}>
                          <td><code>{instruction.address}</code></td>
                          <td><code class="disasm-bytes">{instruction.bytes}</code></td>
                          <td class="disasm-mnemonic">{instruction.mnemonic}</td>
                          <td class="disasm-operands">
                            {#if target}
                              <button
                                type="button"
                                class="disasm-jump-target"
                                title={`Ouvrir ${target.name} (${target.address}) et afficher son pseudocode`}
                                onclick={() => openInBrowser(target.address)}
                              >
                                {target.name}
                              </button>
                            {:else}
                              {instruction.operands}
                            {/if}
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {:else}
                <p>Aucun désassemblage disponible pour cette fonction.</p>
              {/if}
            {:else}
              <div class="code-browser-pagination">
                <button
                  type="button"
                  disabled={currentProgramListingPage <= 1}
                  onclick={() => (programListingPage = currentProgramListingPage - 1)}
                >‹</button>
                <span>
                  Page {currentProgramListingPage} / {programListingPageCount}
                  ({programListingFunctions.length} fonctions internes)
                </span>
                <button
                  type="button"
                  disabled={currentProgramListingPage >= programListingPageCount}
                  onclick={() => (programListingPage = currentProgramListingPage + 1)}
                >›</button>
              </div>

              {#if isLoadingProgramListingPage}
                <p>Désassemblage de la page en cours…</p>
              {:else if programListingError}
                <p class="error" role="alert">{programListingError}</p>
              {:else if currentProgramListingInstructions}
                <div class="code-browser-listing-scroll">
                  <table class="disasm-table">
                    <tbody>
                      {#each currentProgramListingInstructions as instruction, index (instruction.function_address + instruction.address)}
                        {@const target = disasmTarget(instruction)}
                        {@const previous = currentProgramListingInstructions[index - 1]}
                        {#if !previous || previous.function_address !== instruction.function_address}
                          <tr class="disasm-function-header">
                            <td colspan="4">
                              <button
                                type="button"
                                onclick={() => openInBrowser(instruction.function_address)}
                              >
                                {instruction.function_name}
                              </button>
                              <code>{instruction.function_address}</code>
                            </td>
                          </tr>
                        {/if}
                        <tr class={`flow-${instruction.flow_category}`}>
                          <td><code>{instruction.address}</code></td>
                          <td><code class="disasm-bytes">{instruction.bytes}</code></td>
                          <td class="disasm-mnemonic">{instruction.mnemonic}</td>
                          <td class="disasm-operands">
                            {#if target}
                              <button
                                type="button"
                                class="disasm-jump-target"
                                title={`Ouvrir ${target.name} (${target.address}) et afficher son pseudocode`}
                                onclick={() => openInBrowser(target.address)}
                              >
                                {target.name}
                              </button>
                            {:else}
                              {instruction.operands}
                            {/if}
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {:else}
                <p>Aucun désassemblage disponible.</p>
              {/if}
            {/if}
          </div>

          <aside class="code-browser-decompiled">
            <p class="detail-label">Pseudocode</p>

            {#if !selectedFunction}
              <p>—</p>
            {:else if isDecompilingSelected}
              <p>Décompilation en cours…</p>
            {:else if selectedDecompileError}
              <p class="error" role="alert">{selectedDecompileError}</p>
            {:else if selectedDecompiledCode}
              <pre><code>{selectedDecompiledCode}</code></pre>
            {:else}
              <p>Aucun pseudocode disponible pour cette fonction.</p>
            {/if}
          </aside>
        </div>

        {#if selectedFunction}
          <div class="code-browser-bottom">
            <section>
              <h4>Appels sortants ({selectedFunction.calls.length})</h4>
              {#if selectedFunction.calls.length === 0}
                <p>Aucun appel sortant.</p>
              {:else}
                <ul class="code-browser-mini-list">
                  {#each selectedFunction.calls as call}
                    <li>
                      <span>{call.target_name}</span>
                      {#if call.target_address}
                        <button type="button" onclick={() => openInBrowser(call.target_address)}>
                          <code>{call.target_address}</code>
                        </button>
                      {:else}
                        <em>adresse non résolue</em>
                      {/if}
                    </li>
                  {/each}
                </ul>
              {/if}
            </section>

            <section>
              <h4>Chaînes référencées ({selectedFunction.strings.length})</h4>
              {#if selectedFunction.strings.length === 0}
                <p>Aucune chaîne référencée.</p>
              {:else}
                <ul class="code-browser-mini-list">
                  {#each selectedFunction.strings as referencedString}
                    <li><code>{referencedString}</code></li>
                  {/each}
                </ul>
              {/if}
            </section>

            {#if analysisSource === "automatic" && activeProjectId && !selectedFunction.is_external}
              <section class="code-browser-rename">
                <h4>Renommer</h4>
                <div>
                  <input type="text" maxlength="512" bind:value={functionRenameDraft} />
                  <button
                    type="button"
                    disabled={isApplyingFunctionRename || functionRenameDraft.trim() === selectedFunction.name}
                    onclick={applySelectedFunctionRename}
                  >
                    {isApplyingFunctionRename ? "Application…" : "Appliquer"}
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
          </div>
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
            <div class="graph-mode-toggle" aria-label="Mode d'affichage">
              <button type="button" class:active={graphViewMode === "2d"} onclick={() => (graphViewMode = "2d")}>2D</button>
              <button type="button" class:active={graphViewMode === "3d"} onclick={() => (graphViewMode = "3d")}>3D</button>
            </div>
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

        {#if callGraphResult}
          <div class="graph-summary-bar">
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
          </div>
        {/if}

        <div class="graph-layout">
          <aside class="graph-function-browser">
            <header><strong>Fonctions</strong><span>{filteredGraphFunctions.length}</span></header>
            <input type="search" placeholder="Nom ou adresse…" bind:value={graphFunctionSearch} oninput={() => (graphFunctionPage = 1)} />
            <ul>
              {#each paginatedGraphFunctions as func (func.entry_address)}
                <li>
                  <button
                    type="button"
                    class:root={func.entry_address === selectedFunctionAddress}
                    class:active={func.entry_address === graphInspectedFunction?.entry_address}
                    onclick={() => inspectGraphFunction(func.entry_address)}
                    ondblclick={() => navigateWithinGraph(func.entry_address)}
                    title="Clic : afficher les informations. Double-clic : recentrer le graphe."
                  >
                    <span class="graph-function-name">{func.name}</span>
                    <span class="graph-function-meta">
                      <code>{func.entry_address}</code>
                      <small>{func.is_external ? "Externe" : func.is_thunk ? "Thunk" : "Interne"}</small>
                      <small>{func.calls.length} appel{func.calls.length > 1 ? "s" : ""}</small>
                    </span>
                  </button>
                </li>
              {/each}
            </ul>
            <nav><button type="button" disabled={currentGraphFunctionPage === 1} onclick={() => (graphFunctionPage = Math.max(1, currentGraphFunctionPage - 1))}>←</button><span>{currentGraphFunctionPage} / {graphFunctionPageCount}</span><button type="button" disabled={currentGraphFunctionPage === graphFunctionPageCount} onclick={() => (graphFunctionPage = Math.min(graphFunctionPageCount, currentGraphFunctionPage + 1))}>→</button></nav>
          </aside>

          <div
            class="graph-stage-wrap"
            class:panning={graphPanDrag !== null}
            onpointerdown={handleGraphPanPointerDown}
            onpointermove={handleGraphPanPointerMove}
            onpointerup={handleGraphPanPointerUp}
            onpointercancel={handleGraphPanPointerUp}
            oncontextmenu={(event) => event.preventDefault()}
            onwheel={handleGraphStageWheel}
            role="region"
            aria-label="Zone interactive du graphe d'appels"
          >
            {#if isLoadingCallGraph}
              <p class="graph-message">Construction du graphe…</p>
            {:else if callGraphError}
              <p class="error" role="alert">{callGraphError}</p>
            {:else if callGraphResult}
              <div class="graph-interaction-toolbar">
                <span>Clic : informations · double-clic : recentrer · glisser un nœud : l'écarter · clic droit : déplacer la vue</span>
                <div>
                  {#if graphViewMode === "2d"}
                    <span class="graph-zoom-value">Zoom {Math.round(graph2dZoom * 100)} %</span>
                    <button type="button" onclick={resetGraph2dZoom}>Recentrer la vue</button>
                  {/if}
                  <button type="button" onclick={resetGraphNodePositions}>Réorganiser les nœuds</button>
                  {#if graphViewMode === "3d"}<button type="button" onclick={resetGraph3dView}>Réinitialiser la caméra</button>{/if}
                </div>
              </div>
              {#if graphViewMode === "2d"}
                <div class="graph-stage-2d-viewport" style={`width:${graphCanvasWidth * graph2dZoom}px;height:${callGraphLayout.height * graph2dZoom}px`}>
                  <div class="graph-stage graph-stage-2d-canvas" style={`width:${graphCanvasWidth}px;height:${callGraphLayout.height}px;transform:translate(${graph2dPanX}px, ${graph2dPanY}px) scale(${graph2dZoom})`}>
                    <svg class="graph-edges" viewBox={`0 0 ${graphCanvasWidth} ${callGraphLayout.height}`} aria-hidden="true">
                      <defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker></defs>
                      {#each callGraphResult.edges as edge (`${edge.from}-${edge.to}`)}
                        {@const from = graphNodePosition.get(edge.from)}
                        {@const to = graphNodePosition.get(edge.to)}
                        {#if from && to}<path d={`M ${from.x + graphNodeWidth / 2} ${from.y + graphNodeHeight} C ${from.x + graphNodeWidth / 2} ${from.y + graphNodeHeight + 45}, ${to.x + graphNodeWidth / 2} ${to.y - 45}, ${to.x + graphNodeWidth / 2} ${to.y}`} marker-end="url(#arrow)"></path>{/if}
                      {/each}
                    </svg>
                    {#each callGraphLayout.nodes as node (node.entry_address)}
                      <button
                        type="button"
                        class="visual-graph-node"
                        class:root={node.entry_address === selectedFunctionAddress}
                        class:inspected={node.entry_address === graphInspectedFunction?.entry_address}
                        class:dragging={graphNodeDrag?.address === node.entry_address}
                        class:external={node.is_external}
                        class:thunk={node.is_thunk}
                        style={`left:${node.x}px;top:${node.y}px;width:${graphNodeWidth}px;height:${graphNodeHeight}px`}
                        onpointerdown={(event) => handleGraphNodePointerDown(event, node.entry_address)}
                        onpointermove={handleGraphNodePointerMove}
                        onpointerup={handleGraphNodePointerUp}
                        onpointercancel={handleGraphNodePointerUp}
                        ondblclick={() => navigateWithinGraph(node.entry_address)}
                      ><strong>{node.name}</strong><code>{node.entry_address}</code></button>
                    {/each}
                  </div>
                </div>
              {:else}
                <div class="graph-3d-toolbar"><span>Glisse le fond pour tourner · molette pour zoomer</span></div>
                <div
                  class="graph-stage graph-stage-3d"
                  class:dragging={graph3dDrag !== null}
                  style={`width:${graphCanvasWidth}px;height:${graph3dHeight}px`}
                  onpointerdown={handleGraph3dPointerDown}
                  onpointermove={handleGraph3dPointerMove}
                  onpointerup={handleGraph3dPointerUp}
                  onpointercancel={handleGraph3dPointerUp}
                  onwheel={handleGraph3dWheel}
                  role="application"
                  aria-label="Graphe d'appels interactif en trois dimensions"
                >
                  <svg class="graph-edges graph-edges-3d" viewBox={`0 0 ${graphCanvasWidth} ${graph3dHeight}`} aria-hidden="true">
                    <defs><marker id="arrow-3d" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker></defs>
                    {#each graph3dLayout.edges as edge (`3d-${edge.from}-${edge.to}`)}
                      <path d={`M ${edge.fromNode.x} ${edge.fromNode.y} L ${edge.toNode.x} ${edge.toNode.y}`} marker-end="url(#arrow-3d)"></path>
                    {/each}
                  </svg>
                  {#each graph3dLayout.nodes as node (node.entry_address)}
                    <button
                      type="button"
                      class="visual-graph-node graph-node-3d"
                      class:root={node.entry_address === selectedFunctionAddress}
                      class:inspected={node.entry_address === graphInspectedFunction?.entry_address}
                      class:dragging={graphNodeDrag?.address === node.entry_address}
                      class:external={node.is_external}
                      class:thunk={node.is_thunk}
                      style={`left:${node.x - graph3dNodeWidth / 2}px;top:${node.y - graph3dNodeHeight / 2}px;width:${graph3dNodeWidth}px;height:${graph3dNodeHeight}px;transform:scale(${Math.max(0.68, Math.min(1.22, node.scale))});z-index:${Math.round(1000 - node.z)}`}
                      onpointerdown={(event) => handleGraphNodePointerDown(event, node.entry_address)}
                      onpointermove={handleGraphNodePointerMove}
                      onpointerup={handleGraphNodePointerUp}
                      onpointercancel={handleGraphNodePointerUp}
                      ondblclick={() => navigateWithinGraph(node.entry_address)}
                    ><strong>{node.name}</strong><code>{node.entry_address}</code></button>
                  {/each}
                </div>
              {/if}
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
            <h3>{graphInspectedFunction?.name ?? "Aucune fonction"}</h3>
            {#if graphInspectedFunction}
              <code>{graphInspectedFunction.entry_address}</code>
              <dl>
                <div><dt>Type</dt><dd>{graphInspectedFunction.is_external ? "Externe" : graphInspectedFunction.is_thunk ? "Thunk" : "Interne"}</dd></div>
                <div><dt>Appels</dt><dd>{graphInspectedFunction.calls.length}</dd></div>
                <div><dt>Chaînes</dt><dd>{graphInspectedFunction.strings.length}</dd></div>
                <div><dt>Paramètres</dt><dd>{graphInspectedFunction.parameters.length}</dd></div>
              </dl>
              {#if graphInspectedFunction.entry_address === selectedFunctionAddress && callGraphDirection === "outgoing" && callGraphResult?.edges.length === 0}
                <button type="button" class="graph-callers-button" onclick={() => (callGraphDirection = "incoming")}>Afficher les fonctions qui l'appellent</button>
              {/if}
              <button type="button" onclick={() => openFunction(graphInspectedFunction?.entry_address ?? null)}>Voir les détails</button>
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
          <input
            type="search"
            placeholder="Rechercher une fonction…"
            bind:value={functionSearch}
            oninput={() => (functionPage = 1)}
          />
        </header>

        {#if importedExport.functions.length === 0}
          <p>No functions were found in this export.</p>
        {:else}
          <div class="function-list-column">
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
                {#each paginatedFunctions as func (func.entry_address)}
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

            <nav class="function-pagination" aria-label="Pages de fonctions">
              <button
                type="button"
                disabled={currentFunctionPage === 1}
                onclick={() => (functionPage = Math.max(1, currentFunctionPage - 1))}
              >← Précédente</button>
              <span>Page {currentFunctionPage} sur {functionPageCount}</span>
              <button
                type="button"
                disabled={currentFunctionPage === functionPageCount}
                onclick={() => (functionPage = Math.min(functionPageCount, currentFunctionPage + 1))}
              >Suivante →</button>
            </nav>
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
              {#if selectedIdentificationCandidates.length === 0 && !selectedBsimResult}
                <p class="detail-label">Aucune preuve disponible pour cette fonction.</p>
              {/if}

              {#if selectedIdentificationCandidates.length > 0}
                <section class="function-section">
                  <h4>Possible match (FunctionID)</h4>

                  <ul>
                    {#each selectedIdentificationCandidates as candidate}
                      {@const displayedName = displayCandidateName(candidate.name)}
                      {@const automaticChoice = automaticRenameCandidates.find((choice) => choice.func.entry_address === selectedFunction?.entry_address && choice.source === "function_id")}
                      {@const proposedName = automaticChoice && candidate.name === selectedIdentificationCandidates[0]?.name ? automaticChoice.name : (normalizedAutomaticSymbolName(candidate.name) ?? candidate.name)}
                      {@const corroborated = isCorroboratedByRtti(candidate.name, knownRealClassNames)}
                      <li
                        class="rename-suggestion-item"
                        class:selected={functionRenameDraft === proposedName}
                      >
                        <button
                          type="button"
                          class="rename-suggestion"
                          title={`Use ${candidate.name} as the proposed Ghidra name`}
                          onclick={() => selectFunctionRenameSuggestion(proposedName)}
                        >
                          <span>
                            {displayedName}
                            {#if corroborated}<span class="rtti-corroboration-badge">confirmé par RTTI ailleurs</span>{/if}
                            <small>Nom propre proposé : {proposedName}</small>
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
                      {@const mergedBsimCandidates = uniqueBsimCandidates(selectedBsimResult.matches)}
                      <ul>
                        {#each mergedBsimCandidates as candidate}
                          {@const automaticChoice = automaticRenameCandidates.find((choice) => choice.func.entry_address === selectedFunction?.entry_address && choice.source === "bsim")}
                          {@const proposedName = automaticChoice && candidate.name === mergedBsimCandidates[0]?.name ? automaticChoice.name : candidate.name}
                          <li
                            class="rename-suggestion-item"
                            class:selected={functionRenameDraft === proposedName}
                          >
                            <button
                              type="button"
                              class="rename-suggestion"
                              title={`Use ${candidate.name} as the proposed Ghidra name`}
                              onclick={() => selectFunctionRenameSuggestion(proposedName)}
                            >
                              <span>
                                {candidate.name}
                                <em>
                                  {#if candidate.matchingExecutables.length > 1}
                                    ({candidate.corpus} · confirmed by {candidate.matchingExecutables.length} libraries: {candidate.matchingExecutables.join(", ")})
                                  {:else}
                                    ({candidate.corpus} · {candidate.executable})
                                  {/if}
                                </em>
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

  .global-strings-search {
    margin-bottom: 0.75rem;
  }

  .global-strings-count {
    flex-shrink: 0;
    color: #94a3b8;
    font-size: 0.8rem;
    white-space: nowrap;
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
    margin: 0;
    padding: 0;
    border: 0;
  }

  .reports-workspace { min-width: 0; }

  .reports-workspace-header {
    display: flex;
    align-items: end;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.8rem;
  }

  .reports-workspace-header h2 { margin: 0.1rem 0 0.2rem; font-size: 1.18rem; }
  .reports-workspace-header p:not(.detail-label) { margin: 0; color: #8191aa; font-size: 0.7rem; }
  .reports-workspace-header > span { padding: 0.32rem 0.55rem; border: 1px solid #245241; border-radius: 999px; background: #0d2a24; color: #6ee7b7; font-size: 0.58rem; white-space: nowrap; }

  .reports-main-grid { display: grid; grid-template-columns: minmax(0, 1.5fr) minmax(280px, 0.75fr); gap: 0.65rem; }
  .report-export-card,
  .report-status-card,
  .report-content-card,
  .report-highlights > article { border: 1px solid #24334b; border-radius: 10px; background: #0c1627; }

  .report-export-card { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 0.85rem; min-height: 150px; padding: 0.9rem; }
  .report-document-icon { display: grid; place-items: center; width: 72px; height: 92px; border: 1px solid #6d28d9; border-radius: 7px; background: linear-gradient(145deg, #33215f, #17162f); box-shadow: 0 12px 30px rgb(0 0 0 / 28%); }
  .report-document-icon span { color: #ddd6fe; font-size: 0.82rem; font-weight: 900; letter-spacing: 0.08em; }
  .report-export-copy { display: grid; min-width: 0; gap: 0.22rem; }
  .report-export-copy h3 { margin: 0; color: #f4f7fb; font-size: 1.02rem; }
  .report-export-copy > span { color: #82a6cb; font-size: 0.65rem; }
  .report-export-copy > code { overflow: hidden; color: #687d9b; font-size: 0.53rem; text-overflow: ellipsis; white-space: nowrap; }
  .report-export-copy > p:not(.detail-label) { max-width: 700px; margin: 0.3rem 0 0; color: #8494ad; font-size: 0.62rem; line-height: 1.45; }
  .report-export-card > button { padding: 0.62rem 0.85rem; background: #6d28d9; color: #fff; font-size: 0.68rem; white-space: nowrap; }

  .report-status-card { display: grid; align-content: center; min-height: 150px; padding: 0.85rem; }
  .report-status-card.success { border-color: #235743; background: linear-gradient(145deg, #0c201d, #0c1627); }
  .report-status-heading { display: flex; align-items: center; gap: 0.55rem; }
  .report-status-heading > span { display: grid; place-items: center; width: 30px; height: 30px; border-radius: 50%; background: #14532d; color: #86efac; font-weight: 900; }
  .report-status-heading p { margin: 0; color: #86a494; font-size: 0.57rem; }
  .report-status-heading strong { color: #ecfdf5; font-size: 0.82rem; }
  .report-status-card dl { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.35rem; margin: 0.65rem 0 0; }
  .report-status-card dl div { padding: 0.4rem; border-radius: 5px; background: rgb(8 18 30 / 60%); }
  .report-status-card dt { color: #70849e; font-size: 0.5rem; }
  .report-status-card dd { margin: 0.15rem 0 0; color: #dbeafe; font-size: 0.72rem; font-weight: 700; }
  .report-saved-path { display: grid; gap: 0.16rem; margin-top: 0.55rem; }
  .report-saved-path span { color: #6f819a; font-size: 0.5rem; }
  .report-saved-path code { overflow: hidden; color: #89a7c5; font-size: 0.51rem; text-overflow: ellipsis; white-space: nowrap; }
  .report-status-placeholder { display: grid; justify-items: center; text-align: center; }
  .report-status-placeholder > span { color: #8b5cf6; font-size: 1.5rem; }
  .report-status-placeholder strong { margin-top: 0.3rem; color: #dce5f2; font-size: 0.7rem; }
  .report-status-placeholder p { max-width: 310px; margin: 0.3rem 0 0; color: #71829d; font-size: 0.57rem; line-height: 1.4; }

  .report-content-card { margin-top: 0.65rem; overflow: hidden; }
  .report-content-card > header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.65rem 0.8rem; border-bottom: 1px solid #223149; }
  .report-content-card > header h3 { margin: 0.08rem 0 0; font-size: 0.82rem; }
  .report-content-card > header > span { color: #71829d; font-size: 0.56rem; }
  .report-content-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .report-content-grid article { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 0.6rem; min-height: 72px; padding: 0.65rem 0.75rem; border-right: 1px solid #1e2d43; border-bottom: 1px solid #1e2d43; }
  .report-content-grid article:nth-child(3n) { border-right: 0; }
  .report-content-grid article:nth-last-child(-n + 3) { border-bottom: 0; }
  .report-section-icon { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 6px; background: #211845; color: #c4b5fd; font-size: 0.72rem; }
  .report-content-grid article > div { display: grid; min-width: 0; gap: 0.15rem; }
  .report-content-grid strong { color: #dce6f4; font-size: 0.64rem; }
  .report-content-grid p { margin: 0; color: #71829c; font-size: 0.54rem; line-height: 1.35; }
  .report-content-grid b { color: #67e8f9; font-size: 0.57rem; white-space: nowrap; }
  .report-content-grid .not-included { background: rgb(46 17 28 / 25%); }
  .report-content-grid .not-included .report-section-icon { background: #351824; color: #fda4af; }
  .report-content-grid .not-included b { color: #fb7185; }

  .report-highlights { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.55rem; margin-top: 0.65rem; }
  .report-highlights > article { display: grid; gap: 0.12rem; padding: 0.65rem 0.75rem; }
  .report-highlights span { color: #8293ad; font-size: 0.56rem; }
  .report-highlights strong { color: #67e8f9; font-size: 1rem; }
  .report-highlights small { overflow: hidden; color: #657894; font-size: 0.53rem; text-overflow: ellipsis; white-space: nowrap; }

  @media (max-width: 1050px) {
    .reports-main-grid { grid-template-columns: 1fr; }
    .report-content-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .report-content-grid article:nth-child(3n) { border-right: 1px solid #1e2d43; }
    .report-content-grid article:nth-child(2n) { border-right: 0; }
    .report-content-grid article:nth-last-child(-n + 3) { border-bottom: 1px solid #1e2d43; }
    .report-content-grid article:nth-last-child(-n + 2) { border-bottom: 0; }
  }

  .comparison-workspace-header {
    display: flex;
    align-items: end;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.8rem;
  }

  .comparison-workspace-header h2 { margin: 0.1rem 0 0.2rem; font-size: 1.18rem; }
  .comparison-workspace-header p:not(.detail-label) { margin: 0; color: #8191aa; font-size: 0.7rem; }
  .comparison-workspace-header > span { padding: 0.32rem 0.55rem; border: 1px solid #245241; border-radius: 999px; background: #0d2a24; color: #6ee7b7; font-size: 0.58rem; white-space: nowrap; }

  .comparison-project-picker {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) auto;
    align-items: end;
    gap: 0.65rem;
    padding: 0.75rem;
    border: 1px solid #24334b;
    border-radius: 10px;
    background: #0c1627;
  }

  .comparison-project-picker label { display: grid; min-width: 0; gap: 0.35rem; }
  .comparison-project-picker label > span { color: #7e90ac; font-size: 0.57rem; font-weight: 700; letter-spacing: 0.08em; }
  .comparison-project-picker select { width: 100%; min-width: 0; padding: 0.58rem 0.65rem; border: 1px solid #32435f; border-radius: 7px; background: #0a1322; color: #e5edf8; font-size: 0.68rem; }
  .comparison-project-picker button { min-height: 35px; }
  .comparison-swap { width: 38px; padding: 0; border: 1px solid #4c3a83; background: #211845; color: #c4b5fd; font-size: 1rem; }
  .comparison-run { padding: 0.5rem 1rem; background: #6d28d9; color: #fff; font-size: 0.68rem; }

  .project-comparison-result { margin-top: 0.75rem; }
  .comparison-result-context { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 0.65rem; padding: 0 0.15rem; }
  .comparison-result-context span { color: #dce6f5; font-size: 0.72rem; }
  .comparison-result-context small { color: #7e90aa; font-size: 0.58rem; }

  .comparison-kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.55rem; margin: 0; }
  .comparison-kpis > div { display: grid; gap: 0.1rem; min-height: 82px; padding: 0.65rem 0.75rem; border: 1px solid #24334b; border-radius: 8px; background: #0f1b2e; }
  .comparison-kpis dt { color: #8fa0bb; font-size: 0.62rem; }
  .comparison-kpis dd { margin: 0; color: #dbeafe; font-size: 1.35rem; font-weight: 800; }
  .comparison-kpis span { color: #667894; font-size: 0.56rem; }
  .comparison-kpis .changed dd { color: #fbbf24; }
  .comparison-kpis .added dd { color: #4ade80; }
  .comparison-kpis .removed dd { color: #fb7185; }

  .comparison-browser { margin-top: 0.65rem; border: 1px solid #24334b; border-radius: 10px; background: #0a1424; overflow: hidden; }
  .comparison-tabs { display: flex; gap: 0.2rem; padding: 0.35rem 0.5rem 0; border-bottom: 1px solid #223149; }
  .comparison-tabs button { padding: 0.5rem 0.65rem; border-radius: 6px 6px 0 0; background: transparent; color: #8495b0; font-size: 0.65rem; }
  .comparison-tabs button.active { box-shadow: inset 0 -2px #8b5cf6; background: #171b38; color: #f3f0ff; }
  .comparison-tabs button span { margin-left: 0.25rem; padding: 0.08rem 0.3rem; border-radius: 999px; background: #202d43; font-size: 0.52rem; }

  .comparison-search-row { display: flex; align-items: center; gap: 0.7rem; padding: 0.55rem; }
  .comparison-search-row input { flex: 1; min-width: 0; padding: 0.5rem 0.62rem; border: 1px solid #2b3b56; border-radius: 6px; background: #091221; color: #e2e8f0; font-size: 0.66rem; }
  .comparison-search-row span { color: #71819a; font-size: 0.58rem; white-space: nowrap; }

  .comparison-table-header,
  .comparison-rows > li {
    display: grid;
    grid-template-columns: minmax(150px, 1.05fr) 0.55fr 0.55fr minmax(220px, 1.5fr);
    gap: 0.65rem;
    align-items: start;
  }

  .comparison-table-header { padding: 0.42rem 0.7rem; border-block: 1px solid #223149; background: #0d1829; color: #6f819e; font-size: 0.55rem; font-weight: 700; text-transform: uppercase; }
  .comparison-rows { display: grid; margin: 0; padding: 0; list-style: none; }
  .comparison-rows > li { min-height: 54px; padding: 0.58rem 0.7rem; border-bottom: 1px solid #1d2a3f; }
  .comparison-rows > li:hover { background: #101e32; }
  .comparison-rows > li.changed { box-shadow: inset 3px 0 #f59e0b; }
  .comparison-rows > li.added { box-shadow: inset 3px 0 #22c55e; }
  .comparison-rows > li.removed { box-shadow: inset 3px 0 #f43f5e; }
  .comparison-rows > li > div:first-child { display: grid; min-width: 0; gap: 0.15rem; }
  .comparison-rows strong { overflow: hidden; color: #e6edf7; font-size: 0.67rem; text-overflow: ellipsis; white-space: nowrap; }
  .comparison-rows small { color: #71829d; font-size: 0.55rem; }
  .comparison-rows > li > code { color: #86b8e8; font-size: 0.6rem; }

  .comparison-evidence { display: grid; min-width: 0; gap: 0.25rem; }
  .comparison-evidence > small { color: #a78bfa; }
  .comparison-evidence > span { display: grid; grid-template-columns: 90px minmax(0, 1fr) auto minmax(0, 1fr); align-items: center; gap: 0.3rem; }
  .comparison-evidence > span strong { color: #8ea0ba; font-size: 0.54rem; font-weight: 600; }
  .comparison-evidence > span code { overflow: hidden; padding: 0.12rem 0.25rem; border-radius: 3px; background: #121f32; color: #b9c8dc; font-size: 0.52rem; text-overflow: ellipsis; white-space: nowrap; }
  .comparison-evidence b { color: #667894; font-size: 0.55rem; }

  .comparison-no-result { display: grid; place-content: center; min-height: 220px; text-align: center; }
  .comparison-no-result strong { color: #dce5f3; font-size: 0.75rem; }
  .comparison-no-result span { margin-top: 0.3rem; color: #71829d; font-size: 0.62rem; }
  .comparison-pagination { display: flex; align-items: center; justify-content: center; gap: 0.75rem; padding: 0.5rem; border-top: 1px solid #223149; }
  .comparison-pagination button { padding: 0.32rem 0.55rem; border: 1px solid #354765; background: #111e31; color: #d6e0ee; font-size: 0.58rem; }
  .comparison-pagination button:disabled { opacity: 0.3; }
  .comparison-pagination span { color: #71819a; font-size: 0.57rem; }

  @media (max-width: 980px) {
    .comparison-project-picker { grid-template-columns: 1fr auto 1fr; }
    .comparison-run { grid-column: 1 / -1; }
    .comparison-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .comparison-table-header { display: none; }
    .comparison-rows > li { grid-template-columns: 1fr 1fr; }
    .comparison-evidence { grid-column: 1 / -1; }
  }

  .settings-workspace { display: grid; min-width: 0; gap: 0.65rem; }
  .settings-workspace-header { display: flex; align-items: end; justify-content: space-between; gap: 1rem; margin-bottom: 0.15rem; }
  .settings-workspace-header h2 { margin: 0.1rem 0 0.25rem; font-size: 1.45rem; }
  .settings-workspace-header p:not(.detail-label) { margin: 0; color: #8191aa; font-size: 0.84rem; }
  .settings-workspace-header > span { padding: 0.4rem 0.7rem; border: 1px solid #6b3a3a; border-radius: 999px; background: #2a151b; color: #fda4af; font-size: 0.7rem; white-space: nowrap; }
  .settings-workspace-header > span.ready { border-color: #245241; background: #0d2a24; color: #6ee7b7; }

  .settings-section { border: 1px solid #24334b; border-radius: 10px; background: #0c1627; overflow: hidden; }
  .settings-section > header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.82rem 0.95rem; border-bottom: 1px solid #223149; }
  .settings-section > header h3 { margin: 0; font-size: 0.94rem; }
  .settings-section > header p { margin: 0.18rem 0 0; color: #71829d; font-size: 0.7rem; }
  .settings-section > header > span { padding: 0.28rem 0.55rem; border-radius: 999px; background: #341923; color: #fda4af; font-size: 0.66rem; }
  .settings-section > header > span.ready { background: #123326; color: #86efac; }
  .settings-section > header button { padding: 0.45rem 0.7rem; font-size: 0.7rem; }

  .settings-components-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .settings-components-grid article { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 0.65rem; min-height: 118px; padding: 0.82rem 0.95rem; border-right: 1px solid #1e2d43; }
  .settings-components-grid article:last-child { border-right: 0; }
  .settings-component-indicator { width: 11px; height: 11px; border-radius: 50%; background: #ef4444; box-shadow: 0 0 9px rgb(239 68 68 / 45%); }
  .settings-components-grid article.ready .settings-component-indicator { background: #22c55e; box-shadow: 0 0 9px rgb(34 197 94 / 45%); }
  .settings-components-grid article.missing .settings-component-indicator { background: #f59e0b; box-shadow: 0 0 9px rgb(245 158 11 / 40%); }
  .settings-components-grid article > div { display: grid; min-width: 0; gap: 0.12rem; }
  .settings-components-grid strong { color: #e3eaf4; font-size: 0.82rem; }
  .settings-components-grid small { color: #7890ad; font-size: 0.66rem; }
  .settings-components-grid b { padding: 0.2rem 0.42rem; border-radius: 4px; background: #331923; color: #fda4af; font-size: 0.62rem; }
  .settings-components-grid article.ready b { background: #123326; color: #86efac; }
  .settings-components-grid article.missing b { background: #392710; color: #fcd34d; }
  .settings-components-grid p { grid-column: 2 / -1; margin: 0; color: #71819a; font-size: 0.66rem; line-height: 1.4; }
  .settings-components-grid code { grid-column: 2 / -1; overflow: hidden; color: #7796b5; font-size: 0.62rem; text-overflow: ellipsis; white-space: nowrap; }
  .settings-managed-root { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 0.8rem; padding: 0.58rem 0.95rem; border-top: 1px solid #223149; background: #0a1423; }
  .settings-managed-root span { color: #71829d; font-size: 0.66rem; }
  .settings-managed-root code { overflow: hidden; color: #86a5c5; font-size: 0.65rem; text-overflow: ellipsis; white-space: nowrap; }

  .ghidra-settings-card dl { display: grid; grid-template-columns: 0.45fr 1.2fr 1.2fr; margin: 0; }
  .ghidra-settings-card dl > div { min-width: 0; padding: 0.82rem 0.95rem; border-right: 1px solid #1e2d43; }
  .ghidra-settings-card dl > div:last-child { border-right: 0; }
  .ghidra-settings-card dt { color: #71829d; font-size: 0.66rem; }
  .ghidra-settings-card dd { min-width: 0; margin: 0.25rem 0 0; color: #e1e9f4; font-size: 0.8rem; }
  .ghidra-settings-card dd code { display: block; overflow: hidden; color: #83a9cd; font-size: 0.66rem; text-overflow: ellipsis; white-space: nowrap; }
  .settings-actions { display: flex; gap: 0.55rem; padding: 0.68rem 0.95rem; border-top: 1px solid #223149; }
  .settings-actions button { padding: 0.5rem 0.78rem; font-size: 0.72rem; }
  .settings-inline-error { margin: 0.82rem 0.95rem; color: #fda4af; font-size: 0.74rem; }

  .bsim-corpus-list { display: grid; }
  .bsim-header-actions { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 0.5rem; }
  .bsim-corpus-list article { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: start; gap: 0.85rem; padding: 0.9rem 0.95rem; border-bottom: 1px solid #1e2d43; }
  .bsim-corpus-list article:last-child { border-bottom: 0; }
  .bsim-corpus-list article.disabled { opacity: 0.68; }
  .bsim-corpus-list article.unavailable { background: rgb(127 29 29 / 8%); }
  .bsim-corpus-state { width: 11px; height: 11px; margin-top: 0.25rem; border-radius: 50%; background: #64748b; }
  .bsim-corpus-state.active { background: #22c55e; box-shadow: 0 0 9px rgb(34 197 94 / 45%); }
  .bsim-corpus-copy { display: grid; min-width: 0; gap: 0.35rem; }
  .bsim-corpus-heading { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  .bsim-corpus-heading strong { color: #e5edf8; font-size: 0.86rem; }
  .bsim-corpus-heading span { padding: 0.18rem 0.38rem; border-radius: 4px; background: #251653; color: #c4b5fd; font-size: 0.6rem; font-weight: 700; }
  .bsim-corpus-heading small { color: #71829d; font-size: 0.65rem; }
  .bsim-corpus-copy p { margin: 0; color: #8192ad; font-size: 0.72rem; line-height: 1.45; }
  .bsim-corpus-copy code { overflow: hidden; color: #7596b8; font-size: 0.64rem; text-overflow: ellipsis; white-space: nowrap; }
  .bsim-library-tags { display: flex; flex-wrap: wrap; gap: 0.35rem; }
  .bsim-library-tags span { padding: 0.22rem 0.45rem; border: 1px solid #304561; border-radius: 999px; background: #101e32; color: #a8c2df; font-size: 0.63rem; }
  .bsim-corpus-actions { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 0.4rem; max-width: 260px; }
  .bsim-corpus-actions b { padding: 0.25rem 0.45rem; border-radius: 4px; background: #312033; color: #fda4af; font-size: 0.62rem; }
  .bsim-corpus-actions b.ready { background: #123326; color: #86efac; }
  .bsim-corpus-actions button { padding: 0.4rem 0.58rem; font-size: 0.65rem; }
  .danger-button { border: 1px solid #7f3f4b; background: transparent; color: #fda4af; }
  .bsim-corpora-card > footer { padding: 0.65rem 0.95rem; border-top: 1px solid #223149; background: #0a1423; }
  .bsim-corpora-card > footer p,
  .bsim-corpus-empty { margin: 0; color: #71829d; font-size: 0.68rem; line-height: 1.45; }
  .bsim-corpus-empty { padding: 1rem; }

  .ai-provider-list { display: grid; }
  .ai-provider-list article { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: start; gap: 0.85rem; padding: 0.9rem 0.95rem; border-bottom: 1px solid #1e2d43; }
  .ai-provider-list article:last-child { border-bottom: 0; }
  .ai-provider-list article.disabled { opacity: 0.68; }
  .ai-provider-state { width: 11px; height: 11px; margin-top: 0.25rem; border-radius: 50%; background: #64748b; }
  .ai-provider-state.active { background: #22c55e; box-shadow: 0 0 9px rgb(34 197 94 / 45%); }
  .ai-provider-copy { display: grid; min-width: 0; gap: 0.35rem; }
  .ai-provider-heading { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  .ai-provider-heading strong { color: #e5edf8; font-size: 0.86rem; }
  .ai-provider-heading small { color: #71829d; font-size: 0.65rem; }
  .ai-provider-copy code { overflow: hidden; color: #7596b8; font-size: 0.64rem; text-overflow: ellipsis; white-space: nowrap; }
  .ai-provider-key-state { color: #8192ad; font-size: 0.7rem; }
  .ai-provider-actions { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 0.4rem; max-width: 260px; }
  .ai-provider-actions b { padding: 0.25rem 0.45rem; border-radius: 4px; background: #312033; color: #fda4af; font-size: 0.62rem; }
  .ai-provider-actions b.ready { background: #123326; color: #86efac; }
  .ai-provider-actions button { padding: 0.4rem 0.58rem; font-size: 0.65rem; }
  .ai-provider-empty { margin: 0; padding: 1rem; color: #71829d; font-size: 0.68rem; line-height: 1.45; }
  .ai-provider-form { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr auto; gap: 0.5rem; padding: 0.9rem 0.95rem; border-top: 1px solid #223149; background: #0a1423; }
  .ai-provider-form input { min-width: 0; padding: 0.5rem 0.6rem; border: 1px solid #223149; border-radius: 6px; background: #0f1c30; color: #e5edf8; font-size: 0.72rem; }

  .settings-advanced > summary { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.82rem 0.95rem; cursor: pointer; list-style: none; }
  .settings-advanced > summary::-webkit-details-marker { display: none; }
  .settings-advanced > summary h3 { margin: 0; font-size: 0.92rem; }
  .settings-advanced > summary p { margin: 0.18rem 0 0; color: #71829d; font-size: 0.69rem; }
  .settings-advanced > summary > span { color: #a78bfa; font-size: 0.7rem; }
  .settings-advanced[open] > summary { border-bottom: 1px solid #223149; }
  .settings-advanced[open] > summary > span { font-size: 0; }
  .settings-advanced[open] > summary > span::after { font-size: 0.7rem; content: "Réduire"; }
  .settings-advanced-content { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .settings-advanced-content > article { display: grid; align-content: start; gap: 0.75rem; min-width: 0; padding: 0.95rem; border-right: 1px solid #1e2d43; }
  .settings-advanced-content > article:last-child { border-right: 0; }
  .settings-advanced-content h4 { margin: 0; font-size: 0.82rem; }
  .settings-advanced-content p { margin: 0.22rem 0 0; color: #71829d; font-size: 0.68rem; line-height: 1.45; }
  .settings-import-form { display: grid; gap: 0.45rem; }
  .settings-import-form input { padding: 0.62rem 0.72rem; font-size: 0.7rem; }
  .settings-import-form button,
  .settings-backend-check button { padding: 0.52rem 0.72rem; font-size: 0.7rem; }
  .settings-import-form > button { justify-self: start; }
  .settings-backend-check { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  .settings-backend-check span { color: #86efac; font-size: 0.7rem; }

  @media (max-width: 980px) {
    .settings-components-grid { grid-template-columns: 1fr; }
    .settings-components-grid article { border-right: 0; border-bottom: 1px solid #1e2d43; }
    .settings-components-grid article:last-child { border-bottom: 0; }
    .ghidra-settings-card dl,
    .settings-advanced-content { grid-template-columns: 1fr; }
    .ghidra-settings-card dl > div,
    .settings-advanced-content > article { border-right: 0; border-bottom: 1px solid #1e2d43; }
    .bsim-corpus-list article { grid-template-columns: auto minmax(0, 1fr); }
    .bsim-corpus-actions { grid-column: 2; justify-content: flex-start; max-width: none; }
    .ai-provider-list article { grid-template-columns: auto minmax(0, 1fr); }
    .ai-provider-actions { grid-column: 2; justify-content: flex-start; max-width: none; }
    .ai-provider-form { grid-template-columns: 1fr; }
  }

  @media (min-width: 981px) and (max-width: 1400px) {
    .settings-components-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .settings-components-grid article:nth-child(2n) { border-right: 0; }
    .settings-components-grid article:nth-child(-n + 2) { border-bottom: 1px solid #1e2d43; }
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
    scrollbar-width: none;
  }

  .workspace-scroll::-webkit-scrollbar { display: none; }

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
  .settings-workspace,
  .summary,
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

  .code-browser {
    min-width: 0;
  }

  .code-browser-nav {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .code-browser-nav button {
    padding: 0.45rem 0.7rem;
    font-size: 0.75rem;
  }

  .code-browser-layout {
    display: grid;
    grid-template-columns: 220px minmax(0, 1fr) minmax(0, 1fr);
    /* Ghidra's own CodeBrowser gives the Listing and Decompile panes the
       bulk of the window, with only a narrow tree sidebar -- this mirrors
       that proportion (roughly equal Listing/Decompile, thin sidebar)
       rather than the earlier 260px/1.6fr/1fr split, without literally
       cloning Ghidra's multi-panel docking (Program Trees, Data Type
       Manager, ...), which we don't need. */
    height: calc(100vh - 220px);
    margin-top: 0.6rem;
    border: 1px solid #1e2c42;
    border-radius: 10px;
    background: #080f1c;
    overflow: hidden;
  }

  .code-browser-layout.symbols-collapsed {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }

  .code-browser-symbols {
    display: grid;
    grid-template-rows: auto minmax(0, 1fr) auto;
    min-width: 0;
    min-height: 0;
    padding: 0.7rem;
    border-right: 1px solid #1e2c42;
    background: #0b1423;
  }

  .code-browser-symbols-controls {
    display: grid;
    gap: 0.4rem;
    margin-bottom: 0.5rem;
  }

  .code-browser-symbols-controls input,
  .code-browser-symbols-controls select {
    padding: 0.45rem 0.6rem;
    font-size: 0.72rem;
  }

  .code-browser-symbol-list {
    display: grid;
    margin: 0;
    padding: 0;
    gap: 0.15rem;
    overflow-y: auto;
    list-style: none;
    align-content: start;
  }

  .code-browser-symbol-list button {
    display: flex;
    width: 100%;
    min-width: 0;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
    padding: 0.42rem 0.55rem;
    border: 1px solid transparent;
    border-radius: 5px;
    background: #0e192a;
    color: #d7e0ef;
    font-size: 0.72rem;
    text-align: left;
  }

  .code-browser-symbol-list button:hover:not(.active) {
    border-color: #263349;
  }

  .code-browser-symbol-list button.active {
    border-color: #6d28d9;
    background: #24184c;
    box-shadow: inset 3px 0 #8b5cf6;
  }

  .code-browser-symbol-list button span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .code-browser-symbol-list code {
    flex-shrink: 0;
    color: #93c5fd;
    font-size: 0.64rem;
  }

  .code-browser-pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    margin-top: 0.5rem;
    padding-top: 0.5rem;
    border-top: 1px solid #1e2c42;
    color: #71819c;
    font-size: 0.68rem;
  }

  .code-browser-pagination button {
    padding: 0.3rem 0.55rem;
    font-size: 0.72rem;
  }

  .code-browser-listing {
    display: grid;
    grid-template-rows: auto auto minmax(0, 1fr);
    min-width: 0;
    min-height: 0;
    padding: 0.7rem;
    border-right: 1px solid #1e2c42;
  }

  .code-browser-listing-heading {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .code-browser-listing-mode {
    display: flex;
    gap: 0.2rem;
  }

  .code-browser-listing-mode button {
    padding: 0.3rem 0.55rem;
    border: 0;
    border-radius: 5px;
    background: transparent;
    color: #8292ad;
    font-size: 0.66rem;
    font-weight: 600;
  }

  .code-browser-listing-mode button:hover:not(.active),
  .code-browser-listing-mode button.active {
    background: rgb(124 58 237 / 12%);
    color: #e9e3ff;
  }

  .code-browser-listing-scroll {
    min-width: 0;
    overflow: auto;
  }

  .disasm-function-header td {
    padding-top: 0.5rem;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid #263349;
    background: #0e192a;
  }

  .disasm-function-header button {
    padding: 0;
    background: transparent;
    color: #a78bfa;
    font-family: Consolas, "Courier New", monospace;
    font-size: 0.78rem;
    font-weight: 700;
  }

  .disasm-function-header code {
    margin-left: 0.5rem;
    color: #6c7793;
    font-size: 0.66rem;
  }

  .disasm-table {
    width: 100%;
    border-collapse: collapse;
    font-family: Consolas, "Courier New", monospace;
    font-size: 0.72rem;
  }

  .disasm-table td {
    padding: 0.14rem 0.55rem;
    border-bottom: 1px solid #131c2c;
    white-space: nowrap;
  }

  .disasm-table tr:hover td {
    background: #101d30;
  }

  .disasm-table td:first-child code {
    color: #6c7793;
  }

  .disasm-bytes {
    color: #4c5872;
    letter-spacing: 0.04em;
  }

  .disasm-mnemonic {
    color: #93c5fd;
    font-weight: 700;
  }

  .disasm-operands {
    color: #d7e0ef;
    white-space: normal;
    overflow-wrap: anywhere;
  }

  .disasm-table tr.flow-unconditional_call td.disasm-mnemonic,
  .disasm-table tr.flow-conditional_call td.disasm-mnemonic {
    color: #a78bfa;
  }

  .disasm-table tr.flow-unconditional_jump td.disasm-mnemonic,
  .disasm-table tr.flow-conditional_jump td.disasm-mnemonic {
    color: #fbbf24;
  }

  .disasm-table tr.flow-terminator td.disasm-mnemonic {
    color: #f87171;
  }

  .disasm-jump-target {
    padding: 0;
    background: transparent;
    border: 0;
    color: #c4b5fd;
    font-family: Consolas, "Courier New", monospace;
    font-size: 0.72rem;
    font-weight: 700;
    text-decoration: underline;
    text-decoration-color: rgb(196 181 253 / 45%);
    white-space: nowrap;
  }

  .disasm-jump-target:hover {
    color: #e9e3ff;
    text-decoration-color: currentColor;
  }

  .code-browser-decompiled {
    display: grid;
    grid-template-rows: auto minmax(0, 1fr);
    min-width: 0;
    min-height: 0;
    padding: 0.7rem;
    background: #0b1423;
  }

  .code-browser-decompiled pre {
    margin: 0;
    padding: 0.75rem;
    border: 1px solid #1d2a40;
    border-radius: 6px;
    background: #020617;
    overflow: auto;
  }

  .code-browser-decompiled pre code {
    color: #d1fae5;
    font-family: Consolas, "Courier New", monospace;
    font-size: 0.78rem;
    line-height: 1.5;
    white-space: pre;
  }

  .code-browser-bottom {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.7rem;
    margin-top: 0.7rem;
  }

  .code-browser-bottom > section {
    min-width: 0;
    padding: 0.7rem;
    border: 1px solid #1d2a40;
    border-radius: 8px;
    background: #0b1423;
  }

  .code-browser-bottom h4 {
    margin: 0 0 0.5rem;
    color: #a78bfa;
    font-size: 0.78rem;
  }

  .code-browser-mini-list {
    display: grid;
    max-height: 180px;
    margin: 0;
    padding: 0;
    gap: 0.3rem;
    overflow-y: auto;
    list-style: none;
  }

  .code-browser-mini-list li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.5rem;
    border: 1px solid #1d2a40;
    border-radius: 5px;
    background: #101d30;
    font-size: 0.72rem;
    overflow-wrap: anywhere;
  }

  .code-browser-mini-list li button {
    padding: 0;
    background: transparent;
    color: #93c5fd;
  }

  .code-browser-rename > div {
    display: flex;
    gap: 0.5rem;
  }

  .code-browser-rename input {
    min-width: 0;
    flex: 1 1 auto;
    padding: 0.45rem 0.6rem;
    border: 1px solid #475569;
    border-radius: 0.4rem;
    background-color: #0f172a;
    color: #f8fafc;
    font-size: 0.75rem;
  }

  @media (max-width: 1180px) {
    .code-browser-layout {
      grid-template-columns: 1fr;
      height: auto;
      min-height: 0;
    }

    .code-browser-symbols,
    .code-browser-listing {
      border-right: 0;
      border-bottom: 1px solid #1e2c42;
    }

    .code-browser-symbol-list {
      max-height: 260px;
    }

    .code-browser-bottom {
      grid-template-columns: 1fr;
    }
  }

  .graph-workspace {
    min-width: 0;
  }

  .graph-layout {
    display: grid;
    grid-template-columns: 280px minmax(0, 1fr) 230px;
    min-height: 610px;
    margin-top: 0.4rem;
    border: 1px solid #1e2c42;
    border-radius: 10px;
    background: #080f1c;
    overflow: hidden;
  }

  .graph-function-browser {
    display: grid;
    grid-template-rows: auto auto 1fr auto;
    min-width: 0;
    border-right: 1px solid #1e2c42;
    background: #0d1727;
  }

  .graph-function-browser > header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.7rem;
    border-bottom: 1px solid #1e2c42;
  }

  .graph-function-browser > header strong { font-size: 0.78rem; }
  .graph-function-browser > header span { color: #71819a; font-size: 0.64rem; }
  .graph-function-browser > input { width: calc(100% - 1.2rem); min-width: 0; margin: 0.6rem; padding: 0.52rem 0.62rem; box-sizing: border-box; font-size: 0.68rem; }
  .graph-function-browser ul { display: grid; align-content: start; margin: 0; padding: 0; list-style: none; }
  .graph-function-browser li { border-top: 1px solid #18263a; }
  .graph-function-browser li > button { display: grid; width: 100%; gap: 0.26rem; padding: 0.58rem 0.72rem; border-radius: 0; background: transparent; color: #dbe5f2; text-align: left; }
  .graph-function-browser li > button:hover:not(:disabled) { background: #13243a; }
  .graph-function-browser li > button.root { box-shadow: inset 3px 0 #8b5cf6; }
  .graph-function-browser li > button.active { background: #172d4b; outline: 1px solid rgb(34 211 238 / 28%); outline-offset: -1px; }
  .graph-function-name { overflow: hidden; font-size: 0.72rem; font-weight: 700; text-overflow: ellipsis; white-space: nowrap; }
  .graph-function-meta { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; align-items: center; gap: 0.45rem; color: #7486a2; }
  .graph-function-meta code { overflow: hidden; color: #7db2e8; font-size: 0.58rem; text-overflow: ellipsis; }
  .graph-function-meta small { padding: 0.12rem 0.28rem; border-radius: 4px; background: #111e31; font-size: 0.52rem; white-space: nowrap; }
  .graph-function-browser > nav { display: flex; align-items: center; justify-content: center; gap: 0.6rem; padding: 0.5rem; border-top: 1px solid #1e2c42; }
  .graph-function-browser > nav button { padding: 0.25rem 0.5rem; border: 1px solid #354765; background: #111e31; color: #d6e0ee; }
  .graph-function-browser > nav button:disabled { cursor: default; opacity: 0.3; }
  .graph-function-browser > nav span { color: #71819a; font-size: 0.56rem; }

  .graph-stage-wrap {
    position: relative;
    min-width: 0;
    padding: 0.75rem;
    overflow: hidden;
    background-image: radial-gradient(#27364e 0.7px, transparent 0.7px);
    background-size: 18px 18px;
  }

  .graph-stage-wrap.panning { cursor: grabbing; user-select: none; }

  .graph-summary-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    min-height: 34px;
    margin-top: 0.55rem;
    padding: 0.42rem 0.7rem;
    border: 1px solid #1e2c42;
    border-radius: 8px;
    background: #0d1727;
  }

  .graph-summary-bar .call-graph-stats { margin: 0; white-space: nowrap; }

  .graph-interaction-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    min-width: 720px;
    margin-top: 0.38rem;
    color: #7587a3;
    font-size: 0.58rem;
  }

  .graph-interaction-toolbar > div { display: flex; gap: 0.35rem; }
  .graph-zoom-value { align-self: center; min-width: 64px; color: #a9b7cc; text-align: center; }
  .graph-interaction-toolbar button { padding: 0.28rem 0.48rem; border: 1px solid #4c3a83; background: #211845; color: #ddd6fe; font-size: 0.55rem; white-space: nowrap; }

  .graph-mode-toggle {
    display: flex;
    padding: 2px;
    border: 1px solid #334155;
    border-radius: 6px;
    background: #0b1423;
  }

  .graph-mode-toggle button { padding: 0.3rem 0.5rem; border-radius: 4px; background: transparent; color: #8292ad; font-size: 0.62rem; }
  .graph-mode-toggle button:hover:not(:disabled) { background: #17243a; }
  .graph-mode-toggle button.active { background: #6d28d9; color: #fff; }

  .graph-stage {
    position: relative;
    min-width: 100%;
    margin-top: 0.5rem;
  }

  .graph-stage-2d-viewport {
    position: relative;
    min-width: 1px;
    margin-top: 0.5rem;
  }

  .graph-stage-2d-canvas {
    min-width: 0;
    margin-top: 0;
    transform-origin: left top;
  }

  .graph-3d-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 0.5rem;
    color: #71819a;
    font-size: 0.58rem;
  }

  .graph-stage-3d {
    overflow: hidden;
    border: 1px solid #1f3049;
    border-radius: 8px;
    background: radial-gradient(circle at center, rgb(34 48 75 / 42%), rgb(5 11 20 / 82%) 68%);
    cursor: grab;
    touch-action: none;
    user-select: none;
  }

  .graph-stage-3d.dragging { cursor: grabbing; }
  .graph-edges-3d path:not(:first-child) { stroke: #657a9e; stroke-width: 1.4; opacity: 0.82; }
  .graph-node-3d { transform-origin: center; transition: border-color 120ms ease, background 120ms ease; }

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
    cursor: grab;
    text-align: center;
    touch-action: none;
    user-select: none;
  }

  .visual-graph-node.dragging { cursor: grabbing; }

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

  .visual-graph-node.inspected {
    outline: 2px solid #22d3ee;
    outline-offset: 3px;
    box-shadow: 0 0 0 5px rgb(34 211 238 / 10%), 0 10px 28px rgb(0 0 0 / 22%);
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

  .graph-callers-button {
    margin-bottom: 0.45rem;
    border: 1px solid #4c3a83;
    background: #211845;
    color: #ddd6fe;
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
    overflow: hidden;
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
    overflow: hidden;
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

  .function-list-column {
    min-width: 0;
  }

  .function-list-column .function-table-wrap {
    max-height: none;
    overflow: hidden;
  }

  .function-details {
    max-height: none;
    overflow: visible;
  }

  .function-pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    padding: 0.55rem 0.2rem 0;
  }

  .function-pagination span {
    color: #8292ad;
    font-size: 0.68rem;
    white-space: nowrap;
  }

  .function-pagination button {
    padding: 0.38rem 0.55rem;
    border: 1px solid #334765;
    background: #111e31;
    color: #cbd8ea;
    font-size: 0.66rem;
  }

  .function-pagination button:hover:not(:disabled) {
    border-color: #8b5cf6;
    background: #211845;
    color: #fff;
  }

  .function-pagination button:disabled {
    cursor: default;
    opacity: 0.35;
  }

  .function-table-name:hover:not(:disabled),
  .function-table-name:focus-visible {
    background: transparent;
    color: #67e8f9;
    outline: none;
    text-decoration-color: currentColor;
  }

  .function-table tbody tr.active .function-table-name {
    color: #ffffff;
  }

  .identification-workspace {
    display: grid;
    gap: 0.7rem;
  }

  .identification-header {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 1rem;
  }

  .identification-header h2 { margin: 0.2rem 0; font-size: 1.25rem; }
  .identification-header > div > p:last-child { margin: 0; color: #8292ad; font-size: 0.72rem; }

  .identification-header dl {
    display: flex;
    margin: 0;
    gap: 0.45rem;
  }

  .identification-header dl div {
    min-width: 88px;
    padding: 0.45rem 0.6rem;
    border: 1px solid #263750;
    border-radius: 7px;
    background: #0e1a2d;
  }

  .identification-header dt { color: #8292ad; font-size: 0.58rem; }
  .identification-header dd { margin: 0.12rem 0 0; color: #67e8f9; font-size: 1rem; font-weight: 800; }

  .identification-mode-switch {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.6rem 0.75rem;
    border: 1px solid #293a55;
    border-radius: 8px;
    background: #0d182a;
  }

  .identification-mode-switch > div { display: grid; gap: 0.15rem; }
  .identification-mode-switch strong { color: #e5edf8; font-size: 0.75rem; }
  .identification-mode-switch > div span { color: #8292ad; font-size: 0.62rem; }
  .identification-mode-switch > button {
    display: flex;
    flex: 0 0 auto;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.55rem;
    border: 1px solid #3a4b68;
    background: #111e31;
    color: #cbd5e1;
    font-size: 0.64rem;
  }

  .identification-mode-switch > button > span {
    position: relative;
    width: 30px;
    height: 16px;
    border-radius: 999px;
    background: #334155;
    transition: background 140ms ease;
  }

  .identification-mode-switch > button > span::after {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #e2e8f0;
    content: "";
    transition: transform 140ms ease;
  }

  .identification-mode-switch > button.active { border-color: #8b5cf6; background: #241b48; color: #ede9fe; }
  .identification-mode-switch > button.active > span { background: #7c3aed; }
  .identification-mode-switch > button.active > span::after { transform: translateX(14px); }
  .identification-mode-switch > button:hover:not(:disabled) { background: #1c2a40; }

  .automatic-rename-panel {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.65rem 0.75rem;
    border: 1px solid #4c3a83;
    border-radius: 8px;
    background: linear-gradient(90deg, rgb(76 29 149 / 20%), #0d182a 55%);
  }

  .automatic-rename-panel > div { display: grid; gap: 0.18rem; }
  .automatic-rename-panel strong { color: #ddd6fe; font-size: 0.75rem; }
  .automatic-rename-panel span { color: #91a0b8; font-size: 0.64rem; }
  .automatic-rename-panel button { flex: 0 0 auto; padding: 0.5rem 0.7rem; background: #6d28d9; color: white; font-size: 0.66rem; }
  .automatic-rename-panel button:hover:not(:disabled) { background: #7c3aed; }

  .automatic-choice-preview {
    border: 1px solid #22324a;
    border-radius: 8px;
    background: #0b1423;
    overflow: hidden;
  }

  .automatic-choice-preview > header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.65rem 0.75rem;
    border-bottom: 1px solid #22324a;
  }

  .automatic-choice-preview > header div { display: grid; gap: 0.12rem; }
  .automatic-choice-preview h3 { margin: 0; font-size: 0.8rem; }
  .automatic-choice-preview header span,
  .automatic-choice-preview header small { color: #8292ad; font-size: 0.58rem; }
  .automatic-choice-preview table { width: 100%; border-collapse: collapse; table-layout: fixed; }
  .automatic-choice-preview th { padding: 0.5rem 0.65rem; background: #101d30; color: #8292ad; font-size: 0.58rem; text-align: left; }
  .automatic-choice-preview th:nth-child(1) { width: 24%; }
  .automatic-choice-preview th:nth-child(2) { width: 23%; }
  .automatic-choice-preview th:nth-child(3) { width: 35%; }
  .automatic-choice-preview th:nth-child(4) { width: 18%; }
  .automatic-choice-preview td { padding: 0.55rem 0.65rem; border-top: 1px solid #1d2a40; color: #dbe5f2; font-size: 0.66rem; overflow: hidden; text-overflow: ellipsis; }
  .automatic-choice-preview td:first-child,
  .automatic-choice-preview td:nth-child(3) { display: grid; gap: 0.12rem; }
  .automatic-choice-preview td strong,
  .automatic-choice-preview td:nth-child(2) { color: #f1f5f9; font-weight: 700; }
  .automatic-choice-preview td:nth-child(2) { color: #86efac; }
  .automatic-choice-preview td code { color: #7db7e8; font-size: 0.56rem; }
  .automatic-choice-preview td span { color: #a7f3d0; }
  .automatic-choice-preview td small { color: #8292ad; font-size: 0.55rem; }
  .automatic-choice-preview td small.automatic-decision-reason { color: #6ee7b7; }
  .no-automatic-choice { display: grid; place-items: center; min-height: 270px; align-content: center; gap: 0.25rem; color: #8292ad; text-align: center; }
  .no-automatic-choice strong { color: #cbd5e1; font-size: 0.78rem; }
  .no-automatic-choice span { font-size: 0.65rem; }
  .generation-choice-preview { border-color: #4a3a14; }
  .generation-choice-preview > header { border-bottom-color: #4a3a14; }
  .generation-choice-preview h3 { color: #fbbf24; }
  .generation-choice-list { display: grid; gap: 0.55rem; padding: 0.75rem; }
  .generation-choice-item { display: grid; gap: 0.25rem; padding: 0.6rem 0.7rem; border: 1px solid #4a3a14; border-radius: 6px; background: #1a1608; }
  .generation-choice-item > div:first-child { display: flex; align-items: baseline; gap: 0.5rem; }
  .generation-choice-item strong { color: #f1f5f9; font-size: 0.7rem; }
  .generation-choice-item code { color: #7db7e8; font-size: 0.56rem; }
  .generation-choice-name { color: #fbbf24; font-size: 0.7rem; }
  .generation-choice-reasoning { margin: 0; color: #cbb98a; font-size: 0.64rem; line-height: 1.5; }

  .automatic-rejections {
    border: 1px solid #513444;
    border-radius: 8px;
    background: #111522;
    overflow: hidden;
  }

  .automatic-rejections > summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.7rem 0.78rem;
    cursor: pointer;
    list-style: none;
  }

  .automatic-rejections > summary::-webkit-details-marker { display: none; }
  .automatic-rejections > summary > span { display: grid; gap: 0.15rem; }
  .automatic-rejections > summary strong { color: #fecdd3; font-size: 0.74rem; }
  .automatic-rejections > summary small { color: #8f8291; font-size: 0.59rem; }
  .automatic-rejections > summary b { color: #fda4af; font-size: 0.63rem; }
  .automatic-rejections[open] > summary { border-bottom: 1px solid #3d2937; }
  .automatic-rejections[open] > summary b { font-size: 0; }
  .automatic-rejections[open] > summary b::after { font-size: 0.63rem; content: "Masquer"; }

  .automatic-rejection-list {
    display: grid;
    max-height: 390px;
    overflow: auto;
  }

  .automatic-rejection-list article {
    display: grid;
    grid-template-columns: minmax(150px, 0.75fr) minmax(220px, 1fr) minmax(320px, 1.65fr) auto;
    align-items: center;
    gap: 0.75rem;
    padding: 0.65rem 0.78rem;
    border-bottom: 1px solid #292334;
  }

  .automatic-rejection-list article:last-child { border-bottom: 0; }
  .automatic-rejection-list article > div { display: grid; min-width: 0; gap: 0.13rem; }
  .automatic-rejection-list strong { color: #e7edf6; font-size: 0.68rem; }
  .automatic-rejection-list span { color: #fbcfe8; font-size: 0.68rem; overflow-wrap: anywhere; }
  .automatic-rejection-list code,
  .automatic-rejection-list small { color: #7891af; font-size: 0.56rem; overflow-wrap: anywhere; }
  .automatic-rejection-list b { color: #fda4af; font-size: 0.62rem; font-weight: 600; line-height: 1.35; }
  .automatic-rejection-list button { padding: 0.42rem 0.58rem; border: 1px solid #604052; background: #251724; color: #fecdd3; font-size: 0.6rem; white-space: nowrap; }
  .automatic-rejection-list button:hover:not(:disabled) { background: #392033; }

  @media (max-width: 1180px) {
    .automatic-rejection-list article { grid-template-columns: 1fr 1fr; }
  }

  .identification-layout {
    display: grid;
    grid-template-columns: minmax(280px, 0.66fr) minmax(650px, 2.34fr);
    gap: 0.7rem;
    align-items: start;
  }

  .identification-queue,
  .identification-review {
    border: 1px solid #22324a;
    border-radius: 8px;
    background: #0b1423;
  }

  .identification-queue > header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.65rem;
    border-bottom: 1px solid #22324a;
  }

  .identification-queue > header div { display: grid; gap: 0.12rem; }
  .identification-queue > header strong { font-size: 0.75rem; }
  .identification-queue > header span,
  .identification-queue > header small { color: #8292ad; font-size: 0.58rem; }
  .identification-queue-tools { display: grid; gap: 0.45rem; padding: 0.55rem 0.6rem; border-bottom: 1px solid #22324a; }
  .identification-queue-tools > div { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.3rem; }
  .identification-queue-tools button { min-width: 0; padding: 0.35rem 0.3rem; border: 1px solid #30425e; background: #101d30; color: #9fb0c8; font-size: 0.52rem; white-space: nowrap; }
  .identification-queue-tools button b { color: #67e8f9; }
  .identification-queue-tools button.active { border-color: #8b5cf6; background: #241b48; color: #f5f3ff; }
  .identification-queue-tools input { min-width: 0; padding: 0.42rem 0.5rem; font-size: 0.58rem; }
  .identification-queue ol { display: grid; margin: 0; padding: 0; list-style: none; }
  .identification-queue li { border-bottom: 1px solid #1d2a40; }

  .identification-queue li > button {
    display: grid;
    width: 100%;
    grid-template-columns: minmax(0, 1fr) minmax(0, 0.9fr);
    align-items: center;
    gap: 0.55rem;
    padding: 0.53rem 0.65rem;
    border-radius: 0;
    background: transparent;
    color: #e5edf8;
    text-align: left;
  }

  .identification-queue li > button:hover:not(:disabled) { background: #13243a; }
  .identification-queue li > button.active { box-shadow: inset 3px 0 #8b5cf6; background: #172746; }
  .identification-queue li > button > span { display: grid; min-width: 0; gap: 0.1rem; }
  .identification-queue strong,
  .queue-candidate b { overflow: hidden; font-size: 0.68rem; text-overflow: ellipsis; white-space: nowrap; }
  .identification-queue code { color: #79b9ee; font-size: 0.56rem; }
  .queue-candidate small { color: #6ee7b7; font-size: 0.5rem; }
  .queue-candidate b { color: #bbf7d0; }
  .queue-candidate.ambiguous small,
  .queue-candidate.ambiguous b { color: #fbbf24; }
  .queue-no-evidence { color: #66758d; font-size: 0.56rem; }

  .identification-pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.65rem;
    padding: 0.5rem;
  }

  .identification-pagination button { padding: 0.25rem 0.55rem; border: 1px solid #354765; background: #111e31; color: #d6e0ee; }
  .identification-pagination button:disabled { cursor: default; opacity: 0.3; }
  .identification-pagination span { color: #8292ad; font-size: 0.62rem; }
  .identification-queue-empty { margin: 0; padding: 1.5rem 0.75rem; color: #8292ad; font-size: 0.65rem; text-align: center; }

  .identification-review { min-width: 0; }
  .identification-review > header { display: flex; align-items: center; justify-content: space-between; padding: 0.7rem 0.8rem; border-bottom: 1px solid #22324a; }
  .identification-review > header h3 { margin: 0.15rem 0; font-size: 1.05rem; }
  .identification-review > header code { color: #8abce9; font-size: 0.62rem; }
  .review-position { color: #8292ad; font-size: 0.62rem; }

  .identification-review-grid {
    display: grid;
    grid-template-columns: minmax(310px, 0.88fr) minmax(420px, 1.12fr);
    min-height: 410px;
  }

  .identification-evidence,
  .identification-code { min-width: 0; padding: 0.75rem; }
  .identification-evidence { max-height: 410px; overflow: auto; scrollbar-width: none; }
  .identification-code { border-left: 1px solid #22324a; }
  .review-section-heading { display: grid; gap: 0.12rem; margin-bottom: 0.55rem; }
  .review-section-heading h4 { margin: 0; color: #c4b5fd; font-size: 0.78rem; }
  .review-section-heading span { color: #7f8faa; font-size: 0.56rem; overflow-wrap: anywhere; }

  .evidence-source-group { display: grid; gap: 0.35rem; margin-bottom: 0.65rem; }
  .evidence-source-group h5 { display: grid; gap: 0.2rem; margin: 0.15rem 0; color: #67e8f9; font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.06em; }
  .evidence-source-group h5 span { color: #fbbf24; font-size: 0.58rem; font-weight: 500; letter-spacing: 0; line-height: 1.4; text-transform: none; }
  .evidence-source-group button {
    display: flex;
    width: 100%;
    align-items: center;
    justify-content: space-between;
    gap: 0.6rem;
    padding: 0.55rem 0.6rem;
    border: 1px solid #2a3a54;
    background: #101d30;
    color: #edf3fb;
    text-align: left;
  }
  .evidence-source-group button:hover:not(:disabled) { border-color: #22d3ee; background: #13283b; }
  .evidence-source-group button.selected { border-color: #8b5cf6; box-shadow: 0 0 0 1px #8b5cf6; background: #241b48; }
  .evidence-source-group button > span { display: grid; min-width: 0; gap: 0.12rem; }
  .evidence-source-group button > span:last-child { flex: 0 0 auto; text-align: right; }
  .evidence-source-group strong { overflow: hidden; font-size: 0.7rem; text-overflow: ellipsis; white-space: nowrap; }
  .rtti-evidence-group h5 { color: #86efac; }
  .arbitration-evidence-group h5 { color: #c4b5fd; }
  .generation-evidence-group h5 { color: #fbbf24; }
  .rtti-corroboration-badge { display: inline-block; margin-left: 0.4rem; padding: 0.12rem 0.4rem; border-radius: 4px; background: #123326; color: #86efac; font-size: 0.58rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; }
  .fid-raw-candidates > summary { margin-bottom: 0.4rem; color: #8192ad; font-size: 0.66rem; cursor: pointer; list-style: none; }
  .fid-raw-candidates > summary::-webkit-details-marker { display: none; }
  .fid-raw-candidates > summary::before { content: "▸ "; }
  .fid-raw-candidates[open] > summary::before { content: "▾ "; }
  .rtti-shared-note { margin: 0 0 0.5rem; padding: 0.6rem 0.7rem; border: 1px solid #1f4a33; border-radius: 6px; background: #0c1f16; color: #cdeedb; font-size: 0.7rem; line-height: 1.5; }

  .arbitration-panel { display: grid; gap: 0.5rem; margin-bottom: 0.65rem; padding: 0.65rem; border: 1px dashed #2a3a54; border-radius: 6px; background: #0c1930; }
  .arbitration-result { display: grid; gap: 0.3rem; }
  .arbitration-result strong { color: #86efac; font-size: 0.72rem; }
  .arbitration-result p { margin: 0; color: #a9b8d2; font-size: 0.68rem; line-height: 1.45; }
  .arbitration-result small { color: #71829d; font-size: 0.62rem; }
  .arbitration-status { margin: 0; color: #8192ad; font-size: 0.68rem; line-height: 1.45; }
  .arbitration-queue-status { margin: 0.4rem 0.95rem 0; color: #67e8f9; font-size: 0.66rem; }
  .link-button { padding: 0; border: none; background: none; color: #67e8f9; font-size: 0.66rem; text-align: left; text-decoration: underline; cursor: pointer; width: fit-content; }
  .evidence-source-group small { color: #8292ad; font-size: 0.54rem; }
  .evidence-source-group code { color: #a7f3d0; font-size: 0.58rem; }

  .identification-code pre { max-height: 345px; margin: 0; padding: 0.7rem; border: 1px solid #24344c; border-radius: 7px; background: #050b14; overflow: auto; scrollbar-width: none; }
  .identification-evidence::-webkit-scrollbar,
  .identification-code pre::-webkit-scrollbar { display: none; }
  .identification-code pre code { color: #cce8dc; font: 0.66rem/1.5 Consolas, monospace; white-space: pre; }
  .identification-code > p { color: #8292ad; font-size: 0.7rem; }

  .no-identification-evidence { display: grid; gap: 0.2rem; padding: 0.7rem; border: 1px dashed #394861; border-radius: 7px; color: #8292ad; }
  .no-identification-evidence strong { color: #cbd5e1; font-size: 0.7rem; }
  .no-identification-evidence span { font-size: 0.62rem; }

  .identification-actions {
    display: grid;
    grid-template-columns: minmax(220px, 1fr) auto auto;
    align-items: end;
    gap: 0.5rem;
    padding: 0.7rem 0.8rem;
    border-top: 1px solid #22324a;
    background: #0e1a2d;
  }
  .identification-actions > div { display: grid; gap: 0.25rem; }
  .identification-actions label { color: #94a3b8; font-size: 0.58rem; }
  .identification-actions input { padding: 0.5rem 0.6rem; font-size: 0.7rem; }
  .identification-actions button { padding: 0.5rem 0.65rem; font-size: 0.65rem; }
  .ignore-action { border: 1px solid #3a4b68; background: transparent; color: #cbd5e1; }
  .ignore-action:hover:not(:disabled) { background: #1c2a3e; }
  .apply-next-action { background: #6d28d9; color: white; }
  .apply-next-action:hover:not(:disabled) { background: #7c3aed; }
  .identification-message { margin: 0.45rem 0.8rem; padding: 0.45rem 0.6rem; font-size: 0.65rem; }

  .identification-complete { display: grid; place-items: center; min-height: 430px; align-content: center; text-align: center; }
  .identification-complete > span { display: grid; width: 50px; height: 50px; place-items: center; border-radius: 50%; background: #064e3b; color: #6ee7b7; font-size: 1.5rem; }
  .identification-complete h3 { margin: 0.8rem 0 0.2rem; }
  .identification-complete p { margin: 0; color: #8292ad; font-size: 0.72rem; }

  /* Shared presentation for strings, types, and imports/exports. */
  .data-workspace {
    display: grid;
    gap: 0.75rem;
  }

  .data-workspace-header {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 1rem;
  }

  .data-workspace-header h2 { margin: 0.18rem 0; font-size: 1.22rem; }
  .data-workspace-header > div > span { color: #8292ad; font-size: 0.68rem; }
  .data-workspace-header dl { display: flex; margin: 0; gap: 0.45rem; }
  .data-workspace-header dl div { min-width: 88px; padding: 0.45rem 0.6rem; border: 1px solid #263750; border-radius: 7px; background: #0e1a2d; }
  .data-workspace-header dt { color: #8292ad; font-size: 0.56rem; }
  .data-workspace-header dd { margin: 0.12rem 0 0; color: #67e8f9; font-size: 0.96rem; font-weight: 800; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .data-toolbar {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    padding: 0.6rem;
    border: 1px solid #22324a;
    border-radius: 8px;
    background: #0b1423;
  }

  .data-toolbar > input[type="search"] { min-width: 260px; flex: 1 1 auto; padding: 0.48rem 0.65rem; font-size: 0.68rem; }
  .data-toolbar select { padding: 0.48rem 0.65rem; border: 1px solid #334155; border-radius: 6px; background: #0f172a; color: #e2e8f0; font-size: 0.66rem; }
  .data-toolbar > span,
  .data-toolbar label { color: #8292ad; font-size: 0.62rem; white-space: nowrap; }
  .data-toolbar label { display: flex; align-items: center; gap: 0.35rem; }

  .data-table-card {
    border: 1px solid #22324a;
    border-radius: 8px;
    background: #0b1423;
    overflow: hidden;
  }

  .data-table-card table { width: 100%; border-collapse: collapse; table-layout: fixed; }
  .data-table-card th { padding: 0.52rem 0.7rem; background: #101d30; color: #8292ad; font-size: 0.58rem; font-weight: 700; text-align: left; text-transform: uppercase; letter-spacing: 0.035em; }
  .data-table-card td { height: 37px; padding: 0.45rem 0.7rem; border-top: 1px solid #1d2a40; color: #dbe5f2; font-size: 0.66rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .data-table-card tbody tr:hover { background: #101d30; }
  .data-table-card td code { color: #7db7e8; font-size: 0.6rem; }
  .data-table-card td strong { color: #f1f5f9; }
  .data-table-card td > button { padding: 0.3rem 0.55rem; border: 1px solid #4c3a83; background: #211845; color: #ddd6fe; font-size: 0.58rem; }
  .data-table-card td > button:hover:not(:disabled) { background: #352267; }

  .strings-table th:nth-child(1) { width: 14%; }
  .strings-table th:nth-child(2) { width: 42%; }
  .strings-table th:nth-child(3) { width: 12%; text-align: center; }
  .strings-table th:nth-child(4) { width: 32%; }
  .strings-table td:nth-child(2) span { display: block; overflow: hidden; text-overflow: ellipsis; }
  .strings-table td:nth-child(3) { color: #67e8f9; text-align: center; }

  .data-function-chips { display: flex; align-items: center; gap: 0.28rem; overflow: hidden; }
  .data-function-chips button { max-width: 110px; padding: 0.25rem 0.45rem; border: 1px solid #315da0; border-radius: 999px; background: #102447; color: #bfdbfe; font-size: 0.55rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .data-function-chips button:hover:not(:disabled) { background: #1e3a8a; }
  .data-function-chips em,
  .data-function-chips span { color: #71819a; font-size: 0.56rem; font-style: normal; }

  .data-pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.6rem;
    padding: 0.5rem 0.65rem;
    border-top: 1px solid #22324a;
  }
  .data-pagination.compact { justify-content: center; }
  .data-pagination button { padding: 0.32rem 0.55rem; border: 1px solid #354765; background: #111e31; color: #d6e0ee; font-size: 0.58rem; }
  .data-pagination button:hover:not(:disabled) { border-color: #8b5cf6; background: #211845; }
  .data-pagination button:disabled { cursor: default; opacity: 0.3; }
  .data-pagination span { color: #8292ad; font-size: 0.6rem; }
  .data-empty { display: grid; min-height: 280px; place-items: center; margin: 0; color: #8292ad; font-size: 0.72rem; text-align: center; }

  .data-subtabs { display: flex; gap: 0.3rem; padding-bottom: 0.45rem; border-bottom: 1px solid #22324a; }
  .data-subtabs button { display: flex; align-items: center; gap: 0.4rem; padding: 0.45rem 0.65rem; border-bottom: 2px solid transparent; border-radius: 5px 5px 0 0; background: transparent; color: #8292ad; font-size: 0.66rem; }
  .data-subtabs button span { padding: 0.1rem 0.35rem; border-radius: 999px; background: #1b2940; font-size: 0.52rem; }
  .data-subtabs button:hover:not(:disabled) { background: #111e31; color: #e2e8f0; }
  .data-subtabs button.active { border-bottom-color: #8b5cf6; background: #211845; color: #ede9fe; }

  .io-table th:nth-child(1) { width: 15%; }
  .io-table th:nth-child(2) { width: 27%; }
  .io-table th:nth-child(3) { width: 28%; }
  .io-table th:nth-child(4) { width: 18%; }
  .io-table th:nth-child(5) { width: 12%; }
  .exports-table th:nth-child(1) { width: 20%; }
  .exports-table th:nth-child(2) { width: 45%; }
  .exports-table th:nth-child(3) { width: 20%; }
  .exports-table th:nth-child(4) { width: 15%; }
  .data-kind-badge { display: inline-flex; padding: 0.18rem 0.42rem; border: 1px solid #315da0; border-radius: 999px; background: #102447; color: #bfdbfe; font-size: 0.54rem; }

  .libraries-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.65rem; }
  .libraries-grid article { display: flex; align-items: center; gap: 0.7rem; padding: 0.8rem; border: 1px solid #263750; border-radius: 8px; background: #0e1a2d; }
  .libraries-grid article > span { display: grid; width: 32px; height: 32px; flex: 0 0 auto; place-items: center; border-radius: 7px; background: #211845; color: #c4b5fd; }
  .libraries-grid article div { display: grid; min-width: 0; gap: 0.15rem; }
  .libraries-grid strong { overflow: hidden; color: #e5edf8; font-size: 0.7rem; text-overflow: ellipsis; white-space: nowrap; }
  .libraries-grid small { color: #8292ad; font-size: 0.56rem; }

  .types-layout { display: grid; grid-template-columns: minmax(280px, 0.7fr) minmax(620px, 2.3fr); gap: 0.7rem; align-items: start; }
  .types-list-card,
  .type-detail-card { border: 1px solid #22324a; border-radius: 8px; background: #0b1423; overflow: hidden; }
  .types-list-card ul { display: grid; margin: 0; padding: 0; list-style: none; }
  .types-list-card li { border-bottom: 1px solid #1d2a40; }
  .types-list-card li > button { display: flex; width: 100%; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.52rem 0.65rem; border-radius: 0; background: transparent; color: #e2e8f0; text-align: left; }
  .types-list-card li > button:hover:not(:disabled) { background: #13243a; }
  .types-list-card li > button.active { box-shadow: inset 3px 0 #8b5cf6; background: #172746; }
  .types-list-card li > button span { display: grid; min-width: 0; gap: 0.08rem; }
  .types-list-card li > button span:last-child { text-align: right; }
  .types-list-card small { color: #a78bfa; font-size: 0.5rem; text-transform: uppercase; }
  .types-list-card strong { overflow: hidden; font-size: 0.67rem; text-overflow: ellipsis; white-space: nowrap; }
  .types-list-card b,
  .types-list-card em { color: #8292ad; font-size: 0.54rem; font-style: normal; font-weight: 400; }

  .type-detail-card > header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.7rem 0.8rem; border-bottom: 1px solid #22324a; }
  .type-detail-card > header > div { min-width: 0; }
  .type-detail-card h3 { margin: 0.25rem 0 0.12rem; font-size: 1rem; overflow-wrap: anywhere; }
  .type-detail-card > header code { color: #7db7e8; font-size: 0.55rem; }
  .type-detail-card > header dl { display: flex; margin: 0; gap: 0.35rem; }
  .type-detail-card > header dl div { min-width: 65px; padding: 0.35rem 0.45rem; border: 1px solid #293a55; border-radius: 6px; background: #101d30; }
  .type-detail-card dt { color: #8292ad; font-size: 0.5rem; }
  .type-detail-card dd { margin: 0.1rem 0 0; color: #e5edf8; font-size: 0.65rem; }
  .type-detail-grid { display: grid; grid-template-columns: minmax(360px, 1.25fr) minmax(260px, 0.75fr); min-height: 410px; }
  .type-detail-grid > section { min-width: 0; padding: 0.75rem; }
  .type-detail-grid > section + section { border-left: 1px solid #22324a; }
  .type-detail-grid h4 { margin: 0 0 0.55rem; color: #c4b5fd; font-size: 0.72rem; }
  .type-detail-grid p { color: #8292ad; font-size: 0.65rem; }
  .type-detail-grid table { width: 100%; border-collapse: collapse; font-size: 0.61rem; }
  .type-detail-grid th { padding: 0.4rem; border-bottom: 1px solid #293a55; color: #8292ad; text-align: left; }
  .type-detail-grid td { padding: 0.42rem; border-bottom: 1px solid #1d2a40; color: #dbe5f2; overflow-wrap: anywhere; }
  .type-detail-grid td code { color: #93c5fd; }
  .type-usage-list { display: grid; margin: 0; padding: 0; gap: 0.35rem; list-style: none; }
  .type-usage-list li { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.42rem 0.5rem; border: 1px solid #293a55; border-radius: 6px; background: #101d30; }
  .type-usage-list span { color: #8292ad; font-size: 0.56rem; }
  .type-usage-list button { max-width: 150px; padding: 0; background: transparent; color: #93c5fd; font-size: 0.6rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .type-usage-list button:hover:not(:disabled) { background: transparent; color: #67e8f9; }

  @media (max-width: 1320px) {
    .function-explorer { grid-template-columns: minmax(370px, 0.9fr) minmax(580px, 2fr); }
    .function-overview-grid { grid-template-columns: 1fr; }
    .function-graph-preview { padding-left: 0; border-top: 1px solid #1d2a40; border-left: 0; }
    .identification-layout { grid-template-columns: minmax(260px, 0.7fr) minmax(560px, 2fr); }
    .identification-review-grid { grid-template-columns: 1fr; }
    .identification-code { border-top: 1px solid #22324a; border-left: 0; }
    .types-layout { grid-template-columns: minmax(250px, 0.75fr) minmax(500px, 2fr); }
    .type-detail-grid { grid-template-columns: 1fr; }
    .type-detail-grid > section + section { border-top: 1px solid #22324a; border-left: 0; }
    .libraries-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }

  @media (max-width: 980px) {
    .function-explorer { grid-template-columns: 1fr; }
    .function-list-heading { grid-column: 1; }
    .function-table-wrap { max-height: 400px; }
    .function-details { max-height: none; }
    .identification-header { align-items: flex-start; flex-direction: column; }
    .identification-layout { grid-template-columns: 1fr; }
    .identification-actions { grid-template-columns: 1fr; }
    .data-workspace-header { align-items: flex-start; flex-direction: column; }
    .data-toolbar { align-items: stretch; flex-direction: column; }
    .types-layout { grid-template-columns: 1fr; }
    .libraries-grid { grid-template-columns: 1fr; }
  }

  /* The settings screen is read at desktop distance: keep its diagnostic
     information comfortably legible instead of inheriting dashboard density. */
  .settings-workspace {
    gap: 0.95rem;
  }

  .settings-workspace .detail-label {
    font-size: 0.9rem;
  }

  .settings-workspace-header h2 {
    font-size: 1.85rem;
  }

  .settings-workspace-header p:not(.detail-label) {
    font-size: 1rem;
  }

  .settings-workspace-header > span {
    padding: 0.5rem 0.85rem;
    font-size: 0.85rem;
  }

  .settings-section > header {
    padding: 1rem 1.15rem;
  }

  .settings-section > header h3 {
    font-size: 1.1rem;
  }

  .settings-section > header p {
    font-size: 0.86rem;
  }

  .settings-section > header > span,
  .settings-section > header button {
    font-size: 0.84rem;
  }

  .settings-components-grid article {
    min-height: 152px;
    padding: 1rem 1.15rem;
    gap: 0.78rem;
  }

  .settings-component-indicator {
    width: 13px;
    height: 13px;
  }

  .settings-components-grid strong {
    font-size: 1rem;
  }

  .settings-components-grid small {
    font-size: 0.81rem;
  }

  .settings-components-grid b {
    padding: 0.28rem 0.48rem;
    font-size: 0.76rem;
  }

  .settings-components-grid article > p {
    font-size: 0.81rem;
    line-height: 1.5;
  }

  .settings-components-grid article > code {
    font-size: 0.76rem;
    line-height: 1.45;
  }

  .settings-managed-root,
  .settings-managed-root code {
    font-size: 0.78rem;
  }

  .ghidra-settings-card dt {
    font-size: 0.8rem;
  }

  .ghidra-settings-card dd {
    font-size: 0.96rem;
  }

  .ghidra-settings-card code {
    font-size: 0.78rem;
  }

  .settings-actions button {
    padding: 0.65rem 0.95rem;
    font-size: 0.86rem;
  }

  .settings-inline-error {
    font-size: 0.86rem;
  }

  .settings-advanced summary {
    padding: 1rem 1.15rem;
  }

  .settings-advanced summary h3 {
    font-size: 1.08rem;
  }

  .settings-advanced summary p,
  .settings-advanced summary > span {
    font-size: 0.84rem;
  }

  .settings-advanced[open] summary::after {
    font-size: 0.82rem;
  }

  .settings-advanced-content {
    padding: 1.1rem 1.15rem;
  }

  .settings-advanced-content h4 {
    font-size: 0.98rem;
  }

  .settings-advanced-content p,
  .settings-backend-check span {
    font-size: 0.82rem;
  }

  .settings-advanced-content input,
  .settings-advanced-content button {
    font-size: 0.84rem;
  }

  .analysis-progress-panel {
    position: fixed;
    right: 1.35rem;
    bottom: 1.35rem;
    z-index: 80;
    display: grid;
    width: min(520px, calc(100vw - 2.7rem));
    gap: 0.85rem;
    padding: 1.1rem 1.2rem;
    border: 1px solid #31415e;
    border-radius: 12px;
    background: #0b1628;
    box-shadow: 0 22px 60px rgb(0 0 0 / 48%);
  }

  .analysis-progress-panel header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
  }

  .analysis-progress-panel header p {
    margin: 0 0 0.22rem;
    color: #8ea3c1;
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.14em;
  }

  .analysis-progress-panel header h2 {
    margin: 0;
    color: #f4f7fb;
    font-size: 1.2rem;
    overflow-wrap: anywhere;
  }

  .analysis-progress-collapse {
    flex: 0 0 auto;
    padding: 0.42rem 0.65rem;
    border: 1px solid #344866;
    background: #101d31;
    color: #b7c6dc;
    font-size: 0.78rem;
  }

  .analysis-progress-track {
    position: relative;
    height: 12px;
    overflow: hidden;
    border-radius: 999px;
    background: #18253b;
  }

  .analysis-progress-track > span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: linear-gradient(90deg, #7c3aed, #22d3ee);
    transition: width 320ms ease;
  }

  .analysis-progress-track.indeterminate > span {
    width: 38% !important;
    background: linear-gradient(90deg, transparent, #8b5cf6 30%, #22d3ee 70%, transparent);
    animation: analysis-progress-scan 1.45s ease-in-out infinite;
  }

  .analysis-progress-track.failed > span {
    width: 100% !important;
    background: #ef4444;
  }

  .analysis-progress-copy {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 1rem;
  }

  .analysis-progress-copy strong {
    color: #e6edf7;
    font-size: 0.92rem;
    line-height: 1.4;
  }

  .analysis-progress-copy span {
    flex: 0 0 auto;
    color: #67e8f9;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 0.8rem;
  }

  .analysis-progress-panel > small {
    color: #8496b2;
    font-size: 0.76rem;
    line-height: 1.45;
  }

  .analysis-progress-panel > small.analysis-progress-error {
    max-height: 5rem;
    overflow: auto;
    color: #fda4af;
  }

  .analysis-progress-minimized {
    position: fixed;
    right: 1.35rem;
    bottom: 1.35rem;
    z-index: 80;
    display: flex;
    align-items: center;
    gap: 0.65rem;
    padding: 0.72rem 0.9rem;
    border: 1px solid #344866;
    border-radius: 10px;
    background: #0b1628;
    box-shadow: 0 16px 40px rgb(0 0 0 / 42%);
    color: #e6edf7;
  }

  .analysis-progress-minimized > span {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #22d3ee;
    box-shadow: 0 0 10px rgb(34 211 238 / 65%);
    animation: analysis-progress-pulse 1.25s ease-in-out infinite;
  }

  .analysis-progress-minimized > span.complete {
    background: #22c55e;
    animation: none;
  }

  .analysis-progress-minimized strong {
    font-size: 0.82rem;
  }

  .analysis-progress-minimized small {
    color: #8fa3bf;
    font-size: 0.74rem;
  }

  @keyframes analysis-progress-scan {
    from { transform: translateX(-110%); }
    to { transform: translateX(265%); }
  }

  @keyframes analysis-progress-pulse {
    0%, 100% { opacity: 0.55; transform: scale(0.88); }
    50% { opacity: 1; transform: scale(1); }
  }

  @media (max-width: 700px) {
    .analysis-progress-panel,
    .analysis-progress-minimized {
      right: 0.75rem;
      bottom: 0.75rem;
    }

    .analysis-progress-panel {
      width: calc(100vw - 1.5rem);
    }

    .analysis-progress-copy {
      align-items: flex-start;
      flex-direction: column;
      gap: 0.35rem;
    }
  }


</style>
