<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

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
  let decompileCache = $state(new Map<string, DecompiledFunctionDetails>());
  let pendingDecompiles = $state(new Set<string>());
  let decompileErrors = $state(new Map<string, string>());
  let identifications = $state(new Map<string, FidCandidate[]>());

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
    loadGhidraInstallationStatus();
  });

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
    } catch (error) {
      decompileErrors = new Map(decompileErrors).set(entryAddress, String(error));
    } finally {
      const remainingDecompiles = new Set(pendingDecompiles);
      remainingDecompiles.delete(entryAddress);
      pendingDecompiles = remainingDecompiles;
    }
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
      identifications = new Map(
        result.identifications.map((identification) => [
          identification.entry_address,
          identification.candidates,
        ]),
      );
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
            <dt>Decompiled functions</dt>
            <dd>{importSummary.decompiled_function_count}</dd>
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

            {#if selectedIdentificationCandidates.length > 0}
              <section class="function-section">
                <h4>Possible match (FunctionID)</h4>

                <ul>
                  {#each selectedIdentificationCandidates as candidate}
                    <li>
                      <span>
                        {candidate.name}
                        <em>
                          ({candidate.library_family} {candidate.library_version}
                          {candidate.library_variant}, {candidate.match_mode})
                        </em>
                      </span>
                      <code>score {candidate.overall_score.toFixed(1)}</code>
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
                        <li>
                          <span>
                            {candidate.name}
                            <em>({candidate.executable})</em>
                          </span>
                          <code>
                            similarity {candidate.similarity.toFixed(3)} · significance
                            {candidate.significance.toFixed(1)}
                          </code>
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
