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

  interface ProgramMetadata {
  name: string;
  sha256: string;
  format: string;
  architecture: string;
  endianness: "little" | "big";
  image_base: string;
  entry_points: string[];
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

  async function checkBackendStatus() {
    backendStatus = await invoke<string>("get_backend_status");
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
        let selectedFunction = $derived(
          importedExport?.functions.find(
            (func) => func.entry_address === selectedFunctionAddress,
          ) ?? null,
        );
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
    <p class="phase">Phase 5 — Tauri import command</p>

    <h1>Reverse Assistant</h1>

    <p class="description">
      Import and validate a Ghidra JSON export locally.
    </p>

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
                <dd><code>{selectedFunction.return_type}</code></dd>
              </div>

              <div>
                <dt>Parameters</dt>
                <dd>{selectedFunction.parameters.length}</dd>
              </div>

              <div>
                <dt>Calls</dt>
                <dd>{selectedFunction.calls.length}</dd>
              </div>

            <div>
                <dt>Strings</dt>
                <dd>{selectedFunction.strings.length}</dd>
              </div>
            </dl>

            <section class="function-section">
            <h4>Parameters</h4>

              {#if selectedFunction.parameters.length === 0}
                <p>No parameters were identified.</p>
              {:else}
                <ul>
                  {#each selectedFunction.parameters as parameter}
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

            {#if selectedFunction.decompiled_code}
              <pre><code>{selectedFunction.decompiled_code}</code></pre>
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

  .backend-check {
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid #334155;
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