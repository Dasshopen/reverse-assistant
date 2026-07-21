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

  let backendStatus = $state("");
  let exportPath = $state("");
  let importSummary = $state<GhidraImportSummary | null>(null);
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

    const path = exportPath.trim();

    if (!path) {
      importError = "Enter the path of a Ghidra JSON export.";
      return;
    }

    isImporting = true;

    try {
      importSummary = await invoke<GhidraImportSummary>(
        "import_ghidra_export_summary",
        { path },
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
</style>