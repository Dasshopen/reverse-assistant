<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";

  let backendStatus = $state("");

  async function checkBackendStatus() {
    backendStatus = await invoke<string>("get_backend_status");
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
  <p class="phase">Phase 1 — Application skeleton</p>

  <h1>Reverse Assistant</h1>

  <p class="description">
    Local and AI-agnostic reverse engineering assistant.
  </p>

  <button type="button" onclick={checkBackendStatus}>
    Check Rust backend
  </button>

  {#if backendStatus}
    <p class="status">{backendStatus}</p>
  {/if}
</main>

<style>
  :global(body) {
    margin: 0;
    min-width: 320px;
    background-color: #111827;
    color: #f9fafb;
    font-family: Inter, Arial, sans-serif;
  }

  .container {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    box-sizing: border-box;
    padding: 2rem;
    text-align: center;
  }

  .phase {
    color: #22d3ee;
    font-weight: 600;
  }

  h1 {
    margin: 0.5rem 0;
    font-size: 3rem;
  }

  .description {
    margin-bottom: 2rem;
    color: #cbd5e1;
  }

  button {
    padding: 0.8rem 1.2rem;
    border: 0;
    border-radius: 8px;
    background-color: #22d3ee;
    color: #0f172a;
    font-size: 1rem;
    font-weight: 700;
    cursor: pointer;
  }

  button:hover {
    background-color: #67e8f9;
  }

  .status {
    margin-top: 1.5rem;
    padding: 0.8rem 1rem;
    border: 1px solid #22c55e;
    border-radius: 8px;
    color: #86efac;
  }
</style>