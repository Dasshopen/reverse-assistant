<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { open } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";

  type ComponentState = "ready" | "missing" | "invalid";

  interface SetupComponent {
    id: string;
    label: string;
    state: ComponentState;
    version: string | null;
    path: string | null;
    detail: string;
    required: boolean;
  }

  interface SetupOverview {
    ready: boolean;
    managed_install_available: boolean;
    managed_root: string;
    components: SetupComponent[];
  }

  interface SetupInstallItem {
    id: string;
    label: string;
    version: string;
    source: string;
    license: string;
    license_url: string;
    download_required: boolean;
  }

  interface SetupInstallPlan {
    destination: string;
    administrator_required: boolean;
    items: SetupInstallItem[];
  }

  interface SetupProgress {
    stage: string;
    message: string;
    completed_percent: number;
  }

  interface Props {
    onready?: () => void | Promise<void>;
  }

  let { onready }: Props = $props();
  let overview = $state<SetupOverview | null>(null);
  let plan = $state<SetupInstallPlan | null>(null);
  let progress = $state<SetupProgress | null>(null);
  let error = $state("");
  let loading = $state(true);
  let installing = $state(false);
  let configuringExisting = $state(false);
  let licensesAccepted = $state(false);

  onMount(() => {
    let unlisten: UnlistenFn | undefined;
    listen<SetupProgress>("setup-progress", (event) => {
      progress = event.payload;
    }).then((stop) => {
      unlisten = stop;
    });
    loadSetup();
    return () => unlisten?.();
  });

  async function loadSetup() {
    loading = true;
    error = "";
    try {
      overview = await invoke<SetupOverview>("get_setup_overview");
      if (!overview.ready) {
        plan = await invoke<SetupInstallPlan>("get_managed_setup_plan");
      }
    } catch (reason) {
      error = String(reason);
    } finally {
      loading = false;
    }
  }

  async function installAutomatically() {
    if (!licensesAccepted || installing) return;
    installing = true;
    error = "";
    progress = {
      stage: "prepare",
      message: "Préparation de l’installation locale...",
      completed_percent: 1,
    };
    try {
      overview = await invoke<SetupOverview>("install_managed_setup", {
        licensesAccepted: true,
      });
      if (overview.ready) {
        await onready?.();
      }
    } catch (reason) {
      error = String(reason);
    } finally {
      installing = false;
    }
  }

  async function useExistingInstallation() {
    configuringExisting = true;
    error = "";
    try {
      const selected = await open({ directory: true, multiple: false });
      if (typeof selected !== "string") return;
      await invoke("adopt_existing_ghidra", { installDir: selected });
      await loadSetup();
      if (overview?.ready) {
        await onready?.();
      }
    } catch (reason) {
      error = String(reason);
    } finally {
      configuringExisting = false;
    }
  }

  function stateLabel(state: ComponentState) {
    if (state === "ready") return "Prêt";
    if (state === "invalid") return "À réparer";
    return "Manquant";
  }
</script>

{#if loading}
  <div class="setup-backdrop" role="status">
    <div class="setup-dialog setup-loading">Vérification des composants...</div>
  </div>
{:else if overview && !overview.ready}
  <div class="setup-backdrop">
    <div class="setup-dialog" aria-labelledby="setup-title" aria-modal="true" role="dialog">
      <header>
        <div class="setup-mark">RA</div>
        <div>
          <p class="eyebrow">PREMIER DÉMARRAGE</p>
          <h1 id="setup-title">Préparons l’environnement d’analyse</h1>
          <p>
            L’application peut installer et configurer seule les outils nécessaires. Rien ne sera
            ajouté au système avant ton accord.
          </p>
        </div>
      </header>

      <div class="component-list">
        {#each overview.components as component (component.id)}
          <article class:ready={component.state === "ready"}>
            <span class="component-icon" aria-hidden="true">
              {component.state === "ready" ? "✓" : component.required ? "!" : "+"}
            </span>
            <div>
              <div class="component-heading">
                <strong>{component.label}</strong>
                <span class={`state ${component.state}`}>{stateLabel(component.state)}</span>
              </div>
              <p>{component.detail}</p>
              {#if component.version}<small>Version : {component.version}</small>{/if}
            </div>
          </article>
        {/each}
      </div>

      {#if plan}
        <div class="install-summary">
          <div>
            <span>Emplacement</span>
            <code>{plan.destination}</code>
          </div>
          <div>
            <span>Droits administrateur</span>
            <strong>{plan.administrator_required ? "Requis" : "Non requis"}</strong>
          </div>
        </div>

        <details>
          <summary>Sources et licences des composants</summary>
          <ul>
            {#each plan.items as item (item.id)}
              <li>
                <div><strong>{item.label}</strong> <span>{item.version}</span></div>
                <small>{item.source} · {item.license}</small>
              </li>
            {/each}
          </ul>
        </details>

        <label class="consent">
          <input type="checkbox" bind:checked={licensesAccepted} disabled={installing} />
          <span>
            J’ai lu les sources et licences affichées et j’autorise le téléchargement ainsi que
            l’installation dans le dossier local indiqué.
          </span>
        </label>
      {/if}

      {#if progress}
        <div class="progress-block" aria-live="polite">
          <div><strong>{progress.message}</strong><span>{progress.completed_percent}%</span></div>
          <progress max="100" value={progress.completed_percent}></progress>
        </div>
      {/if}

      {#if error}<p class="setup-error" role="alert">{error}</p>{/if}

      <footer>
        <button
          type="button"
          class="secondary"
          disabled={installing || configuringExisting}
          onclick={useExistingInstallation}
        >
          {configuringExisting ? "Vérification..." : "J’ai déjà Ghidra"}
        </button>
        <button
          type="button"
          disabled={!licensesAccepted || installing || !overview.managed_install_available}
          onclick={installAutomatically}
        >
          {installing ? "Installation en cours..." : "Installer et configurer automatiquement"}
        </button>
      </footer>
    </div>
  </div>
{/if}

<style>
  .setup-backdrop {
    position: fixed;
    z-index: 1000;
    inset: 0;
    display: grid;
    place-items: center;
    padding: 1.5rem;
    background: rgb(2 6 23 / 88%);
    backdrop-filter: blur(12px);
  }

  .setup-dialog {
    width: min(760px, 100%);
    max-height: calc(100vh - 3rem);
    overflow: auto;
    box-sizing: border-box;
    padding: 2rem;
    border: 1px solid #26344d;
    border-radius: 18px;
    background: #0b1220;
    color: #e8eef9;
    box-shadow: 0 30px 90px rgb(0 0 0 / 45%);
  }

  .setup-loading {
    width: auto;
    color: #a5b4ce;
  }

  header {
    display: flex;
    gap: 1.1rem;
    align-items: flex-start;
  }

  .setup-mark {
    display: grid;
    width: 3rem;
    height: 3rem;
    flex: 0 0 auto;
    place-items: center;
    border: 1px solid #7c3aed;
    border-radius: 12px;
    background: linear-gradient(135deg, #6d28d9, #312e81);
    font-weight: 800;
  }

  .eyebrow {
    margin: 0 0 0.35rem;
    color: #8b9ab5;
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.14em;
  }

  h1 {
    margin: 0;
    font-size: clamp(1.45rem, 4vw, 2rem);
  }

  header p:last-child {
    margin-bottom: 0;
    color: #a5b4ce;
    line-height: 1.55;
  }

  .component-list {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.7rem;
    margin-top: 1.5rem;
  }

  article {
    display: flex;
    gap: 0.8rem;
    padding: 1rem;
    border: 1px solid #334155;
    border-radius: 12px;
    background: #111a2b;
  }

  article.ready {
    border-color: #1f4e46;
  }

  .component-icon {
    display: grid;
    width: 1.6rem;
    height: 1.6rem;
    flex: 0 0 auto;
    place-items: center;
    border-radius: 999px;
    background: #253149;
    color: #a5b4ce;
    font-weight: 800;
  }

  article.ready .component-icon {
    background: #064e3b;
    color: #6ee7b7;
  }

  .component-heading {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 0.5rem;
  }

  article p {
    margin: 0.45rem 0;
    color: #93a3be;
    font-size: 0.84rem;
    line-height: 1.4;
  }

  article small {
    color: #7787a4;
  }

  .state {
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
    background: #263249;
    color: #a5b4ce;
    font-size: 0.7rem;
    font-weight: 800;
  }

  .state.ready {
    background: #064e3b;
    color: #6ee7b7;
  }

  .state.invalid {
    background: #713f12;
    color: #fde68a;
  }

  .install-summary {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 1rem;
    margin-top: 1rem;
    padding: 0.9rem 1rem;
    border: 1px solid #26344d;
    border-radius: 10px;
    background: #0f172a;
  }

  .install-summary div {
    display: grid;
    gap: 0.3rem;
  }

  .install-summary span,
  details small {
    color: #8494af;
    font-size: 0.78rem;
  }

  .install-summary code {
    overflow-wrap: anywhere;
    color: #cbd5e1;
  }

  details {
    margin-top: 0.8rem;
    padding: 0.8rem 1rem;
    border: 1px solid #26344d;
    border-radius: 10px;
    color: #a5b4ce;
  }

  details ul {
    display: grid;
    gap: 0.6rem;
    margin: 0.8rem 0 0;
    padding: 0;
    list-style: none;
  }

  details li div {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    color: #dbe5f5;
  }

  .consent {
    display: flex;
    gap: 0.7rem;
    margin-top: 1rem;
    color: #bdc9dc;
    font-size: 0.88rem;
    line-height: 1.45;
  }

  .consent input {
    width: 1rem;
    height: 1rem;
    flex: 0 0 auto;
    margin-top: 0.15rem;
    accent-color: #7c3aed;
  }

  .progress-block {
    display: grid;
    gap: 0.5rem;
    margin-top: 1rem;
  }

  .progress-block div {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    font-size: 0.85rem;
  }

  progress {
    width: 100%;
    height: 0.55rem;
    accent-color: #7c3aed;
  }

  .setup-error {
    padding: 0.75rem 0.9rem;
    border: 1px solid #7f1d1d;
    border-radius: 8px;
    background: #450a0a;
    color: #fecaca;
  }

  footer {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1.4rem;
  }

  button {
    padding: 0.75rem 1rem;
    border: 1px solid #7c3aed;
    border-radius: 9px;
    background: #6d28d9;
    color: white;
    font: inherit;
    font-weight: 750;
    cursor: pointer;
  }

  button.secondary {
    border-color: #3a4861;
    background: #172033;
    color: #cbd5e1;
  }

  button:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }

  @media (max-width: 650px) {
    .component-list,
    .install-summary {
      grid-template-columns: 1fr;
    }

    footer {
      flex-direction: column-reverse;
    }

    footer button {
      width: 100%;
    }
  }
</style>
