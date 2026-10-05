<script lang="ts">
  import { onMount } from "svelte";
  import { getVersion } from "@tauri-apps/api/app";
  import { check } from "@tauri-apps/plugin-updater";
  import { confirm } from "@tauri-apps/plugin-dialog";
  import { initialUpdateState, UpdateController } from "$lib/updates";

  let { showPanel, isBusy, onOpen, onLock }: {
    showPanel: boolean;
    isBusy: () => boolean;
    onOpen: () => void;
    onLock: (locked: boolean) => Promise<void>;
  } = $props();
  let updateState = $state(initialUpdateState());
  let currentVersion = $state("");
  let autoCheck = $state(true);
  let dismissed = $state(false);
  let preferenceError = $state("");
  const controller = new UpdateController(
    () => check({ timeout: 15_000 }),
    (next) => { updateState = next; if (next.stage === "available") dismissed = false; },
  );
  const preference = "reverse-assistant-auto-update-check";
  let progress = $derived(updateState.total && updateState.total > 0 ? Math.min(100, Math.round(updateState.downloaded / updateState.total * 100)) : null);
  let processing = $derived(["checking", "downloading", "installing"].includes(updateState.stage));

  onMount(() => {
    let cancelled = false;
    try { autoCheck = window.localStorage.getItem(preference) !== "false"; } catch { /* Keep the default without breaking startup. */ }
    getVersion().then((version) => {
      if (cancelled) return;
      currentVersion = version;
      if (autoCheck && !import.meta.env.DEV) void controller.check();
    }).catch(() => { currentVersion = "indisponible"; });
    return () => { cancelled = true; void controller.dispose().catch(() => {}); };
  });

  function setAutomaticCheck(enabled: boolean) {
    autoCheck = enabled;
    preferenceError = "";
    try { window.localStorage.setItem(preference, String(enabled)); }
    catch { preferenceError = "Ce choix ne pourra pas être conservé après fermeture."; }
  }

  function install() {
    return controller.install(isBusy, () => confirm(
      "L’application va se fermer pour installer la mise à jour, puis redémarrer. Vérifie que ton travail est sauvegardé. Continuer ?",
      { title: "Installer la mise à jour", kind: "warning", okLabel: "Installer", cancelLabel: "Plus tard" },
    ), onLock);
  }
</script>

{#if !showPanel && !dismissed && ["available", "downloading", "ready"].includes(updateState.stage)}
  <aside class="update-notice" aria-label="Mise à jour disponible">
    <span>Reverse Assistant {updateState.version} {updateState.stage === "ready" ? "prête à installer" : "disponible"}</span>
    <button type="button" onclick={onOpen}>Voir la mise à jour</button>
    <button type="button" class="dismiss" aria-label="Masquer la notification" onclick={() => { dismissed = true; }}>×</button>
  </aside>
{/if}

{#if showPanel}
  <section class="update-panel" aria-labelledby="update-heading">
    <header><div><h3 id="update-heading">Mises à jour de l’application</h3><p>Version {currentVersion || "…"} · canal Alpha · paquets vérifiés par signature</p></div></header>
    <div class="update-content">
      <label><input type="checkbox" checked={autoCheck} disabled={updateState.stage === "installing"} onchange={(event) => setAutomaticCheck(event.currentTarget.checked)} /> Vérifier automatiquement au démarrage</label>
      <p class="status" aria-live="polite">
        {#if updateState.stage === "checking"}Vérification en cours…
        {:else if updateState.stage === "current"}Aucune version plus récente sur le canal Alpha.
        {:else if updateState.stage === "available"}La version {updateState.version} est disponible.
        {:else if updateState.stage === "downloading"}Téléchargement et vérification… {progress === null ? `${Math.round(updateState.downloaded / 1024)} Ko` : `${progress}%`}
        {:else if updateState.stage === "ready"}La version {updateState.version} est téléchargée et sa signature a été vérifiée.
        {:else if updateState.stage === "installing"}Installation… L’application va se fermer.
        {:else if updateState.stage === "installed"}Installation lancée. Rouvre l’application si elle ne redémarre pas.
        {:else if updateState.stage === "idle"}Aucune vérification effectuée dans cette session.
        {/if}
      </p>
      {#if updateState.stage === "downloading"}<progress max="100" value={progress ?? undefined} aria-label="Téléchargement de la mise à jour"></progress>{/if}
      {#if updateState.notes}<details><summary>Nouveautés de la version {updateState.version}</summary><p class="release-notes">{updateState.notes}</p></details>{/if}
      {#if updateState.error}<p class="error" role="alert">{updateState.error}</p>{/if}
      {#if preferenceError}<p class="error">{preferenceError}</p>{/if}
      <div class="actions">
        <button type="button" disabled={processing || updateState.stage === "ready" || updateState.stage === "installed"} onclick={() => controller.check()}>Vérifier maintenant</button>
        {#if updateState.version && !["ready", "installing", "installed"].includes(updateState.stage)}<button type="button" disabled={processing} onclick={() => controller.download()}>Télécharger la mise à jour</button>{/if}
        {#if updateState.stage === "ready"}<button type="button" disabled={isBusy()} onclick={install}>Installer et redémarrer</button>{/if}
      </div>
      {#if updateState.stage === "ready" && isBusy()}<p>Attends la fin de l’analyse et des opérations en cours avant d’installer.</p>{/if}
      <small>Le téléchargement ne change pas tes projets. L’installation nécessite ton accord et ferme l’application. La signature des mises à jour ne supprime pas les avertissements Windows d’un installateur non signé.</small>
    </div>
  </section>
{/if}

<style>
  .update-panel { margin: 1rem auto; width: min(100% - 2rem, 1100px); border: 1px solid #314562; border-radius: 10px; background: #0c1627; color: #e1ecfa; }
  header { padding: 0.8rem 1rem; border-bottom: 1px solid #314562; }
  h3 { margin: 0; font-size: 1rem; }
  p { margin: 0.5rem 0; font-size: 0.84rem; }
  header p, small { color: #a4b6ce; }
  .update-content { padding: 1rem; display: grid; gap: 0.65rem; }
  label { display: flex; align-items: center; gap: 0.55rem; font-size: 0.85rem; }
  .actions { display: flex; flex-wrap: wrap; gap: 0.7rem; }
  button { cursor: pointer; padding: 0.6rem 0.85rem; border: 1px solid #526991; border-radius: 7px; background: #182941; color: #eef5ff; font-weight: 600; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button:hover:not(:disabled) { border-color: #a78bfa; }
  summary { cursor: pointer; }
  progress { width: 100%; accent-color: #8b5cf6; }
  .release-notes { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 16rem; overflow-y: auto; }
  .error { color: #fda4af; }
  small { line-height: 1.5; }
  .update-notice { position: fixed; right: 1rem; top: 1rem; z-index: 1800; display: flex; align-items: center; gap: 0.7rem; flex-wrap: wrap; max-width: calc(100vw - 2rem); padding: 0.75rem; border: 1px solid #8b5cf6; border-radius: 10px; background: #181c37; color: #e8edff; box-shadow: 0 8px 30px #0008; }
  .dismiss { padding: 0.25rem 0.5rem; }
</style>
