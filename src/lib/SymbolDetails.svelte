<script lang="ts">
  import { isEncodedCppName, type SymbolPresentation } from "$lib/symbolNames";
  let { name, presentation }: { name: string; presentation?: SymbolPresentation } = $props();
</script>

{#if isEncodedCppName(name)}
  <details class="symbol-details">
    <summary>{presentation?.decoded ? "Signature et symbole brut" : "Symbole C++ brut"}</summary>
    {#if presentation?.decoded}
      <p>Décodage {presentation.scheme === "msvc" ? "MSVC" : "GCC / Clang (Itanium)"} — n'ajoute aucune preuve de correspondance.</p>
      <dl>
        <dt>Signature décodée</dt><dd><code>{presentation.signature}</code></dd>
        <dt>Nom de renommage</dt><dd><code>{presentation.rename_name ?? "Aucun nom valide"}</code></dd>
      </dl>
    {:else}
      <p>{presentation ? "Décodage indisponible : le symbole original est conservé, sans nom deviné." : "Décodage local en cours…"}</p>
    {/if}
    <dl><dt>Symbole original</dt><dd><code>{name}</code></dd></dl>
  </details>
{/if}

<style>
  .symbol-details { grid-column: 1 / -1; font-size: 0.78rem; margin: 0.45rem 0 0.8rem; min-width: 0; color: #a8b9cf; }
  summary { cursor: pointer; color: #9cbad7; }
  p { margin: 0.5rem 0; }
  dl { margin: 0.5rem 0; }
  dt { font-weight: 600; margin-top: 0.35rem; }
  dd { margin: 0.2rem 0 0; }
  code { white-space: normal; overflow-wrap: anywhere; }
</style>
