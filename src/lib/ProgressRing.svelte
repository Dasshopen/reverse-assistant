<script lang="ts">
  // A plain circular progress indicator for a real, already-computed
  // percentage (e.g. on-demand decompilation progress). Deliberately not
  // called a "confidence" gauge anywhere it's used -- this widget has no
  // opinion on what the number means, it just draws it.
  let {
    percentage,
    label,
    sublabel,
  }: { percentage: number; label: string; sublabel?: string } = $props();

  const radius = 42;
  const circumference = 2 * Math.PI * radius;

  let clamped = $derived(Math.max(0, Math.min(100, percentage)));
  let dashOffset = $derived(circumference * (1 - clamped / 100));
  let displayedPercentage = $derived(
    clamped > 0 && clamped < 1 ? "<1%" : `${Math.round(clamped)}%`,
  );
</script>

<div class="progress-ring">
  <div class="ring-visual">
    <svg viewBox="0 0 100 100" aria-hidden="true">
      <circle class="track" cx="50" cy="50" r={radius} />
      <circle
        class="value"
        cx="50"
        cy="50"
        r={radius}
        stroke-dasharray={circumference}
        stroke-dashoffset={dashOffset}
      />
    </svg>
    <div class="progress-ring-text">
      <strong>{displayedPercentage}</strong>
      <span>{label}</span>
    </div>
  </div>
  {#if sublabel}
    <small>{sublabel}</small>
  {/if}
</div>

<style>
  .progress-ring {
    display: grid;
    justify-items: center;
    align-content: center;
    gap: 0.15rem;
  }

  .ring-visual {
    position: relative;
    width: 72px;
    height: 72px;
  }

  svg {
    width: 72px;
    height: 72px;
    transform: rotate(-90deg);
  }

  circle {
    fill: none;
    stroke-width: 9;
  }

  .track {
    stroke: #1c2740;
  }

  .value {
    stroke: #8b5cf6;
    stroke-linecap: round;
    transition: stroke-dashoffset 300ms ease;
  }

  .progress-ring-text {
    position: absolute;
    inset: 0;
    display: grid;
    align-content: center;
    justify-items: center;
    text-align: center;
  }

  .progress-ring-text strong {
    color: #f3f6fb;
    font-size: 1rem;
    line-height: 1;
  }

  .progress-ring-text span {
    color: #8292ad;
    margin-top: 0.16rem;
    font-size: 0.6rem;
  }

  small {
    max-width: 130px;
    margin-top: 0;
    color: #71819c;
    font-size: 0.64rem;
    line-height: 1.15;
    text-align: center;
  }
</style>
