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
</script>

<div class="progress-ring">
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
    <strong>{clamped}%</strong>
    <span>{label}</span>
  </div>
  {#if sublabel}
    <small>{sublabel}</small>
  {/if}
</div>

<style>
  .progress-ring {
    display: grid;
    justify-items: center;
    gap: 0.3rem;
  }

  svg {
    width: 108px;
    height: 108px;
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
    display: grid;
    margin-top: -74px;
    justify-items: center;
    text-align: center;
  }

  .progress-ring-text strong {
    color: #f3f6fb;
    font-size: 1.15rem;
  }

  .progress-ring-text span {
    color: #8292ad;
    font-size: 0.62rem;
  }

  small {
    margin-top: 0.35rem;
    color: #71819c;
    font-size: 0.66rem;
    text-align: center;
  }
</style>
