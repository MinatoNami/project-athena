<script setup lang="ts">
/**
 * One headline number, with the denominator it was computed over (rule 3) and,
 * where there is one, the target it is judged against.
 *
 * §9 prefers a row of these to a pie: a reader compares four tiles faster than
 * four wedges, and a tile can admit it has no value — which a wedge cannot.
 */
defineProps<{
  label: string
  /** `null` means nothing measured it. Rendered hatched, never as zero (rule 1). */
  value: string | number | null
  /** The denominator — "of 41 assets". */
  of?: string
  /** Progress against target, 0–1. Draws the bar only when given. */
  progress?: number | null
  target?: string
  status?: 'good' | 'warn' | 'bad' | null
  hint?: string
  /** `target` is a goal this value is judged against, so met/short is said in words. */
  goal?: boolean
}>()
</script>

<template>
  <div class="tile" :class="status || undefined">
    <span class="lbl">{{ label }}</span>
    <span class="figure">
      <span v-if="value === null" class="hatch unknown" :title="hint || 'Nothing has measured this'">
        <span class="sr-only">{{ hint || 'not measured' }}</span>
      </span>
      <span v-else class="mono tnum value">{{ value }}</span>
      <span v-if="of" class="of">{{ of }}</span>
    </span>
    <div v-if="progress != null" class="track">
      <span class="fill" :style="{ width: `${Math.max(2, Math.min(100, progress * 100))}%` }" />
    </div>
    <!-- Met or short is said in words, not by the figure's colour alone (§7, §8). -->
    <span v-if="target" class="target">
      <template v-if="goal && status === 'good'">✓ meeting · </template>
      <template v-else-if="goal && status === 'bad'">✗ short · </template>
      {{ target }}
    </span>
    <span v-else-if="value === null && hint" class="target">{{ hint }}</span>
  </div>
</template>

<style scoped>
.tile { display: flex; flex-direction: column; gap: .2rem; min-width: 0; }
.figure { display: flex; align-items: baseline; gap: .35rem; }
.value { font-size: 1.12rem; font-weight: 640; letter-spacing: -0.01em; }
.of { font-size: .73rem; color: var(--ink-muted); }
.unknown { display: inline-block; width: 2.1rem; height: .95rem; border-radius: 3px;
           border: 1px dashed var(--rule); }
.target { font-size: .69rem; color: var(--ink-muted); }
/* Status is colour plus a word in the label beside it, never colour alone (§8). */
.good .value { color: var(--good-ink); }
.warn .value { color: var(--warn-ink); }
.bad .value { color: var(--crit); }
.track { height: 4px; border-radius: 2px; background: var(--rule); overflow: hidden; margin: .18rem 0 .1rem; }
.fill { display: block; height: 100%; border-radius: 2px; background: var(--ink-2); }
.good .fill { background: var(--good); }
.warn .fill { background: var(--warn-ink); }
.bad .fill { background: var(--crit); }
</style>
