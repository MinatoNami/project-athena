<script setup lang="ts">
defineProps<{
  label: string
  value: string | number | null
  of?: string
  progress?: number | null
  target?: string
  status?: 'good' | 'warn' | 'bad' | null
  hint?: string
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
.good .value { color: var(--good-ink); }
.warn .value { color: var(--warn-ink); }
.bad .value { color: var(--crit); }
.track { height: 4px; border-radius: 2px; background: var(--rule); overflow: hidden; margin: .18rem 0 .1rem; }
.fill { display: block; height: 100%; border-radius: 2px; background: var(--ink-2); }
.good .fill { background: var(--good); }
.warn .fill { background: var(--warn-ink); }
.bad .fill { background: var(--crit); }
</style>
