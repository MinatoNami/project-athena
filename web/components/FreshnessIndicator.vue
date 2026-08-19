<script setup lang="ts">
/**
 * Data freshness, everywhere a fact is shown.
 *
 * "Never inventoried" is visually distinct from "inventoried and stale", which is
 * distinct from fresh. A host unseen for nine days must never look like one seen
 * five minutes ago.
 */
const props = defineProps<{
  at?: string | null
  neverInventoried?: boolean
  stale?: boolean
}>()

const relative = computed(() => {
  if (!props.at) return null
  const seconds = (Date.now() - new Date(props.at).getTime()) / 1000
  if (seconds < 90) return 'just now'
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`
  return `${Math.round(seconds / 86400)}d ago`
})
</script>

<template>
  <span v-if="neverInventoried" class="fresh never" :title="'This asset has never been successfully inventoried. Its contents are unknown — not clean.'">
    <span aria-hidden="true">⃠</span> never inventoried
  </span>
  <span v-else-if="stale" class="fresh stale" :title="at || ''">
    <span aria-hidden="true">!</span> stale · {{ relative }}
  </span>
  <span v-else class="fresh ok" :title="at || ''">
    <span aria-hidden="true">✓</span> {{ relative }}
  </span>
</template>

<style scoped>
.fresh { font-size: .78rem; white-space: nowrap; }
.ok { color: var(--ink-muted); }
.stale { color: var(--warn-ink); font-weight: 500; }
.never {
  color: var(--crit);
  font-weight: 600;
  /* Hatched, so "unknown" cannot be mistaken for a clean result at a glance. */
  background: repeating-linear-gradient(
    45deg, transparent, transparent 3px, var(--never-hatch) 3px, var(--never-hatch) 4px
  );
  padding: .1rem .35rem;
  border-radius: 4px;
}
</style>
