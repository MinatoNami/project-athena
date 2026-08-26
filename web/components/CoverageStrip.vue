<script setup lang="ts">
/**
 * The denominator strip.
 *
 * Coverage is chrome, not a footnote: every count elsewhere on the page is only
 * meaningful against how much was actually looked at, and a reader should not have
 * to go looking for that.
 */
const props = defineProps<{ coverage: any; findings?: any }>()

const cells = computed(() => {
  const c = props.coverage
  if (!c) return []
  const gap = (c.assets_never_scanned ?? 0) + (c.assets_stale ?? 0)
  return [
    {
      label: 'Inventoried',
      value: `${(c.assets_fresh ?? 0).toLocaleString()}`,
      of: `of ${(c.assets_total ?? 0).toLocaleString()} assets`,
      warn: gap > 0,
    },
    {
      label: 'Never looked at',
      value: `${(c.assets_never_scanned ?? 0).toLocaleString()}`,
      of: c.assets_never_scanned ? 'cannot appear below' : 'none',
      warn: (c.assets_never_scanned ?? 0) > 0,
    },
    {
      label: 'Stale',
      value: `${(c.assets_stale ?? 0).toLocaleString()}`,
      of: 'past their refresh window',
      warn: (c.assets_stale ?? 0) > 0,
    },
    {
      label: 'Assessed',
      value: `${(props.findings?.assessed_count ?? 0).toLocaleString()}`,
      of: `of ${(props.findings?.instance_count ?? 0).toLocaleString()} findings`,
      warn: false,
    },
  ]
})
</script>

<template>
  <div v-if="coverage" class="strip">
    <div v-for="c in cells" :key="c.label" class="cell">
      <span class="lbl">{{ c.label }}</span>
      <span class="figure">
        <span class="mono tnum value" :class="{ warn: c.warn }">{{ c.value }}</span>
        <span class="of">{{ c.of }}</span>
      </span>
    </div>
    <div class="legend">
      <span class="swatch hatch" />
      <span>Hatching means <strong>not looked at</strong>, never <em>clean</em>.</span>
    </div>
  </div>
</template>

<style scoped>
.strip {
  border: 1px solid var(--rule); border-radius: 9px; background: var(--surface);
  padding: .72rem .95rem; display: flex; align-items: center; gap: 1.6rem; flex-wrap: wrap;
}
.cell { display: flex; flex-direction: column; gap: .18rem; }
.figure { display: flex; align-items: baseline; gap: .35rem; }
.value { font-size: 1.05rem; font-weight: 600; }
.value.warn { color: var(--warn-ink); }
.of { font-size: .74rem; color: var(--ink-muted); }
.legend {
  margin-left: auto; display: flex; align-items: center; gap: .5rem;
  padding: .38rem .6rem; border-radius: 7px; background: var(--plane);
  border: 1px dashed var(--rule); font-size: .72rem; color: var(--ink-2); max-width: 20rem;
}
.swatch { width: 11px; height: 11px; flex-shrink: 0; border-radius: 2px; border: 1px solid var(--rule); }
@media (max-width: 1100px) { .legend { margin-left: 0; } }
</style>
