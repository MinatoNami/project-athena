<script setup lang="ts">
/**
 * The denominator strip.
 *
 * Coverage is chrome, not a footnote: every count elsewhere on the page is only
 * meaningful against how much was actually looked at. Tiles rather than a pie,
 * because four tiles compare faster than four wedges (§9) and a tile can say "none
 * of this was measured", which a wedge cannot.
 */
const props = defineProps<{ coverage: any; findings?: any }>()

const read = computed(() => {
  const c = props.coverage
  if (!c?.assets_total) return null
  return (c.assets_fresh ?? 0) / c.assets_total
})
</script>

<template>
  <div v-if="coverage" class="strip">
    <StatTile
      label="Assets read"
      :value="(coverage.assets_fresh ?? 0).toLocaleString()"
      :of="`of ${(coverage.assets_total ?? 0).toLocaleString()}`"
      :progress="read"
      :status="read === null ? null : read < 0.9 ? 'warn' : 'good'"
    />
    <StatTile
      label="Never read"
      :value="(coverage.assets_never_scanned ?? 0).toLocaleString()"
      :of="coverage.assets_never_scanned ? 'contents unknown' : 'none'"
      :status="coverage.assets_never_scanned ? 'bad' : null"
    />
    <StatTile
      label="Stale"
      :value="(coverage.assets_stale ?? 0).toLocaleString()"
      of="past refresh"
      :status="coverage.assets_stale ? 'warn' : null"
    />
    <StatTile
      label="Findings assessed"
      :value="findings ? (findings.assessed_count ?? 0).toLocaleString() : null"
      :of="findings ? `of ${(findings.instance_count ?? 0).toLocaleString()}` : undefined"
      hint="could not be counted"
      :progress="findings?.instance_count ? findings.assessed_count / findings.instance_count : null"
    />
    <p class="legend">
      <span class="swatch hatch" aria-hidden="true" />
      <!-- One text node for the flex container: bare text and inline elements were
           each made a flex item and the sentence split into four columns. -->
      <span>Hatched or dashed means <strong>not looked at</strong> — never <em>clean</em>.</span>
    </p>
  </div>
</template>

<style scoped>
.strip {
  border: 1px solid var(--rule); border-radius: 9px; background: var(--surface);
  padding: .72rem .95rem; display: flex; align-items: flex-start; gap: 1.9rem; flex-wrap: wrap;
}
.legend {
  margin: 0 0 0 auto; display: flex; align-items: center; gap: .45rem; align-self: center;
  padding: .34rem .55rem; border-radius: 7px; background: var(--plane);
  border: 1px dashed var(--rule); font-size: .7rem; color: var(--ink-2); max-width: 17rem;
}
.swatch { width: 11px; height: 11px; flex-shrink: 0; border-radius: 2px; border: 1px solid var(--rule); }
@media (max-width: 1100px) { .legend { margin-left: 0; } }
</style>
