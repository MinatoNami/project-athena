<script setup lang="ts">
const props = defineProps<{
  coverage: {
    assets_total: number
    assets_fresh: number
    assets_stale: number
    assets_never_scanned: number
    coverage_ratio: number | null
    inconclusive_scans_24h: number
    never_scanned: Array<{ id: string; kind: string; display_name: string }>
  }
}>()

const { theme } = useChartTheme()

const rows = computed(() => {
  const c = props.coverage
  return [
    { label: 'read recently', value: c.assets_fresh ?? 0, color: theme.value.good },
    { label: 'past its window', value: c.assets_stale ?? 0, color: theme.value.warnInk },
    {
      label: 'never read',
      value: c.assets_never_scanned ?? 0,
      color: theme.value.crit,
      dashed: true,
      hint: 'contents unknown, not clean',
    },
  ].filter(r => r.value > 0)
})
</script>

<template>
  <div v-if="!coverage.assets_total" class="card">
    <span class="lbl">Coverage</span>
    <p class="muted">No assets registered. Nothing is being watched.</p>
  </div>

  <div v-else class="wrapper">
    <div class="tiles">
      <StatTile
        label="Assets read"
        :value="coverage.assets_fresh"
        :of="`of ${coverage.assets_total}`"
        :progress="coverage.assets_total ? coverage.assets_fresh / coverage.assets_total : null"
        :status="coverage.assets_never_scanned ? 'warn' : 'good'"
      />
      <StatTile
        label="Never read"
        :value="coverage.assets_never_scanned"
        :of="coverage.assets_never_scanned ? 'contents unknown' : 'none'"
        :status="coverage.assets_never_scanned ? 'bad' : null"
      />
      <StatTile
        v-if="coverage.inconclusive_scans_24h"
        label="Inconclusive scans"
        :value="coverage.inconclusive_scans_24h"
        of="in the last 24h — reported unknown"
        status="warn"
      />
    </div>

    <ChartFrame
      title="Coverage"
      note="dashed means nothing has read it"
      :table="{ columns: ['State', 'Assets'], rows: rows.map(r => [r.label, r.value]) }"
    >
      <ChartBars :rows="rows" unit="assets" summary="Assets by how recently they were read" />
    </ChartFrame>

    <ul v-if="coverage.never_scanned.length" class="gaps">
      <li v-for="a in coverage.never_scanned.slice(0, 5)" :key="a.id">
        <NuxtLink :to="`/assets/${a.id}`">{{ a.display_name }}</NuxtLink>
        <span class="muted"> — {{ a.kind }}, unread</span>
      </li>
    </ul>
  </div>
</template>

<style scoped>
.wrapper { display: flex; flex-direction: column; gap: .7rem; margin-bottom: 1rem; }
.tiles { display: flex; gap: 1.8rem; flex-wrap: wrap; border: 1px solid var(--rule);
         border-radius: 9px; background: var(--surface); padding: .72rem .95rem; }
.gaps { margin: 0; padding-left: 1.1rem; font-size: .8rem; color: var(--ink-2); }
</style>
