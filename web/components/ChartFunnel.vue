<script setup lang="ts">
/**
 * Stage drop-off (§9), as a bar funnel rather than a tapering cone.
 *
 * The bars carry the counts; the strip underneath carries what actually matters —
 * how much of the previous stage survived into this one. A funnel without that is
 * four numbers in descending order.
 */
const props = defineProps<{
  stages: { label: string; value: number; hint?: string }[]
  unit?: string
  summary: string
}>()

const { theme } = useChartTheme()

const rows = computed(() =>
  props.stages.map(s => ({ label: s.label, value: s.value, hint: s.hint, color: theme.value.ink2 })),
)

const drops = computed(() =>
  props.stages.slice(1).map((s, i) => {
    const previous = props.stages[i].value
    return {
      label: `${props.stages[i].label} → ${s.label}`,
      share: previous > 0 ? Math.round((s.value / previous) * 100) : null,
    }
  }),
)
</script>

<template>
  <div>
    <ChartBars :rows="rows" :unit="unit" :summary="summary" />
    <div class="drops">
      <span v-for="d in drops" :key="d.label" class="drop">
        {{ d.label }}
        <strong v-if="d.share !== null" class="mono tnum">{{ d.share }}%</strong>
        <strong v-else class="muted">—</strong>
      </span>
    </div>
  </div>
</template>

<style scoped>
.drops { display: flex; flex-wrap: wrap; gap: .25rem .9rem; margin-top: .5rem;
         padding-top: .5rem; border-top: 1px solid var(--rule); }
.drop { font-size: .71rem; color: var(--ink-muted); }
.drop strong { color: var(--ink-2); font-weight: 600; margin-left: .2rem; }
</style>
