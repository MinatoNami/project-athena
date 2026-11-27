<script setup lang="ts">
const props = defineProps<{
  rows: { label: string; value: number | null; color?: string; hint?: string; dashed?: boolean }[]
  unit?: string
  summary: string
}>()

const { theme, chrome } = useChartTheme()

const max = computed(() => Math.max(1, ...props.rows.map(r => r.value ?? 0)))
const height = computed(() => Math.max(90, props.rows.length * 30 + 16))

const gutter = computed(() => {
  const longest = Math.max(...props.rows.map(r =>
    (r.value === null ? (r.hint || 'not measured') : r.value.toLocaleString()).length,
  ))
  return Math.min(150, Math.max(40, longest * 7 + 12))
})

const option = computed(() => ({
  ...chrome.value,
  grid: { left: 0, right: gutter.value, top: 2, bottom: 2, containLabel: true },
  xAxis: { type: 'value', show: false, max: max.value },
  yAxis: {
    type: 'category',
    inverse: true,
    data: props.rows.map(r => r.label),
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: { color: theme.value.ink2, fontSize: 12.5, margin: 10 },
  },
  tooltip: {
    ...chrome.value.tooltip,
    trigger: 'item',
    formatter: (p: any) => {
      const row = props.rows[p.dataIndex]
      const value = row.value === null
        ? 'never measured'
        : `${row.value.toLocaleString()}${props.unit ? ` ${props.unit}` : ''}`
      const hint = row.hint ? `<br>${escapeHtml(row.hint)}` : ''
      return `<strong>${escapeHtml(row.label)}</strong><br>${escapeHtml(value)}${hint}`
    },
  },
  series: [{
    type: 'bar',
    barWidth: 11,
    barCategoryGap: '34%',
    data: props.rows.map(r => ({
      value: r.value ?? max.value,
      itemStyle: r.value === null || r.dashed
        ? {
            color: 'transparent',
            borderColor: r.color || theme.value.rule,
            borderWidth: 1,
            borderType: 'dashed',
            borderRadius: [0, 4, 4, 0],
          }
        : { color: r.color || theme.value.ink2, borderRadius: [0, 4, 4, 0] },
    })),
    label: {
      show: true,
      position: 'right',
      distance: 7,
      color: theme.value.ink2,
      fontSize: 11.5,
      formatter: ({ dataIndex }: any) => {
        const row = props.rows[dataIndex]
        return row.value === null ? (row.hint || 'not measured') : row.value.toLocaleString()
      },
    },
  }],
}))
</script>

<template>
  <ClientOnly>
    <LazyEChart :option="option" :height="height" :summary="summary" />
    <template #fallback><div class="skeleton" :style="{ height: `${height}px` }" /></template>
  </ClientOnly>
</template>
