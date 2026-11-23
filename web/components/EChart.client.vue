<script setup lang="ts">
/**
 * The chart library, isolated to one file.
 *
 * Client-only and lazily imported (§14 budget: the library is never part of the
 * initial payload), and only the pieces actually used are registered, so the
 * chunk carries bar rendering rather than all of ECharts.
 */
import { use } from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import VChart from 'vue-echarts'

use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])

defineProps<{
  option: Record<string, any>
  height: number
  /** Read aloud in place of the marks; the table view is the other fallback (§12). */
  summary: string
}>()
</script>

<template>
  <VChart
    class="chart"
    :option="option"
    :style="{ height: `${height}px` }"
    :aria-label="summary"
    role="img"
    autoresize
  />
</template>

<style scoped>
.chart { width: 100%; }
</style>
