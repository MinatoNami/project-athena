<script setup lang="ts">
import { use } from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import VChart from 'vue-echarts'

use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])

defineProps<{
  option: Record<string, any>
  height: number
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
