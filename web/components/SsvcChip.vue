<script setup lang="ts">
const props = defineProps<{ outcome: string | null | undefined; compact?: boolean }>()

const LABEL: Record<string, string> = {
  act: 'Act', attend: 'Attend', 'track*': 'Track*', track: 'Track',
}
const MEANING: Record<string, string> = {
  act: 'remediate immediately',
  attend: 'sooner than standard timelines',
  'track*': 'monitor closely, standard timelines',
  track: 'standard timelines',
}
const tone = computed(() =>
  props.outcome === 'act' ? 'bad strong' : props.outcome === 'attend' ? 'warn' : '',
)
</script>

<template>
  <span
    v-if="outcome" class="tag" :class="tone"
    :title="`SSVC ${LABEL[outcome] ?? outcome}: ${MEANING[outcome] ?? ''}`"
  >
    <span v-if="!compact" class="k">SSVC</span>
    <span v-else class="sr-only">SSVC</span>
    <span>{{ LABEL[outcome] ?? outcome }}</span>
    <span class="sr-only">: {{ MEANING[outcome] ?? '' }}</span>
  </span>
</template>

<style scoped>
.tag { font-weight: 600; }
.k { font-weight: 500; color: var(--ink-muted); letter-spacing: .03em; font-size: var(--fs-2xs); }
</style>
