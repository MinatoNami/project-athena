<script setup lang="ts">
/**
 * An SSVC outcome — Track, Track*, Attend, Act.
 *
 * Not severity-coloured on purpose: the red ramp belongs to risk bands (§8), and an
 * SSVC outcome is a recommended *response*, which is a different axis. Built on the
 * shared `.tag`, with tone carried by the word and the border weight, never by
 * colour alone. The meaning is in the accessible name, not only in a tooltip.
 */
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
    :aria-label="`SSVC ${LABEL[outcome] ?? outcome} — ${MEANING[outcome] ?? ''}`"
  >
    <span v-if="!compact" class="k" aria-hidden="true">SSVC</span>
    <span aria-hidden="true">{{ LABEL[outcome] ?? outcome }}</span>
  </span>
</template>

<style scoped>
.tag { font-weight: 600; }
.k { font-weight: 500; color: var(--ink-muted); letter-spacing: .03em; font-size: var(--fs-2xs); }
</style>
