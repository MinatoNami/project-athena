<script setup lang="ts">
/**
 * An SSVC outcome — Track, Track*, Attend, Act.
 *
 * Not severity-coloured on purpose: the red ramp belongs to risk bands (§8), and an
 * SSVC outcome is a recommended *response*, which is a different axis. Built on the
 * shared `.tag`, with tone carried by the word and the border weight, never by
 * colour alone. The meaning is in screen-reader text, not only in a tooltip.
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
  <!-- The text is the accessible name. An aria-label on a span with no role is
       ignored by screen readers, and with both children hidden they read nothing. -->
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
