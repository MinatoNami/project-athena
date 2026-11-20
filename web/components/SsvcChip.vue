<script setup lang="ts">
/**
 * An SSVC outcome — Track, Track*, Attend, Act.
 *
 * Not severity-coloured on purpose: the red ramp belongs to risk bands (§8), and an
 * SSVC outcome is a recommended *response*, which is a different axis. Tone is
 * carried by the word and a border weight, never by colour alone.
 */
const props = defineProps<{ outcome: string | null | undefined; compact?: boolean }>()

const LABEL: Record<string, string> = {
  act: 'Act', attend: 'Attend', 'track*': 'Track*', track: 'Track',
}
const TITLE: Record<string, string> = {
  act: 'SSVC: act — remediate immediately',
  attend: 'SSVC: attend — sooner than standard timelines',
  'track*': 'SSVC: track closely — standard timelines',
  track: 'SSVC: track — standard timelines',
}
const tone = computed(() =>
  props.outcome === 'act' ? 'act' : props.outcome === 'attend' ? 'attend' : 'track',
)
</script>

<template>
  <span v-if="outcome" class="ssvc" :class="tone" :title="TITLE[outcome] ?? outcome">
    <span v-if="!compact" class="k">SSVC</span>{{ LABEL[outcome] ?? outcome }}
  </span>
</template>

<style scoped>
.ssvc {
  display: inline-flex; align-items: center; gap: .3rem; white-space: nowrap;
  font-size: .68rem; font-weight: 600; padding: .08rem .38rem; border-radius: 4px;
  border: 1px solid var(--rule); color: var(--ink-2); background: var(--plane);
}
.k { font-weight: 500; color: var(--ink-muted); letter-spacing: .03em; }
.ssvc.attend { border-color: var(--warn-ink); color: var(--warn-ink); }
.ssvc.act { border: 1.5px solid var(--crit); color: var(--crit); }
</style>
