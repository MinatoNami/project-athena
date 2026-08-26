<script setup lang="ts">
/** Placeholder rows shaped like the real ones, so the page does not jump on arrival. */
withDefaults(defineProps<{ rows?: number }>(), { rows: 4 })
const widths = ['58%', '74%', '44%', '66%', '52%', '70%']
</script>

<template>
  <div class="skels" aria-busy="true" aria-live="polite">
    <span class="sr">Loading…</span>
    <div v-for="i in rows" :key="i" class="skelrow">
      <span class="skeleton chip" />
      <span class="skeleton id" />
      <span class="skeleton text" :style="{ width: widths[i % widths.length] }" />
    </div>
  </div>
</template>

<style scoped>
.skels { display: flex; flex-direction: column; gap: .5rem; }
.skelrow {
  border: 1px solid var(--rule); border-radius: 9px; padding: .78rem .9rem;
  display: flex; gap: .7rem; align-items: center;
}
.chip { width: 62px; height: 17px; flex-shrink: 0; }
.id { width: 106px; height: 12px; flex-shrink: 0; }
.text { height: 12px; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
</style>
