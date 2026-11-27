<script setup lang="ts">
defineProps<{ severity: string; kev?: boolean }>()
</script>

<template>
  <span class="chip" :class="severity">
    {{ severity }}
    <span v-if="kev" class="kev" title="CISA Known Exploited Vulnerabilities catalogue">KEV</span>
  </span>
</template>

<style scoped>
.chip {
  display: inline-flex; align-items: center; gap: .35rem;
  font-size: .72rem; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
  padding: .18rem .45rem; border-radius: 4px; white-space: nowrap;
  background: var(--sev-bg); color: var(--sev-ink); border: 1px solid var(--sev-bg);
}
.critical { --sev-bg: var(--sev-critical); --sev-ink: var(--sev-on-dark); }
.high     { --sev-bg: var(--sev-high);     --sev-ink: var(--sev-on-dark); }
.medium   { --sev-bg: var(--sev-medium);   --sev-ink: var(--sev-on-dark); }
.low, .informational {
  --sev-bg: transparent; border-color: var(--rule) !important;
}
.low { --sev-ink: var(--ink-2); --swatch: var(--sev-low); }
.informational { --sev-ink: var(--ink-muted); --swatch: var(--sev-informational); }
.low::before, .informational::before {
  content: ""; width: .5rem; height: .5rem; border-radius: 2px; background: var(--swatch);
}
.unknown  { --sev-bg: transparent; --sev-ink: var(--ink-muted); border-color: var(--rule) !important; }
.kev {
  background: var(--sev-on-dark); color: var(--sev-critical);
  padding: 0 .25rem; border-radius: 3px; font-size: .65rem;
}
</style>
