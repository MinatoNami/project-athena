<script setup lang="ts">
/**
 * Severity as a single-hue ordinal ramp: lightness carries the signal, so the bands
 * stay distinguishable under any colour vision deficiency. Always chip + label,
 * never colour alone.
 *
 * Named "provisional" throughout because before M3 this is the advisory's own view
 * with no environmental context — not assessed risk.
 */
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
.low      { --sev-bg: transparent; --sev-ink: var(--ink-2); border-color: var(--rule) !important; }
.unknown  { --sev-bg: transparent; --sev-ink: var(--ink-muted); border-color: var(--rule) !important; }
.kev {
  background: var(--sev-on-dark); color: var(--sev-critical);
  padding: 0 .25rem; border-radius: 3px; font-size: .65rem;
}
</style>
