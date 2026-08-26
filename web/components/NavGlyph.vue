<script setup lang="ts">
/** Stroke icons on a 24px grid — never emoji, which do not recolour or scale. */
defineProps<{ name: string }>()
</script>

<template>
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
       stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"
       class="glyph" aria-hidden="true">
    <template v-if="name === 'today'">
      <circle cx="12" cy="12" r="8.2" /><path d="M12 7.6V12l2.9 1.7" />
    </template>
    <template v-else-if="name === 'findings'">
      <path d="M4.5 5.5h15M4.5 12h15M4.5 18.5h15" />
    </template>
    <template v-else-if="name === 'assets'">
      <rect x="4.2" y="4.2" width="6.4" height="6.4" rx="1.4" />
      <rect x="13.4" y="4.2" width="6.4" height="6.4" rx="1.4" />
      <rect x="4.2" y="13.4" width="6.4" height="6.4" rx="1.4" />
      <rect x="13.4" y="13.4" width="6.4" height="6.4" rx="1.4" />
    </template>
    <template v-else-if="name === 'activity'">
      <path d="M3.5 12h4l2.5-6 4 12 2.5-6h4" />
    </template>
  </svg>
</template>

<style scoped>
.glyph { flex-shrink: 0; color: var(--ink-muted); }
.navitem.on .glyph { color: var(--ink); }
</style>
