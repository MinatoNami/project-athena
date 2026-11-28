<script setup lang="ts">
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
    <template v-else-if="name === 'metrics'">
      <path d="M4.5 19.5V10" /><path d="M10.2 19.5V4.5" />
      <path d="M15.8 19.5v-6" /><path d="M21 19.5V8" />
    </template>
    <template v-else-if="name === 'activity'">
      <path d="M3.5 12h4l2.5-6 4 12 2.5-6h4" />
    </template>
    <template v-else-if="name === 'code'">
      <rect x="5" y="10.5" width="14" height="9.5" rx="1.8" />
      <path d="M8.2 10.5V7.8a3.8 3.8 0 017.6 0v2.7" />
    </template>
    <template v-else-if="name === 'intel'">
      <path d="M4 18.5a8.5 8.5 0 0116 0" /><path d="M7.5 18.5a4.5 4.5 0 019 0" />
      <circle cx="12" cy="18.5" r="1" />
    </template>
    <template v-else-if="name === 'search'">
      <circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" />
    </template>
  </svg>
</template>

<style scoped>
.glyph { flex-shrink: 0; color: var(--ink-muted); }
.navitem.on .glyph { color: var(--ink); }
</style>
