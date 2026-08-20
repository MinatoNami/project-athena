<script setup lang="ts">
/**
 * Renders attacker-influenceable content as a text node.
 *
 * Advisory summaries, CVE details, package names, and commit messages are all
 * written by people Athena does not trust. This component exists so that is
 * explicit at every call site, and so no path can reach v-html.
 */
defineProps<{ text: string }>()
</script>

<template>
  <span>{{ text }}</span>
</template>
