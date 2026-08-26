<script setup lang="ts">
/**
 * Empty, unlooked-at, clean and error states.
 *
 * The distinction this component exists to hold: `kind="never"` means nothing has
 * been checked, `kind="clean"` means something was checked and found nothing. Most
 * security tools render both as an empty list, which turns a blind spot into a
 * false all-clear. Here they get different marks — hatched versus a tick — and
 * `clean` is required to carry its denominators.
 */
defineProps<{
  kind: 'never' | 'clean' | 'empty' | 'error'
  title: string
  stats?: { value: string; label: string }[]
}>()
</script>

<template>
  <div class="state">
    <span class="mark" :class="kind">
      <svg v-if="kind === 'clean'" width="21" height="21" viewBox="0 0 24 24" fill="none"
           stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M5 12.5l4.5 4.5L19 7.5" />
      </svg>
      <svg v-else-if="kind === 'error'" width="21" height="21" viewBox="0 0 24 24" fill="none"
           stroke="currentColor" stroke-width="1.9" stroke-linecap="round">
        <circle cx="12" cy="12" r="9" /><path d="M12 7.5v5.5" /><path d="M12 16.4v.01" />
      </svg>
    </span>

    <div class="title">{{ title }}</div>
    <p class="body"><slot /></p>

    <!-- The denominators are the claim. Without them "nothing needs you" is just a
         green tick, which is the shape of reassurance this product refuses to give. -->
    <div v-if="stats?.length" class="stats">
      <div v-for="s in stats" :key="s.label" class="stat">
        <span class="mono tnum value">{{ s.value }}</span>
        <span class="label">{{ s.label }}</span>
      </div>
    </div>

    <div v-if="$slots.actions" class="acts"><slot name="actions" /></div>
  </div>
</template>

<style scoped>
.state {
  display: flex; flex-direction: column; align-items: center; gap: .7rem;
  text-align: center; padding: 2.6rem 1.5rem;
}
.mark {
  width: 46px; height: 46px; border-radius: 10px; display: flex;
  align-items: center; justify-content: center; border: 1px solid var(--rule);
  background: var(--plane); margin-bottom: .1rem;
}
.mark.never, .mark.empty {
  border-style: dashed;
  background: repeating-linear-gradient(45deg, transparent, transparent 4px,
              var(--never-hatch) 4px, var(--never-hatch) 5px);
}
.mark.clean { color: var(--good); }
.mark.error { color: var(--crit); }
.title { font-size: 1.05rem; font-weight: 640; letter-spacing: -0.01em; }
.body { margin: 0; font-size: .87rem; line-height: 1.6; color: var(--ink-2); max-width: 48ch; }
.stats {
  display: flex; gap: 1.4rem; margin-top: .4rem;
  padding-top: .8rem; border-top: 1px solid var(--rule);
}
.stat { display: flex; flex-direction: column; gap: .1rem; }
.value { font-size: .95rem; font-weight: 600; }
.label { font-size: .7rem; color: var(--ink-muted); }
.acts { display: flex; gap: .55rem; margin-top: .25rem; }
</style>
