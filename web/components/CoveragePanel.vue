<script setup lang="ts">
/** Coverage is reported as prominently as findings. A gap must never read as clean. */
defineProps<{
  coverage: {
    assets_total: number
    assets_fresh: number
    assets_stale: number
    assets_never_scanned: number
    coverage_ratio: number | null
    inconclusive_scans_24h: number
    never_scanned: Array<{ id: string; kind: string; display_name: string }>
  }
}>()
</script>

<template>
  <div class="card">
    <h2>Coverage</h2>
    <p v-if="!coverage.assets_total" class="muted">
      No assets registered yet. Nothing is being watched.
    </p>
    <template v-else>
      <div class="bar" role="img"
           :aria-label="`${coverage.assets_fresh} of ${coverage.assets_total} assets inventoried recently`">
        <span class="seg ok" :style="{ flex: coverage.assets_fresh || 0 }" />
        <span class="seg stale" :style="{ flex: coverage.assets_stale || 0 }" />
        <span class="seg never" :style="{ flex: coverage.assets_never_scanned || 0 }" />
      </div>
      <p class="legend">
        <strong>{{ coverage.assets_fresh }}</strong> of
        <strong>{{ coverage.assets_total }}</strong> assets inventoried recently
        <template v-if="coverage.assets_stale"> · <span class="stale-ink">{{ coverage.assets_stale }} stale</span></template>
        <template v-if="coverage.assets_never_scanned"> · <span class="never-ink">{{ coverage.assets_never_scanned }} never scanned</span></template>
      </p>
      <p v-if="coverage.inconclusive_scans_24h" class="muted">
        {{ coverage.inconclusive_scans_24h }} scan(s) failed or completed only partly in the
        last 24h. Those assets are reported as unknown, not clean.
      </p>
      <ul v-if="coverage.never_scanned.length" class="gaps">
        <li v-for="a in coverage.never_scanned.slice(0, 5)" :key="a.id">
          <NuxtLink :to="`/assets/${a.id}`">{{ a.display_name }}</NuxtLink>
          <span class="muted"> — {{ a.kind }}, contents unknown</span>
        </li>
      </ul>
    </template>
  </div>
</template>

<style scoped>
.bar { display: flex; height: .55rem; border-radius: 99px; overflow: hidden; background: var(--rule); gap: 2px; }
.seg { display: block; }
.seg.ok { background: var(--good); }
.seg.stale { background: var(--warn); }
.seg.never { background: var(--crit); }
.legend { margin: .7rem 0 .25rem; font-size: .9rem; }
.stale-ink { color: var(--warn-ink); }
.never-ink { color: var(--crit); font-weight: 600; }
.gaps { margin: .5rem 0 0; padding-left: 1.1rem; font-size: .88rem; }
</style>
