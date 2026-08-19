<script setup lang="ts">
const route = useRoute()
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data: asset, refresh } = await useAsyncData(`asset-${route.params.id}`, () =>
  api<any>(`assets/${route.params.id}`),
)
const scanning = ref(false)
useHead({ title: () => asset.value?.display_name || 'Asset' })

async function rescan() {
  scanning.value = true
  try {
    await api(`assets/${route.params.id}/scan`, { method: 'POST' })
  } finally {
    scanning.value = false
  }
}
useEvents(['assets'], refresh)

const statusClass = (s: string) => (s === 'succeeded' ? 'ok' : s === 'running' ? 'muted' : 'bad')
</script>

<template>
  <div v-if="asset" class="wrap">
    <NuxtLink to="/assets" class="muted">← Assets</NuxtLink>
    <h1>{{ asset.display_name }}</h1>
    <p class="sub">{{ asset.kind }} · <code>{{ asset.identity_key }}</code></p>

    <div class="card">
      <h2>Status</h2>
      <p>
        <FreshnessIndicator
          :at="asset.last_inventoried_at"
          :never-inventoried="asset.never_inventoried"
          :stale="asset.stale"
        />
      </p>
      <p v-if="asset.never_inventoried" class="warn-block">
        Athena has never successfully inventoried this asset. Its contents are
        <strong>unknown</strong> — this is not a clean result.
      </p>
      <p class="muted">
        tier {{ asset.tier }} · exposure {{ asset.exposure }} ·
        criticality {{ asset.criticality ?? 'unset' }}
        <span v-if="asset.criticality === null">(unset criticality deflates risk scoring)</span>
      </p>
      <button class="secondary" :disabled="scanning" @click="rescan">
        {{ scanning ? 'Queued…' : 'Rescan' }}
      </button>
    </div>

    <div v-if="asset.merge_candidates?.length" class="card">
      <h2>Possible duplicates</h2>
      <p class="muted">Flagged for review. Athena never merges assets automatically.</p>
      <ul>
        <li v-for="m in asset.merge_candidates" :key="m.id">
          {{ m.reason }} <span class="muted">(confidence {{ m.confidence }})</span>
        </li>
      </ul>
    </div>

    <div class="card">
      <h2>Scan history</h2>
      <table>
        <thead><tr><th>status</th><th>tool</th><th>started</th><th>detail</th></tr></thead>
        <tbody>
          <tr v-for="r in asset.scan_runs" :key="r.id">
            <td :class="statusClass(r.status)">{{ r.status }}</td>
            <td class="muted">{{ r.tool }} {{ r.tool_version || '' }}</td>
            <td class="muted">{{ new Date(r.started_at).toLocaleString() }}</td>
            <td class="muted small">
              <span v-if="r.error">{{ r.error }}</span>
              <span v-else-if="r.stats?.components != null">{{ r.stats.components }} components</span>
              <div v-if="r.stats?.notes?.length" class="note">{{ r.stats.notes.join('; ') }}</div>
            </td>
          </tr>
          <tr v-if="!asset.scan_runs?.length"><td colspan="4" class="muted">Never scanned.</td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Components ({{ asset.component_count }})</h2>
      <p v-if="asset.never_inventoried" class="muted">
        Not inventoried, so this list is unknown rather than empty.
      </p>
      <table v-else>
        <thead><tr><th>package</th><th>version</th><th>ecosystem</th><th>scope</th></tr></thead>
        <tbody>
          <tr v-for="c in asset.components" :key="c.id">
            <td>{{ c.name }}</td>
            <td>{{ c.version }}</td>
            <td class="muted">{{ c.ecosystem }}</td>
            <td class="muted">
              <span v-if="c.scope === 'unknown'"
                    title="The SBOM did not distinguish direct from transitive dependencies">
                unknown
              </span>
              <span v-else>{{ c.scope }}</span>
            </td>
          </tr>
          <tr v-if="!asset.components?.length"><td colspan="4" class="muted">No components found.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.ok { color: var(--good); font-weight: 500; }
.bad { color: var(--crit); font-weight: 600; }
.small { font-size: .82rem; max-width: 30rem; }
.note { color: var(--ink-muted); font-style: italic; margin-top: .2rem; }
.warn-block {
  background: var(--plane); border-left: 3px solid var(--crit);
  padding: .6rem .8rem; border-radius: 4px; font-size: .9rem;
}
</style>
