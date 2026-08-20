<script setup lang="ts">
useHead({ title: 'Findings' })

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const kevOnly = ref(false)
const { data, refresh, pending } = await useAsyncData(
  'findings',
  () => api<any>(`findings?limit=100${kevOnly.value ? '&kev_only=true' : ''}`),
  { watch: [kevOnly] },
)
const { data: intel } = await useAsyncData('intel', () => api<any>('intel/sources'))

const expanded = ref<string | null>(null)
const refreshing = ref(false)

async function refreshIntel() {
  refreshing.value = true
  try {
    await api('intel/refresh', { method: 'POST' })
  } finally {
    refreshing.value = false
  }
}

useEvents(['findings'], refresh)

function ageLabel(seconds: number | null) {
  if (seconds === null) return 'never'
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`
  return `${Math.round(seconds / 86400)}d ago`
}
</script>

<template>
  <div class="wrap">
    <h1>Findings</h1>
    <p class="sub">Packages that match a published advisory. Grouped by vulnerability.</p>

    <!-- Stated up front, not buried. These are version matches, not assessed risk. -->
    <div class="caveat">
      <strong>Not yet investigated.</strong>
      {{ data?.caveat }}
    </div>

    <div v-if="intel" class="card">
      <h2>Vulnerability intelligence</h2>
      <p v-if="!intel.sources.length" class="muted">
        No intelligence has been fetched yet, so nothing can be matched.
        Findings are empty because Athena has not looked — not because you are clean.
      </p>
      <template v-else>
        <p>
          <strong>{{ intel.advisories.toLocaleString() }}</strong> advisories
          · <strong>{{ intel.kev_advisories.toLocaleString() }}</strong> known-exploited
        </p>
        <table>
          <thead><tr><th>source</th><th>last success</th><th>advisories</th><th></th></tr></thead>
          <tbody>
            <tr v-for="s in intel.sources" :key="s.name">
              <td><code>{{ s.name }}</code></td>
              <td :class="s.never_succeeded ? 'bad' : 'muted'">
                {{ ageLabel(s.age_seconds) }}
              </td>
              <td class="muted">{{ s.advisories }}</td>
              <td class="muted small">{{ s.last_error || '' }}</td>
            </tr>
          </tbody>
        </table>
      </template>
      <button class="secondary" style="margin-top:.9rem" :disabled="refreshing" @click="refreshIntel">
        {{ refreshing ? 'Queued…' : 'Refresh intelligence' }}
      </button>
    </div>

    <div class="card">
      <div class="head">
        <h2 style="margin:0">
          {{ data?.group_count ?? 0 }} vulnerabilities
        </h2>
        <label class="toggle">
          <input v-model="kevOnly" type="checkbox">
          Known-exploited only
        </label>
      </div>

      <p v-if="data?.coverage" class="muted denom">
        Across {{ data.coverage.of_assets_observed }} of
        {{ data.coverage.of_assets_total }} registered assets.
        <span v-if="data.coverage.of_assets_observed < data.coverage.of_assets_total">
          Assets Athena has not inventoried cannot appear here.
        </span>
      </p>

      <p v-if="!pending && !(data?.groups ?? []).length" class="muted">
        No matches. If intelligence has been fetched and assets inventoried, that is a
        real result — otherwise it means Athena has not looked yet.
      </p>

      <div v-for="g in data?.groups ?? []" :key="g.group_key" class="finding">
        <div class="row" @click="expanded = expanded === g.group_key ? null : g.group_key">
          <SeverityChip :severity="g.provisional_severity" :kev="g.kev" />
          <code class="cve">{{ g.vulnerability_id }}</code>
          <span class="count">{{ g.instance_count }}
            {{ g.instance_count === 1 ? 'asset' : 'assets' }}</span>
          <span class="summary">{{ g.summary || '—' }}</span>
          <span class="chev">{{ expanded === g.group_key ? '▾' : '▸' }}</span>
        </div>

        <div v-if="expanded === g.group_key" class="detail">
          <p class="muted small">
            <template v-if="g.cvss_score">CVSS {{ g.cvss_score }} · </template>
            <template v-if="g.epss_score">EPSS {{ (g.epss_score * 100).toFixed(1) }}% · </template>
            <template v-if="g.kev_ransomware">used in ransomware campaigns · </template>
            published {{ g.published_at ? new Date(g.published_at).toLocaleDateString() : 'unknown' }}
          </p>
          <table>
            <thead>
              <tr><th>asset</th><th>component</th><th>fixed in</th><th>match</th></tr>
            </thead>
            <tbody>
              <tr v-for="i in g.instances" :key="i.finding_id">
                <td>
                  <NuxtLink :to="`/findings/${i.finding_id}`">{{ i.asset }}</NuxtLink>
                  <span class="muted"> · {{ i.tier }}</span>
                </td>
                <td><code>{{ i.component }}</code></td>
                <td>{{ i.fixed_version || '—' }}</td>
                <td class="muted small">
                  {{ i.match_method }}
                  <span :title="'How the match was made, not whether it is exploitable here'">
                    ({{ (i.match_confidence * 100).toFixed(0) }}%)
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.caveat {
  border-left: 3px solid var(--warn); background: var(--surface);
  padding: .7rem .9rem; border-radius: 4px; font-size: .88rem; margin-bottom: 1rem;
  color: var(--ink-2);
}
.head { display: flex; justify-content: space-between; align-items: center; margin-bottom: .5rem; }
.toggle { display: flex; gap: .4rem; align-items: center; font-size: .85rem; margin: 0; }
.toggle input { width: auto; }
.denom { margin: 0 0 1rem; font-size: .85rem; }
.finding { border-top: 1px solid var(--rule); }
.row {
  display: grid; grid-template-columns: 7.5rem 10rem 5.5rem 1fr 1rem;
  gap: .7rem; align-items: center; padding: .6rem .1rem; cursor: pointer;
}
.row:hover { background: var(--plane); }
.cve { font-size: .85rem; }
.count { font-size: .8rem; color: var(--ink-muted); }
.summary { font-size: .87rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chev { color: var(--ink-muted); }
.detail { padding: .2rem .1rem 1rem; }
.small { font-size: .8rem; }
.bad { color: var(--crit); font-weight: 600; }
</style>
