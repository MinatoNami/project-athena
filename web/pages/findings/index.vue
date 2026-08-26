<script setup lang="ts">
/**
 * Findings, grouped by vulnerability.
 *
 * Filtering, sorting and paging are the server's job now. They used to happen in the
 * browser over whatever the API returned, which meant the counts beside each facet
 * described the page rather than the estate, and the page was itself an arbitrary
 * slice once the estate outgrew it.
 *
 * Each facet shows two numbers when they differ: how many survive the current
 * filters, and how many exist at all. A count that silently means "of what you can
 * currently see" is how a filtered view comes to read as a complete one.
 */
useHead({ title: 'Findings' })

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const includeNoFix = ref(false)
const query = ref('')
const debounced = ref('')
const facets = ref<string[]>([])
const sort = ref<'risk' | 'spread' | 'recent'>('risk')
const expanded = ref<string | null>(null)
const refreshing = ref(false)
const pages = ref<any[]>([])
const cursor = ref<string | null>(null)
const loadingMore = ref(false)

let debounceTimer: ReturnType<typeof setTimeout> | undefined
watch(query, value => {
  clearTimeout(debounceTimer)
  debounceTimer = setTimeout(() => (debounced.value = value), 250)
})

/** Facet id → the query parameter it sets. Kept in one place so the chips, the
    request and the counts cannot drift apart. */
const FACET_PARAM: Record<string, string> = {
  assessed: 'assessed=true',
  unassessed: 'assessed=false',
  kev: 'kev_only=true',
  has_fix: 'has_fix=true',
  no_fix: 'has_fix=false',
  'exposure:internet': 'exposure=internet',
}

const params = computed(() => {
  const parts = [`limit=50`, `sort=${sort.value}`]
  if (includeNoFix.value) parts.push('include_no_fix=true')
  if (debounced.value.trim()) parts.push(`q=${encodeURIComponent(debounced.value.trim())}`)
  for (const id of facets.value) if (FACET_PARAM[id]) parts.push(FACET_PARAM[id])
  return parts.join('&')
})

const { data, pending, error, refresh } = await useAsyncData(
  'findings',
  () => api<any>(`findings?${params.value}`),
  { watch: [params] },
)
const { data: intel, refresh: refreshIntelData } = await useAsyncData('intel', () =>
  api<any>('intel/sources'),
)

// A new filter set is a new list, not more of the old one. `immediate` matters:
// the first payload arrives with the server-rendered page, before this watcher
// exists, so without it the list stayed empty while the header counted 137.
watch(data, value => {
  pages.value = value?.groups ?? []
  cursor.value = value?.next_cursor ?? null
  expanded.value = null
}, { immediate: true })

useEvents(['findings'], refresh)

async function loadMore() {
  if (!cursor.value || loadingMore.value) return
  loadingMore.value = true
  try {
    const next = await api<any>(`findings?${params.value}&cursor=${encodeURIComponent(cursor.value)}`)
    pages.value = [...pages.value, ...(next.groups ?? [])]
    cursor.value = next.next_cursor ?? null
  } finally {
    loadingMore.value = false
  }
}

async function refreshIntel() {
  refreshing.value = true
  try {
    await api('intel/refresh', { method: 'POST' })
    await refreshIntelData()
  } finally {
    refreshing.value = false
  }
}

const shown = computed(() => pages.value)

function facetCount(id: string) {
  return data.value?.facets?.[id] ?? { total: 0, matching: 0 }
}

const facetGroups = computed(() => [
  {
    label: 'Assessment',
    options: [
      { id: 'assessed', label: 'Investigated' },
      { id: 'unassessed', label: 'Not yet looked at' },
    ],
  },
  {
    label: 'Exploitation',
    options: [
      { id: 'kev', label: 'Known-exploited' },
      { id: 'exposure:internet', label: 'Internet-facing' },
    ],
  },
  {
    label: 'Fix',
    options: [
      { id: 'has_fix', label: 'Fix published' },
      { id: 'no_fix', label: 'No fix yet' },
    ],
  },
])

function toggle(id: string) {
  // Opposing facets are mutually exclusive: holding both asks for nothing.
  const opposite: Record<string, string> = {
    assessed: 'unassessed', unassessed: 'assessed', has_fix: 'no_fix', no_fix: 'has_fix',
  }
  const at = facets.value.indexOf(id)
  if (at !== -1) {
    facets.value.splice(at, 1)
    return
  }
  const other = facets.value.indexOf(opposite[id] ?? '')
  if (other !== -1) facets.value.splice(other, 1)
  facets.value.push(id)
}

function clearAll() {
  facets.value = []
  query.value = ''
  debounced.value = ''
}

function ageLabel(seconds: number | null) {
  if (seconds === null) return 'never'
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`
  return `${Math.round(seconds / 86400)}d ago`
}

/** Near-identical assets collapse: eight tags of one image are one decision. */
function instanceLines(g: any) {
  const families = new Map<string, any[]>()
  for (const i of g.instances ?? []) {
    const family = String(i.asset).replace(/[@:][^@:]*$/, '')
    if (!families.has(family)) families.set(family, [])
    families.get(family)!.push(i)
  }
  return [...families.entries()].map(([family, members]) => ({
    key: family,
    first: members[0],
    members,
    label: members.length > 1 ? `${family} · ${members.length} tags` : members[0].asset,
  }))
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Findings</h1>
        <p>
          Grouped by vulnerability. One row is one thing to decide about, however many
          assets carry it.
        </p>
      </div>
      <div class="actions">
        <button class="btn" :disabled="refreshing" @click="refreshIntel">
          {{ refreshing ? 'Queued…' : 'Refresh intelligence' }}
        </button>
      </div>
    </div>

    <!-- The two populations, stated once and compactly rather than as a wall of text. -->
    <div v-if="data" class="mix">
      <strong>{{ (data.assessed_count ?? 0).toLocaleString() }}</strong> of
      <strong>{{ (data.instance_count ?? 0).toLocaleString() }}</strong> findings have been
      investigated on the asset that carries them. The rest are version matches only —
      nothing has checked whether they run, are reachable, or are exploitable here.
    </div>

    <div v-if="intel && !intel.sources.length" class="mix warn">
      <strong>No intelligence has been fetched.</strong>
      Nothing can be matched, so this list is empty because Athena has not looked — not
      because you are clean.
    </div>

    <div class="cols">
      <aside class="facets">
        <input v-model="query" class="search" type="search" placeholder="Search CVE or summary…">

        <div v-for="fg in facetGroups" :key="fg.label" class="fgroup">
          <div class="lbl">{{ fg.label }}</div>
          <button
            v-for="o in fg.options" :key="o.id" class="facet"
            :class="{ on: facets.includes(o.id) }" :aria-pressed="facets.includes(o.id)"
            :title="`${facetCount(o.id).matching} of ${facetCount(o.id).total} match the current filters`"
            @click="toggle(o.id)"
          >
            <span class="box">{{ facets.includes(o.id) ? '✓' : '' }}</span>
            <span class="fname">{{ o.label }}</span>
            <span class="mono tnum fn">
              {{ facetCount(o.id).matching }}<span
                v-if="facetCount(o.id).matching !== facetCount(o.id).total"
                class="denom">/{{ facetCount(o.id).total }}</span>
            </span>
          </button>
        </div>

        <label class="fgroup toggle">
          <input v-model="includeNoFix" type="checkbox">
          <span>
            Include {{ (data?.no_fix_available_count ?? 0).toLocaleString() }} with no
            published fix
          </span>
        </label>

        <div v-if="intel?.sources?.length" class="fgroup sources">
          <div class="lbl">Sources</div>
          <div v-for="s in intel.sources" :key="s.name" class="source">
            <code>{{ s.name }}</code>
            <span :class="s.never_succeeded ? 'bad' : 'muted'">{{ ageLabel(s.age_seconds) }}</span>
          </div>
        </div>
      </aside>

      <section class="results">
        <div class="resulthead">
          <span class="n">
            {{ (data?.matching_group_count ?? 0).toLocaleString() }}
            {{ data?.matching_group_count === 1 ? 'vulnerability' : 'vulnerabilities' }}
          </span>
          <span class="of">
            {{ data && data.matching_group_count === data.group_count
              ? 'no filters applied'
              : `of ${(data?.group_count ?? 0).toLocaleString()}` }}
          </span>
          <div class="seg">
            <button :class="{ on: sort === 'risk' }" @click="sort = 'risk'">Risk</button>
            <button :class="{ on: sort === 'spread' }" @click="sort = 'spread'">Spread</button>
            <button :class="{ on: sort === 'recent' }" @click="sort = 'recent'">Newest</button>
          </div>
        </div>

        <RowSkeleton v-if="pending" :rows="6" />

        <StateBlock v-else-if="error" kind="error" title="Cannot reach Athena">
          The dashboard is running but the core service did not answer.
          <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
        </StateBlock>

        <StateBlock
          v-else-if="!data?.group_count" kind="never" title="Athena has not looked yet"
        >
          No advisories have been matched against your inventory. This list is empty
          because nothing has been checked — <strong>not because you are clean</strong>.
        </StateBlock>

        <StateBlock
          v-else-if="!shown.length" kind="empty" title="Nothing matches those filters"
        >
          That is a statement about the filters, not about your estate.
          {{ (data?.group_count ?? 0).toLocaleString() }} vulnerabilities are still here
          with them cleared.
          <template #actions><button class="btn" @click="clearAll">Clear filters</button></template>
        </StateBlock>

        <div
          v-for="g in shown" :key="g.group_key" :id="g.vulnerability_id" class="group"
        >
          <div
            class="grow" role="button" tabindex="0"
            @click="expanded = expanded === g.group_key ? null : g.group_key"
            @keydown.enter="expanded = expanded === g.group_key ? null : g.group_key"
          >
            <SeverityChip v-if="g.worst_band" :severity="g.worst_band" :kev="g.kev" />
            <span v-else class="unassessed" title="Version match only — not investigated">
              unassessed
              <span v-if="g.kev" class="kevflag">KEV</span>
            </span>
            <code class="cve">{{ g.vulnerability_id }}</code>
            <span class="summary">{{ g.summary || '—' }}</span>
            <span class="spread">
              {{ g.instance_count }} {{ g.instance_count === 1 ? 'asset' : 'assets' }}
              <template v-if="g.investigated_count">· {{ g.investigated_count }} assessed</template>
            </span>
            <span class="chev">{{ expanded === g.group_key ? '▾' : '▸' }}</span>
          </div>

          <div v-if="expanded === g.group_key" class="detail">
            <div class="facts">
              <span v-if="g.cvss_score">CVSS {{ g.cvss_score }}</span>
              <span v-if="g.epss_score != null">EPSS {{ (g.epss_score * 100).toFixed(1) }}%</span>
              <span v-else class="gap">EPSS not published — unrated, not harmless</span>
              <span v-if="g.kev_ransomware" class="bad">used in ransomware campaigns</span>
              <span v-if="g.published_at">
                published {{ new Date(g.published_at).toLocaleDateString() }}
              </span>
            </div>

            <table>
              <thead>
                <tr><th>Asset</th><th>Component</th><th>Fixed in</th><th>Assessment</th></tr>
              </thead>
              <tbody>
                <tr v-for="line in instanceLines(g)" :key="line.key">
                  <td>
                    <NuxtLink :to="`/findings/${line.first.finding_id}`">{{ line.label }}</NuxtLink>
                    <span class="muted"> · {{ line.first.tier }}</span>
                  </td>
                  <td><code>{{ line.first.component }}</code></td>
                  <td>
                    {{ line.first.fixed_version || '—' }}
                    <span
                      v-if="line.first.fix_channel && line.first.fix_channel !== 'standard'"
                      class="channel"
                      :title="`Delivered through ${line.first.fix_channel.toUpperCase()} — needs an entitlement`"
                    >{{ line.first.fix_channel }}</span>
                  </td>
                  <td class="assess">
                    <template v-if="line.first.investigated">
                      <SeverityChip :severity="line.first.risk_band" />
                      <span class="muted mono tnum"> {{ line.first.risk_score }}/100</span>
                    </template>
                    <template v-else-if="line.first.triage_disposition === 'deprioritise'">
                      <span class="muted" :title="line.first.triage_reason">
                        lower priority · not investigated
                      </span>
                    </template>
                    <template v-else>
                      <span class="muted">not investigated</span>
                    </template>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div v-if="cursor" class="more">
          <button class="btn" :disabled="loadingMore" @click="loadMore">
            {{ loadingMore ? 'Loading…' : 'Load more' }}
          </button>
          <span class="moremeta">
            Showing {{ shown.length.toLocaleString() }} of
            {{ (data?.matching_group_count ?? 0).toLocaleString() }}
          </span>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.mix {
  border: 1px solid var(--rule); border-left: 3px solid var(--rule);
  border-radius: 7px; background: var(--surface); padding: .6rem .8rem;
  font-size: .8rem; line-height: 1.5; color: var(--ink-2); margin-bottom: .8rem;
}
.mix.warn { border-left-color: var(--warn); }
.mix strong { color: var(--ink); font-weight: 600; }

.cols { display: flex; gap: 1.1rem; align-items: flex-start; }
.facets { width: 214px; flex-shrink: 0; display: flex; flex-direction: column; gap: 1rem; }
.search {
  width: 100%; font: inherit; font-size: .82rem; padding: .45rem .6rem;
  border-radius: 8px; border: 1px solid var(--rule);
  background: var(--surface); color: var(--ink);
}
.fgroup { display: flex; flex-direction: column; gap: 2px; }
.fgroup .lbl { padding: 0 .5rem .25rem; }
.facet {
  display: flex; align-items: center; gap: .5rem; padding: .28rem .5rem;
  border-radius: 6px; border: 0; background: transparent; cursor: pointer;
  font: inherit; font-size: .79rem; color: var(--ink-2); text-align: left; width: 100%;
}
.facet:hover { background: var(--plane); color: var(--ink); }
.facet.on { background: var(--plane); color: var(--ink); font-weight: 560; }
.box {
  width: 13px; height: 13px; border-radius: 3px; border: 1px solid var(--rule);
  flex-shrink: 0; display: flex; align-items: center; justify-content: center; font-size: .6rem;
}
.facet.on .box { background: var(--ink); border-color: var(--ink); color: var(--surface); }
.fname { flex-grow: 1; }
.fn { font-size: .7rem; color: var(--ink-muted); }
.denom { opacity: .6; }
.more { padding: .7rem .85rem; border-top: 1px solid var(--rule);
        display: flex; align-items: center; gap: .8rem; }
.moremeta { font-size: .74rem; color: var(--ink-muted); }
.toggle { flex-direction: row; align-items: flex-start; gap: .45rem; font-size: .76rem;
          color: var(--ink-2); padding: 0 .5rem; margin: 0; line-height: 1.4; }
.toggle input { width: auto; margin-top: .15rem; }
.sources .source { display: flex; justify-content: space-between; gap: .5rem;
                   padding: .18rem .5rem; font-size: .72rem; }
.sources code { font-size: .72rem; }

.results {
  flex-grow: 1; min-width: 0; border: 1px solid var(--rule); border-radius: 10px;
  background: var(--surface); overflow: hidden;
}
.resulthead {
  padding: .6rem .85rem; display: flex; align-items: center; gap: .7rem;
  border-bottom: 1px solid var(--rule);
}
.resulthead .n { font-size: .82rem; font-weight: 600; }
.resulthead .of { font-size: .76rem; color: var(--ink-muted); }
.resulthead .seg { margin-left: auto; }

.group { border-top: 1px solid var(--rule); }
.group:first-of-type { border-top: 0; }
.grow {
  display: grid; grid-template-columns: 6.6rem 8.6rem 1fr 10rem 1rem;
  gap: .7rem; align-items: center; padding: .55rem .85rem; cursor: pointer;
}
.grow:hover { background: var(--plane); }
.cve { font-size: .79rem; font-weight: 600; }
.summary { font-size: .8rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.spread { font-size: .73rem; color: var(--ink-muted); text-align: right; }
.chev { color: var(--ink-muted); font-size: .7rem; }
.detail { padding: .1rem .85rem 1rem; background: var(--plane); }
.facts { display: flex; gap: .9rem; flex-wrap: wrap; font-size: .74rem;
         color: var(--ink-muted); padding: .5rem 0 .6rem; }
.facts .gap { color: var(--warn-ink); }
.facts .bad { color: var(--crit); font-weight: 600; }
.assess { white-space: nowrap; }
.channel {
  font-size: .62rem; text-transform: uppercase; letter-spacing: .04em;
  border: 1px solid var(--rule); border-radius: 3px; padding: 0 .22rem;
  color: var(--warn-ink); margin-left: .25rem;
}
.bad { color: var(--crit); font-weight: 600; }
.unassessed {
  font-size: .66rem; text-transform: uppercase; letter-spacing: .04em; color: var(--ink-muted);
  border: 1px dashed var(--rule); border-radius: 4px; padding: .15rem .38rem;
  white-space: nowrap; justify-self: start;
}
.kevflag { background: var(--sev-critical); color: var(--sev-on-dark);
           padding: 0 .22rem; border-radius: 3px; margin-left: .22rem; }

@media (max-width: 1000px) {
  .cols { flex-direction: column; }
  .facets { width: 100%; flex-direction: row; flex-wrap: wrap; gap: 1.2rem; }
  .grow { grid-template-columns: 6.6rem 1fr 1rem; }
  .summary, .spread { display: none; }
}
</style>
