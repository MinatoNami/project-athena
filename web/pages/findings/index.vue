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
const includeBaseline = ref(false)
const query = ref('')
const debounced = ref('')
const facets = ref<string[]>([])
const includeSuppressed = ref(false)
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
  malicious: 'malicious=true',
  has_fix: 'has_fix=true',
  no_fix: 'has_fix=false',
  'exposure:internet': 'exposure=internet',
}

const params = computed(() => {
  const parts = [`limit=50`, `sort=${sort.value}`]
  if (includeNoFix.value) parts.push('include_no_fix=true')
  if (includeBaseline.value) parts.push('include_baseline=true')
  if (includeSuppressed.value) parts.push('include_suppressed=true')
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

const exportingVex = ref(false)
const exportNote = ref<string | null>(null)
async function exportVex() {
  exportingVex.value = true
  exportNote.value = null
  try {
    await downloadJson('export/openvex', 'athena.openvex.json')
  } catch (e: any) {
    exportNote.value = e?.data?.detail || 'The VEX document could not be produced.'
  } finally {
    exportingVex.value = false
  }
}

/** The benchmark date, in words relative to today. */
function dueLabel(i: any) {
  if (i.due_on_upgrade) return 'next upgrade'
  return dueText(i.due)
}

/** The group's most urgent SSVC outcome and soonest deadline, for the collapsed row:
    a reader scanning the list should not have to open every row to find the
    overdue one. Malware is left out of both — it is removed now, not scheduled. */
const SSVC_RANK: Record<string, number> = { track: 0, 'track*': 1, attend: 2, act: 3 }
function worstSsvc(g: any): string | null {
  if (g.malicious) return null
  let best: string | null = null
  for (const i of g.instances ?? []) {
    if (i.ssvc && (best === null || (SSVC_RANK[i.ssvc] ?? -1) > (SSVC_RANK[best] ?? -1))) best = i.ssvc
  }
  return best
}
function earliestDue(g: any): any | null {
  if (g.malicious) return null
  const dated = (g.instances ?? []).filter((i: any) => i.due)
  if (dated.length) return dated.reduce((a: any, b: any) => (a.due <= b.due ? a : b))
  return (g.instances ?? []).find((i: any) => i.due_on_upgrade) ?? null
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
      { id: 'malicious', label: 'Malicious package' },
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

const { severity } = useChartTheme()

/**
 * The shape of what the current filters actually select.
 *
 * Read from `matching` rather than from the loaded rows: the list is paged, so
 * counting what is on screen would draw the first fifty and call it the estate.
 * Unassessed groups have no band at all and are stated in the caption instead of
 * being folded into the mildest one.
 */
const bands = computed(() =>
  (['critical', 'high', 'medium', 'low', 'informational'] as const)
    .map(name => ({
      label: name,
      value: facetCount(`band:${name}`).matching,
      color: severity.value[name],
    }))
    .filter(r => r.value > 0),
)

const unbanded = computed(() => facetCount('band:unassessed').matching)

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
        <button class="btn" :disabled="exportingVex" @click="exportVex"
                title="OpenVEX for every finding: not_affected only where a person decided it">
          {{ exportingVex ? 'Exporting…' : 'Export VEX' }}
        </button>
        <button class="btn" :disabled="refreshing" @click="refreshIntel">
          {{ refreshing ? 'Queued…' : 'Refresh intelligence' }}
        </button>
      </div>
    </div>

    <p v-if="exportNote" class="err">{{ exportNote }}</p>

    <!-- The two populations, as figures rather than a paragraph. The caveat stays:
         an un-investigated finding is a version match, not a confirmed one. -->
    <div v-if="data" class="statstrip">
      <StatTile
        label="Investigated"
        :value="(data.assessed_count ?? 0).toLocaleString()"
        :of="`of ${(data.instance_count ?? 0).toLocaleString()} findings`"
        :progress="data.instance_count ? data.assessed_count / data.instance_count : null"
        hint="the rest are version matches only"
      />
      <StatTile
        label="Known-exploited"
        :value="facetCount('kev').matching"
        :of="`of ${facetCount('kev').total} in the estate`"
        :status="facetCount('kev').matching ? 'bad' : null"
      />
      <StatTile
        v-if="facetCount('malicious').total"
        label="Malicious packages"
        :value="facetCount('malicious').matching"
        :of="`of ${facetCount('malicious').total} in the estate`"
        status="bad"
      />
      <!-- Findings with no published fix are left out of this list unless asked for,
           so the facet over the list counted almost nothing (mostly malware, which
           has no version to wait for). The API's own count is the real figure. -->
      <StatTile
        label="No fix published"
        :value="includeNoFix ? facetCount('no_fix').matching : (data?.no_fix_available_count ?? null)"
        :of="includeNoFix ? 'clock has not started' : 'held out of this list · clock has not started'"
      />
      <p class="caveat">
        A finding nobody has investigated is a version match — nothing has checked
        whether it runs, is reachable, or is exploitable here.
      </p>
    </div>

    <ChartFrame
      v-if="data"
      title="Worst band reached"
      :note="unbanded
        ? `${unbanded.toLocaleString()} more match but have no band — nothing has assessed them`
        : 'across everything the current filters select'"
      :empty="!bands.length"
      :empty-text="unbanded
        ? `All ${unbanded.toLocaleString()} matching groups are unassessed, so none has a band yet.`
        : 'Nothing matches the current filters.'"
      :table="{ columns: ['Band', 'Groups'], rows: bands.map(b => [b.label, b.value]) }"
      class="distribution"
    >
      <ChartBars :rows="bands" unit="groups" summary="Matching finding groups by worst band" />
    </ChartFrame>

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

        <label v-if="data?.baseline_group_count" class="fgroup toggle">
          <input v-model="includeBaseline" type="checkbox">
          <span>
            Include {{ data.baseline_group_count.toLocaleString() }} pre-existing
            <span class="subtle">— the backlog you started from</span>
          </span>
        </label>

        <label v-if="data?.suppressed_group_count" class="fgroup toggle">
          <input v-model="includeSuppressed" type="checkbox">
          <span>
            Include {{ data.suppressed_group_count.toLocaleString() }} you stopped showing
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
            <button :class="{ on: sort === 'risk' }" :aria-pressed="sort === 'risk'" @click="sort = 'risk'">Risk</button>
            <button :class="{ on: sort === 'spread' }" :aria-pressed="sort === 'spread'" @click="sort = 'spread'">Spread</button>
            <button :class="{ on: sort === 'recent' }" :aria-pressed="sort === 'recent'" @click="sort = 'recent'">Newest</button>
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
            :aria-expanded="expanded === g.group_key"
            @click="expanded = expanded === g.group_key ? null : g.group_key"
            @keydown.enter.prevent="expanded = expanded === g.group_key ? null : g.group_key"
            @keydown.space.prevent="expanded = expanded === g.group_key ? null : g.group_key"
          >
            <SeverityChip v-if="g.worst_band" :severity="g.worst_band" :kev="g.kev" />
            <span v-else class="unassessed" title="Version match only — not investigated">
              unassessed
              <span v-if="g.kev" class="kevflag">KEV</span>
            </span>
            <!-- One grid cell: the row is a fixed five-column grid, and a sixth child
                 would push every later cell one column over. -->
            <span class="idcell">
              <code class="cve">{{ g.vulnerability_id }}</code>
              <span v-if="g.malicious" class="tag bad strong caps">malware</span>
            </span>
            <span class="summary"><UntrustedText :text="g.summary || '—'" /></span>
            <span class="gssvc"><SsvcChip :outcome="worstSsvc(g)" compact /></span>
            <span
              class="gdue" :class="{ overdue: (dueLabel(earliestDue(g) ?? {}) ?? '').startsWith('overdue') }"
            >{{ earliestDue(g) ? dueLabel(earliestDue(g)) : '' }}</span>
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
              <span v-if="g.epss_percentile != null">
                {{ ordinal(Math.round(g.epss_percentile * 100)) }} EPSS percentile
              </span>
              <span v-if="g.kev_due_date">CISA due {{ g.kev_due_date }}</span>
              <span v-if="g.published_at">
                published {{ new Date(g.published_at).toLocaleDateString() }}
              </span>
            </div>

            <table>
              <thead>
                <tr>
                  <th>Asset</th><th>Component</th><th>Fixed in</th><th>Assessment</th>
                  <th title="CISA SSVC outcome for this asset">SSVC</th>
                  <th title="CISA BOD 26-04 deadline, as a benchmark">Due</th>
                </tr>
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
                  <td><SsvcChip v-if="!g.malicious" :outcome="line.first.ssvc" compact /></td>
                  <td class="due" :class="{ overdue: dueLabel(line.first)?.startsWith('overdue') }">
                    {{ dueLabel(line.first) ?? '—' }}
                    <span v-if="line.first.forensic_triage" class="tag bad caps"
                          title="Check for prior compromise, not only the patch">+ triage</span>
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
.idcell { display: flex; flex-direction: column; align-items: flex-start; gap: .15rem; min-width: 0; }
.due { white-space: nowrap; font-size: .76rem; color: var(--ink-2); }
/* Not `.summary`: that is the row's summary text, and sharing the name drew a
   bordered box around every row's summary and hid this strip below 1000px. */
.statstrip {
  display: flex; gap: 1.8rem; flex-wrap: wrap; align-items: flex-start;
  border: 1px solid var(--rule); border-radius: 9px; background: var(--surface);
  padding: .72rem .95rem; margin-bottom: .7rem;
}
.caveat { margin: 0 0 0 auto; max-width: 20rem; font-size: .71rem; line-height: 1.45;
          color: var(--ink-muted); }
.distribution { margin-bottom: .9rem; }
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
.denom { color: var(--ink-muted); font-weight: 400; }
.more { padding: .7rem .85rem; border-top: 1px solid var(--rule);
        display: flex; align-items: center; gap: .8rem; }
.moremeta { font-size: .74rem; color: var(--ink-muted); }
.toggle { flex-direction: row; align-items: flex-start; gap: .45rem; font-size: .76rem;
          color: var(--ink-2); padding: 0 .5rem; margin: 0; line-height: 1.4; }
.toggle input { width: auto; margin-top: .15rem; }
.subtle { color: var(--ink-muted); }
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
  display: grid; grid-template-columns: 6.6rem 8.6rem 1fr 4.6rem 6.4rem 9rem 1rem;
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
.kevflag { border: 1px solid var(--bad); color: var(--ink); font-weight: 600;
           padding: 0 .22rem; border-radius: 3px; margin-left: .22rem; }
.gdue { font-size: var(--fs-xs); color: var(--ink-2); white-space: nowrap; }
.gdue.overdue, .due.overdue { color: var(--ink); font-weight: 600;
  text-decoration: underline; text-decoration-color: var(--bad); text-decoration-thickness: 2px;
  text-underline-offset: 3px; }

/* At 1024 the summary column measured 27px wide — present, but unreadable. Below
   1180 it takes a line of its own under the id instead of being squeezed or hidden:
   the summary is what tells a reader whether to open the row at all. */
@media (max-width: 1180px) {
  .grow {
    grid-template-columns: 6.6rem 1fr auto auto;
    grid-template-areas: "band id ssvc chev" "band sum due chev";
    row-gap: .2rem;
  }
  .gssvc { grid-area: ssvc; justify-self: end; }
  .gdue { grid-area: due; justify-self: end; }
  .grow > :first-child { grid-area: band; align-self: start; }
  .idcell { grid-area: id; flex-direction: row; align-items: center; gap: .4rem; }
  .summary { grid-area: sum; white-space: normal; color: var(--ink-2); }
  .spread { display: none; }
  .chev { grid-area: chev; }
}
@media (max-width: 1000px) {
  .cols { flex-direction: column; }
  .facets { width: 100%; flex-direction: row; flex-wrap: wrap; gap: 1.2rem; }
}
</style>
