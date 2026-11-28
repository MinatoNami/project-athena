<script setup lang="ts">
useHead({ title: 'Today' })

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const tab = ref<'needs' | 'waiting' | 'cleared'>('needs')
const open = ref<string | null>(null)

const QUERIES = {
  needs: 'needs_attention=true&sort=risk&limit=50',
  waiting: 'fully_assessed=false&needs_attention=false&sort=risk&limit=50',
  cleared: 'fully_assessed=true&needs_attention=false&sort=risk&limit=50',
}

const { data, pending, error, refresh } = await useAsyncData(
  'today',
  () => api<any>(`findings?${QUERIES[tab.value]}`),
  { watch: [tab] },
)
const { data: coverage } = await useAsyncData('today-coverage', () =>
  api<any>('coverage').catch(() => null),
)

const { data: estate, refresh: refreshEstate } = await useAsyncData('today-estate', () =>
  api<any>('findings?limit=1').catch(() => null),
)
const { data: unclassified } = await useAsyncData('today-unclassified', () =>
  api<any>('assets/unclassified').catch(() => null),
)

useEvents(['findings'], () => {
  refresh()
  refreshEstate()
})
const { severity } = useChartTheme()

const shownTab = ref(tab.value)
watch(data, () => { shownTab.value = tab.value })
const loading = computed(() => pending.value && (!data.value || shownTab.value !== tab.value))

const TAB_IDS = ['needs', 'waiting', 'cleared'] as const
function selectTab(id: string) {
  tab.value = id as typeof tab.value
  open.value = null
}

const instances = computed(() => {
  const collapsed = new Map<string, any>()
  for (const g of data.value?.groups ?? []) {
    for (const i of g.instances ?? []) {
      const family = String(i.asset).replace(/[@:][^@:]*$/, '')
      const key = `${g.vulnerability_id}::${family}`
      const entry = collapsed.get(key)
      if (!entry) {
        collapsed.set(key, { ...i, group: g, family, siblings: 1 })
        continue
      }
      entry.siblings += 1
      if ((i.risk_score ?? -1) > (entry.risk_score ?? -1)) {
        Object.assign(entry, i, { group: g, family, siblings: entry.siblings })
      }
    }
  }
  return [...collapsed.values()]
})

const rows = computed(() =>
  tab.value === 'needs'
    ? instances.value
    : instances.value.filter((i: any) => i.triage_disposition !== 'deprioritise'),
)

const facet = (name: string) => estate.value?.facets?.[name]?.total ?? 0

const estateUnknown = computed(() => estate.value == null)

const tabs = computed(() => [
  { id: 'needs', label: 'Needs you', count: estateUnknown.value ? null : facet('needs_attention') },
  { id: 'waiting', label: 'Waiting on Athena', count: estateUnknown.value ? null : facet('waiting') },
  { id: 'cleared', label: 'Cleared', count: estateUnknown.value ? null : facet('cleared') },
])

const bands = computed(() => {
  const sev = severity.value
  return (['critical', 'high', 'medium', 'low', 'informational'] as const)
    .map(name => ({ label: name, value: facet(`band:${name}`), color: sev[name] }))
    .filter(r => r.value > 0)
})

const unassessedGroups = computed(() => facet('band:unassessed'))

const exposure = computed(() =>
  (['internet', 'internal', 'isolated', 'unknown'] as const)
    .map(name => ({
      label: name === 'unknown' ? 'unclassified' : name,
      value: facet(`exposure:${name}`),
      dashed: name === 'unknown',
      hint: name === 'unknown' ? 'nobody has said what these are' : undefined,
    }))
    .filter(r => r.value > 0),
)

const truncated = computed(() =>
  (data.value?.matching_group_count ?? 0) > (data.value?.groups?.length ?? 0),
)

function signals(i: any) {
  const out: { text: string; tone?: 'bad' | 'warn' }[] = []
  if (i.group.kev) out.push({ text: 'actively exploited', tone: 'bad' })
  if (i.exposure === 'internet') out.push({ text: 'internet-facing', tone: 'bad' })
  if (!i.investigated) out.push({ text: 'not investigated', tone: 'warn' })
  if (i.group.epss_score != null && i.group.epss_score >= 0.1) {
    out.push({ text: `${(i.group.epss_score * 100).toFixed(0)}% exploit likelihood`, tone: 'warn' })
  }
  if (i.investigated && i.confidence != null && i.confidence < 0.5) {
    out.push({ text: 'inconclusive', tone: 'warn' })
  }
  if (i.due && !i.group.malicious) {
    const days = daysUntil(i.due)
    if (days <= 14) out.push({ text: `${dueText(i.due)} · BOD 26-04`, tone: days <= 0 ? 'bad' : 'warn' })
  }
  if (i.forensic_triage && i.group.kev) out.push({ text: 'forensic triage', tone: 'bad' })
  if (!i.fixed_version && !i.group.malicious) out.push({ text: 'no fix yet' })
  if (!out.length) out.push({ text: i.investigated ? 'assessed here' : 'version match' })
  return out
}

const suppressing = ref<any | null>(null)

async function suppressed() {
  suppressing.value = null
  await Promise.all([refresh(), refreshEstate()])
}

const heldBack = computed(() => {
  const out: { label: string; value: number }[] = []
  if (estate.value?.no_fix_available_count) {
    out.push({ label: 'No fix published', value: estate.value.no_fix_available_count })
  }
  if (estate.value?.suppressed_group_count) {
    out.push({ label: 'Suppressed by you', value: estate.value.suppressed_group_count })
  }
  if (estate.value?.baseline_group_count) {
    out.push({ label: 'Pre-existing', value: estate.value.baseline_group_count })
  }
  return out
})

const hiddenLowerPriority = computed(() =>
  tab.value === 'needs'
    ? 0
    : instances.value.filter((i: any) => i.triage_disposition === 'deprioritise').length,
)
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Today</h1>
        <p v-if="!loading">
          <template v-if="estateUnknown">Counts could not be loaded — this is not an all-clear.</template>
          <template v-else-if="facet('needs_attention')">
            <strong>{{ facet('needs_attention') }}</strong> need a person.
          </template>
          <template v-else>Nothing is waiting on you.</template>
        </p>
      </div>
      <div class="actions">
        <NuxtLink to="/findings" class="btn">All findings</NuxtLink>
      </div>
    </div>

    <CoverageStrip :coverage="coverage" :findings="estate" />

    <div class="charts">
      <ChartFrame
        title="Worst band reached"
        :note="unassessedGroups
          ? `${unassessedGroups.toLocaleString()} more have no band — nothing has assessed them`
          : 'one row per decision, across the estate'"
        :empty="!bands.length"
        :empty-text="estateUnknown
          ? 'Counts could not be loaded.'
          : unassessedGroups
            ? `None of the ${unassessedGroups.toLocaleString()} groups found so far has been assessed, so none has a band yet.`
            : 'Nothing matched yet.'"
        :table="{ columns: ['Band', 'Groups'], rows: bands.map(b => [b.label, b.value]) }"
      >
        <ChartBars :rows="bands" unit="groups" summary="Finding groups by worst band reached" />
      </ChartFrame>

      <ChartFrame
        title="Where they sit"
        note="dashed means nobody has classified the asset"
        :empty="!exposure.length"
        :empty-text="estateUnknown ? 'Counts could not be loaded.' : 'No exposure recorded yet.'"
        :table="{ columns: ['Exposure', 'Groups'], rows: exposure.map(e => [e.label, e.value]) }"
      >
        <ChartBars :rows="exposure" unit="groups" summary="Finding groups by asset exposure" />
      </ChartFrame>
    </div>

    <div class="tabbar">
      <div class="tabs" role="tablist" aria-label="Queue">
        <button
          v-for="t in tabs" :id="`tab-${t.id}`" :key="t.id" class="tab" :class="{ on: tab === t.id }"
          role="tab" :aria-selected="tab === t.id" aria-controls="queue-panel"
          :tabindex="tab === t.id ? 0 : -1"
          @click="selectTab(t.id)"
          @keydown="tabKeydown($event, TAB_IDS, tab, selectTab)"
        >
          {{ t.label }} <span class="mono tnum count">{{ t.count ?? '—' }}</span>
        </button>
      </div>
      <span class="hint">Ranked by what changes if you ignore it</span>
    </div>

    <div class="cols">
      <div id="queue-panel" class="queue" role="tabpanel" :aria-labelledby="`tab-${tab}`">
        <RowSkeleton v-if="loading" :rows="4" />

        <StateBlock v-else-if="error" kind="error" title="Cannot reach Athena">
          The core service did not answer. Your findings are not lost — this view
          cannot read them right now.
          <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
        </StateBlock>

        <StateBlock
          v-else-if="!rows.length && tab === 'needs' && !estate?.group_count"
          kind="never" title="Athena has not looked yet"
        >
          Nothing has been matched — <strong>not a clean result</strong>. Fetch
          intelligence and inventory an asset, and this fills in.
          <template #actions>
            <NuxtLink to="/findings" class="btn primary">Vulnerability intelligence</NuxtLink>
          </template>
        </StateBlock>

        <StateBlock
          v-else-if="!rows.length && tab === 'needs'"
          kind="clean" title="Nothing needs you"
          :stats="[
            { value: `${coverage?.assets_fresh ?? 0} / ${coverage?.assets_total ?? 0}`, label: 'assets read' },
            { value: `${(estate?.assessed_count ?? 0).toLocaleString()}`, label: 'findings assessed' },
            { value: `${(estate?.instance_count ?? 0).toLocaleString()}`, label: 'findings total' },
          ]"
        >
          Every assessed finding landed below the band that needs a person. The counts
          are the claim — without them this is only a green tick.
        </StateBlock>

        <StateBlock v-else-if="!rows.length" kind="empty" title="Nothing in this tab">
          A statement about this tab, not about your estate.
        </StateBlock>

        <template v-else>
        <div v-for="i in rows" :key="i.finding_id" class="row" :class="{ isopen: open === i.finding_id }">
          <div
            class="rowhead" role="button" tabindex="0"
            :aria-expanded="open === i.finding_id"
            @click="open = open === i.finding_id ? null : i.finding_id"
            @keydown.enter.prevent="open = open === i.finding_id ? null : i.finding_id"
            @keydown.space.prevent="open = open === i.finding_id ? null : i.finding_id"
          >
            <SeverityChip v-if="i.investigated" :severity="i.risk_band" :kev="i.group.kev" />
            <span v-else class="unassessed" title="Version match only — not investigated">
              unassessed
              <span v-if="i.group.kev" class="kevflag">KEV</span>
            </span>

            <div class="meat">
              <div class="idline">
                <code class="cve">{{ i.group.vulnerability_id }}</code>
                <code class="pkg">{{ i.component }}</code>
                <span class="on">
                  {{ i.siblings > 1 ? i.family : i.asset }}
                  <span v-if="i.siblings > 1" class="siblings">+{{ i.siblings - 1 }}</span>
                </span>
              </div>
              <div class="chips">
                <span v-if="i.group.malicious" class="tag bad strong caps">malware</span>
                <SsvcChip
                  v-if="!i.group.malicious && (i.ssvc === 'act' || i.ssvc === 'attend')"
                  :outcome="i.ssvc"
                />
                <span
                  v-for="s in signals(i)" :key="s.text"
                  class="tag" :class="s.tone"
                >{{ s.text }}</span>
              </div>
            </div>

            <div class="score">
              <span v-if="i.investigated" class="mono tnum n">{{ i.risk_score }}</span>
              <span v-else class="hatchbox hatch" aria-hidden="true" />
              <span class="conf">
                {{ !i.investigated ? 'not scored'
                  : i.confidence != null ? `${(i.confidence * 100).toFixed(0)}% sure`
                  : 'confidence not recorded' }}
              </span>
              <FreshnessIndicator :at="i.observed_at" :never-inventoried="!i.observed_at" />
            </div>
          </div>

          <div v-if="open === i.finding_id" class="rowbody">
            <p class="summary"><UntrustedText :text="i.group.summary || 'No summary published.'" /></p>
            <div class="facts">
              <span v-if="i.group.cvss_score">CVSS {{ i.group.cvss_score }}</span>
              <span v-if="i.group.epss_score != null">
                EPSS {{ (i.group.epss_score * 100).toFixed(1) }}%
              </span>
              <span v-else class="gap">EPSS not published</span>
              <span>fixed in {{ i.fixed_version || 'nothing yet' }}</span>
              <span>{{ i.tier }}</span>
            </div>
            <div class="rowacts">
              <NuxtLink :to="`/findings/${i.finding_id}`" class="btn primary">Open case</NuxtLink>
              <button class="btn" @click="suppressing = i">Stop showing this…</button>
              <NuxtLink :to="`/findings#${i.group.vulnerability_id}`" class="btn">
                All {{ i.group.instance_count }} affected
              </NuxtLink>
            </div>
          </div>
        </div>

        <p v-if="truncated" class="truncated">
          Top {{ rows.length }} of
          {{ (data?.matching_group_count ?? 0).toLocaleString() }}.
          <NuxtLink to="/findings">See all →</NuxtLink>
        </p>
        <p v-if="hiddenLowerPriority" class="truncated">
          {{ plural(hiddenLowerPriority, 'more row') }} ranked lower by triage
          {{ hiddenLowerPriority === 1 ? 'is' : 'are' }} left out of this tab, not removed.
        </p>
        </template>
      </div>

      <aside class="rail">
        <BaselineOffer @done="refreshEstate(); refresh()" />

        <div v-if="unclassified?.asset_count" class="card lever">
          <div class="lbl">Biggest lever</div>
          <p>
            <strong>{{ unclassified.asset_count.toLocaleString() }}
            {{ unclassified.asset_count === 1 ? 'asset has' : 'assets have' }} no tier or
            exposure.</strong>
            Athena scores them as middling, so nothing is hidden — but importance is a
            placeholder in every score until you say what they are.
          </p>
          <NuxtLink to="/assets/classify" class="btn primary block">
            Classify {{ unclassified.group_count }}
            {{ unclassified.group_count === 1 ? 'group' : 'groups' }}
          </NuxtLink>
        </div>

        <ChartFrame
          v-if="heldBack.length"
          title="Held back, not hidden"
          note="out of the queue, still counted"
          :table="{ columns: ['Reason', 'Groups'], rows: heldBack.map(h => [h.label, h.value]) }"
        >
          <ChartBars :rows="heldBack" unit="groups" summary="Findings held out of the queue, by reason" />
        </ChartFrame>
      </aside>
    </div>

    <SuppressDialog
      v-if="suppressing"
      :finding-id="suppressing.finding_id"
      :vulnerability-id="suppressing.group.vulnerability_id"
      :asset="suppressing.asset"
      :instance-count="suppressing.group.instance_count"
      @close="suppressing = null"
      @done="suppressed"
    />
  </div>
</template>

<style scoped>
.charts { display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; margin: .8rem 0 .2rem; }

.tabbar { display: flex; align-items: center; gap: .35rem; margin: 1rem 0 .8rem; flex-wrap: wrap; }
.tabs { display: flex; align-items: center; gap: .35rem; }
.tab {
  font: inherit; font-size: .8rem; font-weight: 500; padding: .35rem .7rem;
  border-radius: 7px; border: 1px solid transparent; background: transparent;
  color: var(--ink-muted); cursor: pointer;
}
.tab:hover { color: var(--ink); }
.tab.on { background: var(--surface); border-color: var(--rule); color: var(--ink); font-weight: 600; }
.count { color: var(--ink-muted); }
.hint { margin-left: auto; font-size: .74rem; color: var(--ink-muted); }

.cols { display: flex; gap: 1.1rem; align-items: flex-start; }
.queue { flex-grow: 1; min-width: 0; display: flex; flex-direction: column; gap: .5rem; }
.rail { width: 268px; flex-shrink: 0; display: flex; flex-direction: column; gap: .65rem; }

.row { border: 1px solid var(--rule); border-radius: 9px; background: var(--surface); }
.rowhead { cursor: pointer; border-radius: 8px; }
.row.isopen { border-color: var(--line-strong); }
.row:hover { border-color: var(--ink-muted); }
.rowhead { padding: .7rem .85rem; display: flex; align-items: flex-start; gap: .7rem; }
.meat { flex-grow: 1; min-width: 0; display: flex; flex-direction: column; gap: .32rem; }
.idline { display: flex; align-items: baseline; gap: .55rem; flex-wrap: wrap; }
.cve { font-size: .8rem; font-weight: 600; }
.pkg { font-size: .78rem; color: var(--ink-2); }
.on { font-size: .76rem; color: var(--ink-muted); }
.siblings { border: 1px dashed var(--rule); border-radius: 3px; padding: 0 .22rem; }

.chips { display: flex; flex-wrap: wrap; gap: .3rem; align-items: center; }

.score { display: flex; flex-direction: column; align-items: flex-end; gap: .1rem; flex-shrink: 0; }
.score .n { font-size: .95rem; font-weight: 600; }
.conf { font-size: .66rem; color: var(--ink-muted); white-space: nowrap; }

.rowbody {
  border-top: 1px solid var(--rule); padding: .8rem .85rem; background: var(--plane);
  border-radius: 0 0 8px 8px; display: flex; flex-direction: column; gap: .6rem; cursor: default;
}
.summary { margin: 0; font-size: .82rem; line-height: 1.55; color: var(--ink-2); }
.facts { display: flex; gap: .9rem; flex-wrap: wrap; font-size: .74rem; color: var(--ink-muted); }
.facts .gap { color: var(--warn-ink); }
.rowacts { display: flex; gap: .5rem; }

.truncated { margin: .4rem 0 0; font-size: .76rem; color: var(--ink-muted); }
.card { border: 1px solid var(--rule); border-radius: 9px; background: var(--surface); padding: .85rem .9rem; }
.card p { margin: .5rem 0 .6rem; font-size: .8rem; line-height: 1.5; color: var(--ink-2); }
.card p strong { color: var(--ink); font-weight: 600; }
.block { display: block; width: 100%; text-align: center; text-decoration: none; }

.unassessed {
  font-size: .66rem; text-transform: uppercase; letter-spacing: .04em; color: var(--ink-muted);
  border: 1px dashed var(--rule); border-radius: 4px; padding: .15rem .38rem; white-space: nowrap;
}
.kevflag {
  border: 1px solid var(--bad); color: var(--ink); font-weight: 600;
  padding: 0 .22rem; border-radius: 3px; margin-left: .22rem;
}
.hatchbox { display: inline-block; width: 1.6rem; height: .9rem; border-radius: 3px;
            border: 1px dashed var(--line-strong); }

@media (max-width: 1080px) {
  .charts { grid-template-columns: 1fr; }
  .cols { flex-direction: column; }
  .rail { width: 100%; flex-direction: row; flex-wrap: wrap; }
  .rail > * { flex: 1 1 260px; }
}
</style>
