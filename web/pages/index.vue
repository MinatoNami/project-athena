<script setup lang="ts">
/**
 * Today — a ranked worklist, not a dashboard.
 *
 * This page used to be a developer console: an "enqueue probe job" button and a raw
 * job table. It answered "is the machinery running" when the question a person
 * arrives with is "what do I do next".
 *
 * Every row states why it is ranked where it is. A rank with no stated cause is an
 * opinion, and an opinion is exactly what this product is trying not to be.
 */
useHead({ title: 'Today' })

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const tab = ref<'needs' | 'waiting' | 'cleared'>('needs')
const open = ref<string | null>(null)

/**
 * Three populations, each asked for by name rather than carved out of one
 * over-fetched list. The counts beside the tabs are then the server's, which means
 * they describe the estate rather than however much happened to be downloaded.
 */
const QUERIES = {
  needs: 'needs_attention=true&sort=risk&limit=50',
  waiting: 'assessed=false&sort=risk&limit=50',
  cleared: 'assessed=true&sort=risk&limit=50',
}

const { data, pending, error, refresh } = await useAsyncData(
  'today',
  () => api<any>(`findings?${QUERIES[tab.value]}`),
  { watch: [tab] },
)
const { data: coverage } = await useAsyncData('today-coverage', () =>
  api<any>('coverage').catch(() => null),
)

/**
 * Estate-wide totals, fetched separately from whichever tab is open.
 *
 * The strip and the all-clear state are denominators — "assessed, out of how many"
 * — and taking them from the current tab's response made an empty queue report
 * "0 of 0 findings assessed" while 537 were in fact assessed. A denominator that
 * shrinks to match the filter is not a denominator.
 */
const { data: estate } = await useAsyncData('today-estate', () =>
  api<any>('findings?limit=1').catch(() => null),
)
const { data: unclassified } = await useAsyncData('today-unclassified', () =>
  api<any>('assets/unclassified').catch(() => null),
)

useEvents(['findings'], refresh)

/**
 * One entry per decision, not per row in the database.
 *
 * Near-identical assets collapse: fourteen tags of one image carrying one
 * vulnerability is one thing to decide about. Without this the queue fills with the
 * same CVE repeated down the page, which is the wall of noise a triage view exists
 * to prevent — and the worst instance is what should be shown, since acting on the
 * family covers the rest.
 */
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
      // Keep whichever instance argues hardest for attention.
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

/** Tab counts are the server's, so they count the estate rather than the download. */
const tabs = computed(() => {
  const f = estate.value?.facets ?? {}
  return [
    { id: 'needs', label: 'Needs you', count: f.needs_attention?.total ?? 0 },
    { id: 'waiting', label: 'Waiting on Athena', count: f.unassessed?.total ?? 0 },
    { id: 'cleared', label: 'Cleared', count: f.assessed?.total ?? 0 },
  ]
})

const truncated = computed(() =>
  (data.value?.matching_group_count ?? 0) > (data.value?.groups?.length ?? 0),
)

/** Why this sits where it does — assembled from what was actually established. */
function reason(i: any) {
  const bits: string[] = []
  if (i.group.kev) bits.push('listed as actively exploited')
  if (i.exposure === 'internet') bits.push('internet-facing')
  if (!i.investigated) {
    bits.push('not yet investigated — nothing has checked whether it runs or is reachable here')
  }
  if (i.group.epss_score != null && i.group.epss_score >= 0.1) {
    bits.push(`exploitation likelihood ${(i.group.epss_score * 100).toFixed(0)}%`)
  }
  if (i.investigated && i.confidence != null && i.confidence < 0.5) {
    bits.push('the investigation was inconclusive')
  }
  if (!i.fixed_version) bits.push('no published fix, so the clock has not started')
  if (!bits.length) {
    bits.push(
      i.investigated
        ? 'assessed on this asset and scored on what was found'
        : 'a version match against a published advisory',
    )
  }
  return bits.join(' · ')
}

const heldBack = computed(() => {
  const out: { label: string; n: number }[] = []
  if (data.value?.no_fix_available_count) {
    out.push({ label: 'No fix published', n: data.value.no_fix_available_count })
  }
  const entitled = instances.value.filter(
    (i: any) => i.fix_channel && i.fix_channel !== 'standard',
  ).length
  if (entitled) out.push({ label: 'Needs a paid entitlement', n: entitled })
  const deprioritised = instances.value.filter(
    (i: any) => i.triage_disposition === 'deprioritise',
  ).length
  if (deprioritised) out.push({ label: 'Triaged as lower priority', n: deprioritised })
  return out
})
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Today</h1>
        <p v-if="!pending">
          <template v-if="estate?.facets?.needs_attention?.total">
            {{ estate.facets.needs_attention.total }}
            {{ estate.facets.needs_attention.total === 1 ? 'vulnerability needs' : 'vulnerabilities need' }}
            a person. Everything else is either handled or still being looked at.
          </template>
          <template v-else>Nothing is waiting on you right now.</template>
        </p>
      </div>
      <div class="actions">
        <NuxtLink to="/findings" class="btn">All findings</NuxtLink>
      </div>
    </div>

    <CoverageStrip :coverage="coverage" :findings="estate" />

    <div class="tabs">
      <button
        v-for="t in tabs" :key="t.id" class="tab" :class="{ on: tab === t.id }"
        @click="tab = t.id as any; open = null"
      >
        {{ t.label }} <span class="mono tnum count">{{ t.count }}</span>
      </button>
      <span class="hint">Ranked by what changes if you ignore it</span>
    </div>

    <div class="cols">
      <div class="queue">
        <RowSkeleton v-if="pending" :rows="4" />

        <StateBlock v-else-if="error" kind="error" title="Cannot reach Athena">
          The dashboard is running but the core service did not answer. Your findings are
          not lost — this view simply cannot read them right now.
          <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
        </StateBlock>

        <StateBlock
          v-else-if="!rows.length && tab === 'needs' && !estate?.group_count"
          kind="never" title="Athena has not looked yet"
        >
          No findings exist because nothing has been matched yet — <strong>not because you
          are clean</strong>. Fetch intelligence and inventory an asset, and this fills in.
          <template #actions>
            <NuxtLink to="/findings" class="btn primary">Vulnerability intelligence</NuxtLink>
          </template>
        </StateBlock>

        <StateBlock
          v-else-if="!rows.length && tab === 'needs'"
          kind="clean" title="Nothing needs you"
          :stats="[
            { value: `${coverage?.assets_fresh ?? 0} / ${coverage?.assets_total ?? 0}`, label: 'assets inventoried' },
            { value: `${(estate?.assessed_count ?? 0).toLocaleString()}`, label: 'findings assessed' },
            { value: `${(estate?.instance_count ?? 0).toLocaleString()}`, label: 'findings total' },
          ]"
        >
          Every assessed finding landed below the band that needs a person. The counts
          above are the claim — without them this is only a green tick.
        </StateBlock>

        <StateBlock v-else-if="!rows.length" kind="empty" title="Nothing in this tab">
          That is a statement about this tab, not about your estate.
        </StateBlock>

        <div
          v-for="i in rows" :key="i.finding_id" class="row"
          @click="open = open === i.finding_id ? null : i.finding_id"
        >
          <div class="rowhead">
            <SeverityChip
              v-if="i.investigated" :severity="i.risk_band" :kev="i.group.kev"
            />
            <span v-else class="unassessed" title="Version match only — not investigated">
              unassessed
              <span v-if="i.group.kev" class="kevflag">KEV</span>
            </span>

            <div class="meat">
              <div class="idline">
                <code class="cve">{{ i.group.vulnerability_id }}</code>
                <code class="pkg">{{ i.component }}</code>
                <span class="on">
                  on {{ i.siblings > 1 ? i.family : i.asset }}
                  <span v-if="i.siblings > 1" class="siblings">
                    · {{ i.siblings }} near-identical
                  </span>
                </span>
              </div>
              <div class="reason">{{ reason(i) }}</div>
            </div>

            <div class="score">
              <span class="mono tnum n">{{ i.investigated ? i.risk_score : '—' }}</span>
              <span class="conf">
                {{ i.investigated && i.confidence != null
                  ? `confidence ${(i.confidence * 100).toFixed(0)}%`
                  : 'not investigated' }}
              </span>
            </div>
          </div>

          <div v-if="open === i.finding_id" class="rowbody" @click.stop>
            <p class="summary">{{ i.group.summary || 'No summary published.' }}</p>
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
              <NuxtLink :to="`/findings#${i.group.vulnerability_id}`" class="btn">
                See all {{ i.group.instance_count }} affected assets
              </NuxtLink>
            </div>
          </div>
        </div>

        <p v-if="truncated" class="truncated">
          Showing the {{ rows.length }} highest-ranked of
          {{ (data?.matching_group_count ?? 0).toLocaleString() }}.
          <NuxtLink to="/findings">See all in Findings →</NuxtLink>
        </p>
      </div>

      <aside class="rail">
        <!-- The single highest-leverage action available, stated as a lever rather
             than a nag: unclassified assets score at a placeholder importance, so most
             of the ranking beside this card is guesswork until it is filled in. -->
        <div v-if="unclassified?.asset_count" class="card lever">
          <div class="lbl">Biggest lever</div>
          <p>
            <strong>{{ unclassified.asset_count.toLocaleString() }} assets have no tier or
            exposure set.</strong>
            Athena scores them as middling rather than harmless, so nothing is hidden —
            but importance is a placeholder in every score until you say what these are.
          </p>
          <NuxtLink to="/assets/classify" class="btn primary block">
            Classify {{ unclassified.group_count }} groups
          </NuxtLink>
          <p class="fine">
            Grouped by what they appear to be, so it is {{ unclassified.group_count }}
            decisions rather than {{ unclassified.asset_count.toLocaleString() }}.
          </p>
        </div>

        <div v-if="heldBack.length" class="card">
          <div class="lbl">Held back, not hidden</div>
          <div v-for="h in heldBack" :key="h.label" class="held">
            <span>{{ h.label }}</span><span class="mono tnum">{{ h.n.toLocaleString() }}</span>
          </div>
          <p class="fine">
            Nothing can be done about these yet, so they stay out of the queue — and stay
            countable.
          </p>
        </div>
      </aside>
    </div>
  </div>
</template>

<style scoped>
.tabs { display: flex; align-items: center; gap: .35rem; margin: 1rem 0 .8rem; }
.tab {
  font: inherit; font-size: .8rem; font-weight: 500; padding: .35rem .7rem;
  border-radius: 7px; border: 1px solid transparent; background: transparent;
  color: var(--ink-muted); cursor: pointer;
}
.tab:hover { color: var(--ink); }
.tab.on { background: var(--surface); border-color: var(--rule); color: var(--ink); font-weight: 600; }
.count { opacity: .65; }
.hint { margin-left: auto; font-size: .74rem; color: var(--ink-muted); }

.cols { display: flex; gap: 1.1rem; align-items: flex-start; }
.queue { flex-grow: 1; min-width: 0; display: flex; flex-direction: column; gap: .5rem; }
.rail { width: 268px; flex-shrink: 0; display: flex; flex-direction: column; gap: .65rem; }

.row { border: 1px solid var(--rule); border-radius: 9px; background: var(--surface); cursor: pointer; }
.row:hover { border-color: var(--ink-muted); }
.rowhead { padding: .7rem .85rem; display: flex; align-items: flex-start; gap: .7rem; }
.meat { flex-grow: 1; min-width: 0; display: flex; flex-direction: column; gap: .28rem; }
.idline { display: flex; align-items: baseline; gap: .55rem; flex-wrap: wrap; }
.cve { font-size: .8rem; font-weight: 600; }
.pkg { font-size: .78rem; color: var(--ink-2); }
.on { font-size: .76rem; color: var(--ink-muted); }
.siblings { border: 1px dashed var(--rule); border-radius: 3px; padding: 0 .22rem; }
.reason { font-size: .79rem; line-height: 1.45; color: var(--ink-2); }
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
.card .fine { margin: .5rem 0 0; font-size: .71rem; color: var(--ink-muted); }
.block { display: block; width: 100%; text-align: center; text-decoration: none; }
.held { display: flex; justify-content: space-between; gap: .6rem; padding: .28rem 0; font-size: .79rem; color: var(--ink-2); }
.held .mono { color: var(--ink-muted); }

.unassessed {
  font-size: .66rem; text-transform: uppercase; letter-spacing: .04em; color: var(--ink-muted);
  border: 1px dashed var(--rule); border-radius: 4px; padding: .15rem .38rem; white-space: nowrap;
}
.kevflag {
  background: var(--sev-critical); color: var(--sev-on-dark);
  padding: 0 .22rem; border-radius: 3px; margin-left: .22rem;
}

@media (max-width: 1080px) {
  .cols { flex-direction: column; }
  .rail { width: 100%; flex-direction: row; flex-wrap: wrap; }
  .rail .card { flex: 1 1 260px; }
}
</style>
