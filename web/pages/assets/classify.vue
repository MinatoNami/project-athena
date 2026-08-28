<script setup lang="ts">
/**
 * Classify assets.
 *
 * The highest-leverage action in the product and there was no way to do it. Tier and
 * exposure are scoring inputs; while they are unknown, importance is a placeholder in
 * every score on every other page.
 *
 * Grouped server-side so this is a handful of decisions rather than several hundred,
 * and the consequence of each is shown before it is committed rather than after.
 */
useHead({ title: 'Classify assets' })

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const TIERS = ['production', 'staging', 'development', 'personal']
const EXPOSURES = ['internet', 'internal', 'isolated']

const { data, pending, error, refresh } = await useAsyncData('unclassified', () =>
  api<any>('assets/unclassified'),
)

const picks = reactive<Record<string, { tier?: string; exposure?: string }>>({})

/**
 * A field Athena already worked out is not a question. Tier flows along the graph —
 * a container on the production host is production — so most groups arrive with it
 * settled, and asking again is how a queue of decisions stops being worked through.
 * Exposure is not derived for images and containers on purpose: one bound to loopback
 * may still be reached through a reverse proxy on the same host, and this estate runs
 * one. That is the question left, and the evidence for it is shown beside it.
 */
function settled(g: any, field: 'tier' | 'exposure'): string | null {
  const why = g.classification?.[field]
  const value = field === 'tier' ? g.tier : g.exposure
  return why && value && value !== 'unknown' ? why : null
}
function needs(g: any, field: 'tier' | 'exposure'): boolean {
  return !settled(g, field)
}
function answered(g: any): boolean {
  return (['tier', 'exposure'] as const).every(f => !needs(g, f) || picks[g.key]?.[f])
}
function why(g: any, field: 'tier' | 'exposure'): string {
  const w = settled(g, field)
  return w === 'operator' ? 'you set this' : (w ?? '')
}
const applying = ref(false)
const applied = ref<{ assets: number; rescore: boolean } | null>(null)
const failed = ref<string | null>(null)

function set(key: string, field: 'tier' | 'exposure', value: string) {
  const current = picks[key] ?? (picks[key] = {})
  current[field] = current[field] === value ? undefined : value
}

const groups = computed(() => data.value?.groups ?? [])
// A group counts as complete when everything still open has been answered — not
// when every field has been clicked. Re-answering what is already settled is work
// without a decision in it.
const complete = computed(() =>
  groups.value.filter((g: any) => answered(g) && Object.keys(picks[g.key] ?? {}).length),
)
const findingsAffected = computed(() =>
  complete.value.reduce((n: number, g: any) => n + (g.finding_count ?? 0), 0),
)
const progress = computed(() =>
  groups.value.length ? Math.round((complete.value.length / groups.value.length) * 100) : 0,
)

/**
 * What this choice does, said before it is applied. "production + internet" raises
 * consequence; "development" or "isolated" lowers it. Anything else is a real answer
 * replacing a placeholder, which is worth saying even when the number barely moves.
 */
function impact(g: any) {
  const p = picks[g.key]
  const tier = p?.tier ?? (settled(g, 'tier') ? g.tier : undefined)
  const exposure = p?.exposure ?? (settled(g, 'exposure') ? g.exposure : undefined)
  if (!tier || !exposure) {
    return { text: '—', note: 'answer what is open to see the effect', tone: 'idle' }
  }
  if (!g.finding_count) return { text: 'No findings', note: 'nothing to rescore', tone: 'idle' }
  if (tier === 'production' && exposure === 'internet') {
    return { text: `${g.finding_count} rescored up`, note: 'production and internet-facing', tone: 'up' }
  }
  if (tier === 'development' || tier === 'personal' || exposure === 'isolated') {
    return { text: `${g.finding_count} rescored down`, note: 'lower consequence than assumed', tone: 'down' }
  }
  return { text: `${g.finding_count} rescored`, note: 'importance measured, not assumed', tone: 'flat' }
}

async function apply() {
  applying.value = true
  failed.value = null
  try {
    const body = {
      groups: complete.value.map((g: any) => ({
        asset_ids: g.asset_ids,
        // Only what was actually decided here. Sending back a derived value would
        // stamp it as an operator decision and freeze it against future evidence.
        tier: picks[g.key]?.tier,
        exposure: picks[g.key]?.exposure,
      })),
    }
    const result = await api<any>('assets/classify', { method: 'POST', body })
    applied.value = { assets: result.assets_changed, rescore: result.rescore_queued }
    for (const key of Object.keys(picks)) delete picks[key]
    await refresh()
  } catch (e: any) {
    failed.value = e?.data?.detail || e?.message || 'The classification was not saved.'
  } finally {
    applying.value = false
  }
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Classify assets</h1>
        <p>
          Athena treats an unclassified asset as middling rather than unimportant, so
          nothing is being hidden from you. But it means importance is a placeholder in
          every score until you say what these are.
        </p>
      </div>
      <div v-if="groups.length" class="progress">
        <div class="pfig">
          <span class="mono tnum big">{{ complete.length }}</span>
          <span class="pof">of {{ groups.length }} groups set</span>
        </div>
        <div class="bar"><div class="fill" :style="{ width: `${progress}%` }" /></div>
      </div>
    </div>

    <div v-if="applied" class="banner good">
      <strong>{{ applied.assets.toLocaleString() }} assets classified.</strong>
      <template v-if="applied.rescore">
        Rescoring is queued — scores across the estate will update as it runs.
      </template>
      <template v-else>Nothing changed, so no rescore was needed.</template>
    </div>
    <div v-if="failed" class="banner bad"><strong>Not saved.</strong> {{ failed }}</div>

    <div v-if="groups.length" class="note">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
        <circle cx="12" cy="12" r="9" /><path d="M12 8v5" /><path d="M12 16.5v.01" />
      </svg>
      <span>
        Grouped by what they appear to be — {{ groups.length }}
        {{ groups.length === 1 ? 'decision' : 'decisions' }} instead of
        {{ (data?.asset_count ?? 0).toLocaleString() }} assets. Setting a group applies to
        every asset in it. Where a value was worked out from the estate itself it is
        shown rather than asked for; answering over it makes it yours, and no later
        pass will change it.
      </span>
    </div>

    <RowSkeleton v-if="pending" :rows="5" />

    <StateBlock v-else-if="error" kind="error" title="Cannot reach Athena">
      The classification list could not be loaded.
      <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
    </StateBlock>

    <StateBlock
      v-else-if="!groups.length" kind="clean" title="Everything is classified"
      :stats="[{ value: '0', label: 'assets without a tier or exposure' }]"
    >
      Every asset carries a tier and an exposure, so importance is measured rather than
      assumed in every score.
      <template #actions><NuxtLink to="/" class="btn primary">Back to Today</NuxtLink></template>
    </StateBlock>

    <div v-else class="groups">
      <div
        v-for="g in groups" :key="g.key" class="grp"
        :class="{ done: answered(g) }"
      >
        <div class="who">
          <span class="dot" :class="answered(g) ? 'live' : 'idle'" />
          <div class="names">
            <span class="name">{{ g.label }}</span>
            <span class="detail">
              {{ g.asset_count }}
              {{ g.asset_count === 1 ? g.kind : `${g.kind}s` }}
              · {{ g.finding_count.toLocaleString() }}
              {{ g.finding_count === 1 ? 'finding' : 'findings' }}
              <span v-if="g.mixed" class="mixed" title="Members do not currently agree">mixed</span>
            </span>

            <!-- What was observed about reachability, since that is the question left
                 open. Shown rather than acted on: whether loopback means unreachable
                 depends on what else runs on the host, which Athena cannot see. -->
            <ul v-if="g.evidence?.length && needs(g, 'exposure')" class="ev">
              <li v-for="(line, n) in g.evidence.slice(0, 4)" :key="n">
                <UntrustedText :text="line" />
              </li>
              <li v-if="g.evidence.length > 4" class="more">
                and {{ g.evidence.length - 4 }} more
              </li>
            </ul>
          </div>
        </div>

        <div class="field">
          <span class="lbl">Tier</span>
          <div v-if="!needs(g, 'tier')" class="already">
            <span class="val">{{ g.tier }}</span>
            <span class="src">{{ why(g, 'tier') }}</span>
          </div>
          <div v-else class="seg">
            <button
              v-for="t in TIERS" :key="t" :class="{ on: picks[g.key]?.tier === t }"
              @click="set(g.key, 'tier', t)"
            >{{ t }}</button>
          </div>
        </div>

        <div class="field">
          <span class="lbl">Exposure</span>
          <div v-if="!needs(g, 'exposure')" class="already">
            <span class="val">{{ g.exposure }}</span>
            <span class="src">{{ why(g, 'exposure') }}</span>
          </div>
          <div v-else class="seg">
            <button
              v-for="e in EXPOSURES" :key="e" :class="{ on: picks[g.key]?.exposure === e }"
              @click="set(g.key, 'exposure', e)"
            >{{ e }}</button>
          </div>
        </div>

        <div class="impact" :class="impact(g).tone">
          <span class="itext">{{ impact(g).text }}</span>
          <span class="inote">{{ impact(g).note }}</span>
        </div>
      </div>
    </div>

    <div v-if="groups.length" class="footer">
      <span class="sum">
        <template v-if="complete.length">
          {{ complete.length }} {{ complete.length === 1 ? 'group' : 'groups' }} set ·
          {{ findingsAffected.toLocaleString() }}
          {{ findingsAffected === 1 ? 'finding' : 'findings' }} will be rescored
        </template>
        <template v-else>Nothing set yet. Scores stay as they are until you apply.</template>
      </span>
      <button class="btn primary" :disabled="!complete.length || applying" @click="apply">
        {{ applying ? 'Applying…' : complete.length
          ? `Apply and rescore ${complete.length}` : 'Apply' }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.progress { display: flex; flex-direction: column; align-items: flex-end; gap: .4rem; flex-shrink: 0; }
.pfig { display: flex; align-items: baseline; gap: .4rem; }
.big { font-size: 1.35rem; font-weight: 600; }
.pof { font-size: .76rem; color: var(--ink-muted); }
.bar { width: 190px; height: 5px; border-radius: 3px; background: var(--rule); overflow: hidden; }
.fill { height: 100%; background: var(--ink); transition: width .25s ease; }

.banner {
  border: 1px solid var(--rule); border-radius: 8px; padding: .6rem .8rem;
  font-size: .82rem; color: var(--ink-2); margin-bottom: .8rem; background: var(--surface);
}
.banner strong { color: var(--ink); }
.banner.good { border-left: 3px solid var(--good); }
.banner.bad { border-left: 3px solid var(--crit); }

.note {
  border: 1px solid var(--rule); border-radius: 9px; background: var(--surface);
  padding: .58rem .8rem; display: flex; align-items: center; gap: .6rem;
  font-size: .79rem; line-height: 1.5; color: var(--ink-2); margin-bottom: .9rem;
}
.note svg { color: var(--ink-muted); flex-shrink: 0; }

.groups { display: flex; flex-direction: column; gap: .5rem; }
.grp {
  border: 1px solid var(--rule); border-radius: 10px; background: var(--surface);
  padding: .75rem .9rem; display: flex; align-items: center; gap: 1.2rem; flex-wrap: wrap;
}
.grp.done { border-color: var(--ink-muted); }
.who { width: 15rem; flex-shrink: 0; display: flex; align-items: center; gap: .55rem; min-width: 0; }
.dot.idle { background: var(--ink-muted); }
.names { display: flex; flex-direction: column; gap: .1rem; min-width: 0; }
.name { font-size: .85rem; font-weight: 600; overflow: hidden;
        text-overflow: ellipsis; white-space: nowrap; }
.detail { font-size: .72rem; color: var(--ink-muted); }
.mixed {
  border: 1px dashed var(--rule); border-radius: 3px; padding: 0 .22rem;
  margin-left: .25rem; font-size: .64rem; color: var(--warn-ink);
}
.field { display: flex; flex-direction: column; gap: .3rem; }
.impact {
  margin-left: auto; width: 11rem; text-align: right; flex-shrink: 0;
  display: flex; flex-direction: column; gap: .1rem;
}
.itext { font-size: .79rem; font-weight: 600; color: var(--ink-muted); }
.inote { font-size: .69rem; color: var(--ink-muted); }
.impact.up .itext { color: var(--crit); }
.impact.down .itext, .impact.flat .itext { color: var(--ink-2); }

.footer {
  position: sticky; bottom: 0; margin-top: .9rem; border-top: 1px solid var(--rule);
  background: var(--surface); padding: .7rem .9rem; display: flex;
  align-items: center; gap: 1rem; border-radius: 0 0 9px 9px;
}
.sum { font-size: .8rem; color: var(--ink-2); flex-grow: 1; }

@media (max-width: 1180px) {
  .grp { gap: .8rem; }
  .who { width: 100%; }
  .impact { margin-left: 0; width: auto; text-align: left; }
}
.ev { margin: .35rem 0 0; padding-left: 0; list-style: none;
      display: flex; flex-direction: column; gap: .15rem; }
.ev li { font-size: .72rem; line-height: 1.45; color: var(--ink-muted); }
.ev li.more { font-style: italic; }
.already { display: flex; flex-direction: column; gap: .1rem; }
.already .val { font-size: .82rem; font-weight: 600; color: var(--ink); }
.already .src { font-size: .68rem; line-height: 1.4; color: var(--ink-muted); }
</style>
