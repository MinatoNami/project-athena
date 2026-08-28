<script setup lang="ts">
/**
 * One finding, as a case file.
 *
 * The investigation is what separates this from a version-matcher, and the old page
 * buried it under advisory metadata. Three things are deliberately prominent rather
 * than tucked away: what was established and by which tool, where code overruled the
 * model, and what could not be determined at all. The first is the claim, the second
 * is the best available measure of how far to trust it, the third is its honest edge.
 */
const route = useRoute()
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const tab = ref<'verdict' | 'fix' | 'risk' | 'evidence' | 'advisory'>('verdict')

const { data, pending, error, refresh } = await useAsyncData(`finding-${route.params.id}`, () =>
  api<any>(`findings/${route.params.id}`),
)

useHead({ title: () => data.value?.vulnerability?.id ?? 'Finding' })

const { data: suppression, refresh: refreshSuppression } = await useAsyncData(
  `suppression-${route.params.id}`,
  () => api<any>(`findings/${route.params.id}/suppression`).catch(() => null),
)

const suppressing = ref(false)

async function suppressed() {
  suppressing.value = false
  await Promise.all([refresh(), refreshSuppression()])
}

async function revoke() {
  if (!suppression.value?.active) return
  await api(`suppressions/${suppression.value.active.id}/revoke`, { method: 'POST' })
  await Promise.all([refresh(), refreshSuppression()])
}

const inv = computed(() => data.value?.investigation)
const risk = computed(() => data.value?.risk_explained)

const allSignals = computed(() =>
  Object.entries(inv.value?.signals ?? {}).map(([name, s]: any) => ({ name, ...s })),
)
const settled = computed(() =>
  allSignals.value.filter(s => s.value !== 'unknown' && s.value !== null),
)
const unsettled = computed(() =>
  allSignals.value.filter(s => s.value === 'unknown' || s.value === null),
)

function pretty(name: string) {
  return name.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())
}
function valueLabel(v: any) {
  if (v === true) return 'yes'
  if (v === false) return 'no'
  return String(v)
}
function evidenceLabel(s: any) {
  return s.evidence?.length ? s.evidence.join(', ') : 'nothing cited'
}

// Named for what the operator has to do about it, not for the taxonomy. Nobody
// arrives wanting to know that something is `base_image`; they want to know that the
// command they were about to run will not survive a restart.
const FIX_KIND: Record<string, string> = {
  os_package: 'The package manager installs this',
  base_image: 'This needs the image rebuilt',
  dependency: 'This is a change to a manifest',
  transitive: 'Something else has to move first',
  no_fix: 'There is nothing to install yet',
  entitlement: 'The fix is behind a subscription',
  unknown: 'Not enough is recorded to say',
}

const fix = computed(() => data.value?.remediation ?? null)

const copied = ref(false)
async function copyCommand() {
  if (!fix.value?.command) return
  try {
    await navigator.clipboard.writeText(fix.value.command)
    copied.value = true
    setTimeout(() => { copied.value = false }, 1600)
  } catch {
    // A refused clipboard is not worth an error state — the text is on screen and
    // selectable, which is what it was there for.
  }
}

const tabs = [
  { id: 'verdict', label: 'Verdict' },
  { id: 'fix', label: 'Fix' },
  { id: 'risk', label: 'Why this score' },
  { id: 'evidence', label: 'Raw evidence' },
  { id: 'advisory', label: 'Advisory' },
]
</script>

<template>
  <div class="page">
    <RowSkeleton v-if="pending" :rows="3" />

    <StateBlock v-else-if="error" kind="error" title="Cannot load this finding">
      It may have been resolved and removed, or the core service did not answer.
      <template #actions>
        <button class="btn primary" @click="refresh()">Retry</button>
        <NuxtLink to="/findings" class="btn">Back to findings</NuxtLink>
      </template>
    </StateBlock>

    <template v-else-if="data">
      <nav class="crumbs">
        <NuxtLink to="/findings">Findings</NuxtLink>
        <span>/</span>
        <code>{{ data.vulnerability.id }}</code>
      </nav>

      <div class="head">
        <div class="headmain">
          <div class="titleline">
            <SeverityChip
              v-if="data.risk_band" :severity="data.risk_band" :kev="data.vulnerability.kev"
            />
            <span v-else class="unassessed">
              unassessed
              <span v-if="data.vulnerability.kev" class="kevflag">KEV</span>
            </span>
            <h1><UntrustedText :text="data.vulnerability.summary || data.vulnerability.id" /></h1>
          </div>
          <div class="subline">
            <code>{{ data.component.ecosystem }}:{{ data.component.name }}
              {{ data.component.version }}</code>
            <span class="sep">·</span>
            <span>on <NuxtLink :to="`/assets/${data.asset.id}`">
              <strong>{{ data.asset.display_name }}</strong></NuxtLink></span>
            <span class="sep">·</span>
            <span>{{ data.asset.tier }}, {{ data.asset.exposure }}</span>
            <span class="sep">·</span>
            <span>
              fixed in
              <code v-if="data.fixed_version">{{ data.fixed_version }}</code>
              <span v-else class="gap">nothing published yet</span>
            </span>
          </div>
        </div>

        <div class="headside">
          <div class="headacts">
            <button v-if="!suppression?.active" class="btn" @click="suppressing = true">
              Stop showing this…
            </button>
          </div>
          <div v-if="data.risk_score != null" class="scorefig">
            <span class="mono tnum n">{{ data.risk_score }}</span>
            <span class="of">of 100</span>
          </div>
          <div v-else class="scorefig">
            <span class="hatchbox hatch" />
            <span class="of">not scored</span>
          </div>
        </div>
      </div>

      <!-- Not investigated is its own state, never a low score. And "waiting its
           turn" is not the same as "the floor will never select it" — a page that
           says the first while the second is true is telling the operator something
           is coming that is not. -->
      <div v-if="data.deferred" class="banner">
        <strong>This has not been investigated, and will not be at the current
          setting.</strong>
        <UntrustedText :text="data.deferred.reason" />
        <span class="fineline">
          The investigation floor is set to “{{ data.deferred.floor }}”. Known-exploited,
          CVSS 9+, EPSS 10%+ and internet-facing production findings are investigated
          regardless of it.
        </span>
      </div>

      <div v-else-if="data.not_yet_investigated" class="banner">
        <strong>This has not been investigated.</strong>
        It is a version match against a published advisory. Nothing has checked whether
        the component runs here, is reachable, or is exploitable — so it has no score,
        rather than a low one.
      </div>

      <div v-if="data.triage?.disposition === 'deprioritise'" class="banner">
        <strong>Triaged as lower priority.</strong>
        <UntrustedText :text="data.triage.reason || ''" />
        That is a judgement about <em>priority</em>, not a conclusion that this does not
        apply here.
      </div>

      <div v-if="suppression?.active" class="banner suppressed">
        <strong>You stopped showing this on
          {{ new Date(suppression.active.created_at).toLocaleDateString() }}.</strong>
        <UntrustedText :text="suppression.active.reason" />
        <span class="fineline">
          {{ suppression.active.reason_label }}
          · {{ suppression.active.scope === 'everywhere' ? 'everywhere'
            : suppression.active.scope === 'asset' ? 'on this asset' : 'this finding only' }}
          <template v-if="suppression.active.expires_at">
            · under review on
            {{ new Date(suppression.active.expires_at).toLocaleDateString() }}
          </template>
        </span>
        <button class="btn" style="margin-top:.5rem" @click="revoke">Show it again</button>
      </div>

      <!-- A finding that came back says why, rather than simply reappearing. -->
      <div v-else-if="suppression?.lapsed?.invalidated_reason" class="banner warn">
        <strong>This came back.</strong>
        It was set aside on
        {{ new Date(suppression.lapsed.created_at).toLocaleDateString() }} —
        “<UntrustedText :text="suppression.lapsed.reason" />” — and that no longer holds,
        because {{ suppression.lapsed.invalidated_reason }}.
      </div>

      <div v-if="risk?.stale" class="banner warn">
        <strong>This score is out of date.</strong>
        The scoring function has changed since this was last evaluated: it would now
        score {{ risk.score }} rather than {{ risk.stored_score }}. The breakdown below
        describes the current function.
      </div>

      <div class="tabs">
        <button
          v-for="t in tabs" :key="t.id" class="tab" :class="{ on: tab === t.id }"
          @click="tab = t.id as any"
        >{{ t.label }}</button>
      </div>

      <!-- ══ Verdict ══ -->
      <div v-if="tab === 'verdict'" class="cols">
        <div class="main">
          <StateBlock v-if="!inv" kind="never" title="No investigation has run">
            Correlation matched a version. Nothing beyond that has been established, so
            there is no verdict to show — an absence, not a clean result.
          </StateBlock>

          <template v-else>
            <div class="card">
              <div class="verdicthead">
                <span class="lbl">Verdict</span>
                <span class="verdict">{{
                  inv.verdict === 'applicable' ? 'Applies to this asset'
                  : inv.verdict === 'not_applicable' ? 'Does not apply here'
                  : 'Could not be settled' }}</span>
                <span class="conf">confidence {{ (inv.confidence * 100).toFixed(0) }}%</span>
              </div>
              <p class="rationale"><UntrustedText :text="inv.rationale || ''" /></p>
            </div>

            <div v-if="settled.length" class="card">
              <div class="lbl">What Athena checked</div>
              <table class="sig">
                <thead>
                  <tr><th>Signal</th><th>Value</th><th>Confidence</th><th>Established by</th></tr>
                </thead>
                <tbody>
                  <tr v-for="s in settled" :key="s.name">
                    <td class="sname">{{ pretty(s.name) }}</td>
                    <td class="sval">{{ valueLabel(s.value) }}</td>
                    <td class="mono tnum muted">{{ s.confidence?.toFixed(2) }}</td>
                    <td class="muted"><code class="src">{{ evidenceLabel(s) }}</code></td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- Where the model asserted something it could not support and code
                 overruled it. Prominent, because burying it would defeat its purpose. -->
            <div v-if="inv.corrections?.length" class="card overruled">
              <div class="lbl warn">Athena overruled itself · {{ inv.corrections.length }}</div>
              <ul class="corrections">
                <li v-for="(c, n) in inv.corrections" :key="n"><UntrustedText :text="c" /></li>
              </ul>
              <p class="fine">
                These are corrections, not errors for you to act on — but they are the best
                available measure of how far to trust the verdict above.
              </p>
            </div>

            <div v-if="inv.uncertainties?.length || unsettled.length" class="card">
              <div class="lbl">Could not determine</div>
              <ul class="unknowns">
                <li v-for="(u, n) in inv.uncertainties ?? []" :key="`u${n}`">
                  <span class="hatchdot hatch" /><UntrustedText :text="u" />
                </li>
                <li v-for="s in unsettled" :key="s.name">
                  <span class="hatchdot hatch" />{{ pretty(s.name) }}
                  <span class="muted">— {{ evidenceLabel(s) }}</span>
                </li>
              </ul>
            </div>
          </template>
        </div>

        <aside class="side">
          <!-- A reused verdict is a different claim from one reached for this asset
               alone, and with a high cache-hit rate most verdicts are reused. -->
          <div v-if="inv" class="card">
            <div class="lbl">This answer</div>
            <div class="kv"><span>Reached</span>
              <span class="muted">{{ new Date(inv.at).toLocaleString() }}</span></div>
            <div class="kv"><span>Tools called</span>
              <span class="mono tnum muted">{{ inv.tools_called?.length ?? 0 }}</span></div>
            <div class="kv"><span>Shared with</span>
              <span class="mono tnum muted">{{ inv.shared_with_findings }} findings</span></div>
            <div class="kv"><span>Model</span>
              <span class="muted src">{{ inv.model }}</span></div>
            <p class="fine">
              {{ inv.shared_with_findings
                ? 'Reused across findings whose relevant facts match — not reached for this asset alone.'
                : 'Reached for this asset alone, not reused from a matching one.' }}
            </p>
          </div>

          <div class="card">
            <div class="lbl">Match</div>
            <div class="kv"><span>Method</span>
              <span class="muted src">{{ data.match_method }}</span></div>
            <div class="kv"><span>Confidence</span>
              <span class="mono tnum muted">{{ (data.match_confidence * 100).toFixed(0) }}%</span></div>
            <div class="kv"><span>Source</span>
              <span class="muted src">{{ data.matched_source || '—' }}</span></div>
            <p class="fine">How the match was made — not whether it is exploitable here.</p>
          </div>
        </aside>
      </div>

      <!-- ══ Why this score ══ -->
      <!-- ══ Fix ══ -->
      <div v-else-if="tab === 'fix'" class="narrow">
        <StateBlock v-if="!fix" kind="never" title="No route to a fix has been worked out">
          This finding has not been classified, so nothing here would be more than a
          guess about where the change belongs.
        </StateBlock>

        <template v-else>
          <div class="card" :class="{ blocked: !fix.actionable }">
            <div class="lbl">{{ FIX_KIND[fix.class] ?? FIX_KIND.unknown }}</div>
            <p class="fixsummary"><UntrustedText :text="fix.summary" /></p>

            <!-- Deliberately absent for a transitive dependency and for a package
                 baked into an image: there is no command that would work, and
                 offering a plausible one invites exactly the wrong attempt. -->
            <div v-if="fix.command" class="cmdrow">
              <code class="cmd">{{ fix.command }}</code>
              <button class="btn" @click="copyCommand">{{ copied ? 'Copied' : 'Copy' }}</button>
            </div>
            <p v-else-if="fix.actionable" class="fine">
              This ecosystem has no single command worth pretending to; the change is
              made by editing the manifest.
            </p>

            <div class="kv"><span>Change it at</span>
              <span class="muted"><UntrustedText :text="fix.change_at" /></span></div>
          </div>

          <!-- Why it cannot be done now sits on its own, above the unknowns: it is a
               different kind of statement from "we did not check". -->
          <div v-if="fix.blocked_by" class="card blocked">
            <div class="lbl warn">Not actionable yet</div>
            <p class="rationale">
              Blocked because <UntrustedText :text="fix.blocked_by" />.
            </p>
          </div>

          <div v-if="fix.unknowns?.length" class="card">
            <div class="lbl">Could not determine</div>
            <ul class="unknowns">
              <li v-for="(u, n) in fix.unknowns" :key="`f${n}`">
                <span class="hatchdot hatch" /><UntrustedText :text="u" />
              </li>
            </ul>
            <p class="fine">
              Worked out from what has been recorded about this finding, not from
              anything anyone has attempted. Nothing here has been applied or tested.
            </p>
          </div>
        </template>
      </div>

      <div v-else-if="tab === 'risk'" class="narrow">
        <StateBlock v-if="!risk" kind="never" title="No score to explain">
          Nothing has been scored for this finding yet.
        </StateBlock>
        <template v-else>
          <div class="card">
            <div class="lbl">How {{ risk.score }} was reached</div>
            <table class="sig">
              <thead><tr><th>Factor</th><th>Weight</th></tr></thead>
              <tbody>
                <tr v-for="(v, k) in risk.factors" :key="k">
                  <td class="sname">{{ pretty(String(k)) }}</td>
                  <td class="mono tnum sval">{{ Number(v).toFixed(2) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="risk.overrides?.length" class="card">
            <div class="lbl">Overrides applied, in order</div>
            <ol class="overrides">
              <li v-for="(o, n) in risk.overrides" :key="n">{{ o }}</li>
            </ol>
            <p class="fine">
              Overrides can disagree with one another. They are listed in the order they
              applied rather than resolved silently, so the tension stays visible.
            </p>
          </div>
        </template>
      </div>

      <!-- ══ Raw evidence ══ -->
      <div v-else-if="tab === 'evidence'" class="narrow">
        <StateBlock v-if="!data.evidence?.length" kind="never" title="No evidence recorded">
          Nothing has been observed and stored for this finding yet.
        </StateBlock>
        <div v-else class="card">
          <div class="lbl">Observations, as recorded</div>
          <div v-for="(e, n) in data.evidence" :key="n" class="ev">
            <div class="evhead">
              <code class="src">{{ e.kind }}</code>
              <span class="muted">{{ new Date(e.observed_at).toLocaleString() }}</span>
            </div>
            <div class="evclaim"><UntrustedText :text="e.claim" /></div>
          </div>
        </div>
      </div>

      <!-- ══ Advisory ══ -->
      <div v-else class="narrow">
        <div class="card">
          <div class="lbl">Advisory</div>
          <div class="kv"><span>CVSS</span>
            <span class="mono tnum muted">{{ data.vulnerability.cvss_score ?? '—' }}</span></div>
          <div class="kv"><span>EPSS</span>
            <span class="mono tnum muted">
              {{ data.vulnerability.epss_score != null
                ? `${(data.vulnerability.epss_score * 100).toFixed(1)}%` : 'not published' }}
            </span></div>
          <div class="kv"><span>Known-exploited</span>
            <span class="muted">{{ data.vulnerability.kev ? 'yes' : 'no' }}</span></div>
          <div class="kv"><span>Published</span>
            <span class="muted">{{ data.vulnerability.published_at
              ? new Date(data.vulnerability.published_at).toLocaleDateString() : '—' }}</span></div>
          <p v-if="data.vulnerability.details" class="details">
            <UntrustedText :text="data.vulnerability.details" />
          </p>
        </div>

        <!-- Sources can disagree about which versions are affected. Shown rather than
             resolved behind the scenes. -->
        <div v-if="data.advisory_ranges?.length" class="card">
          <div class="lbl">Affected ranges, by source</div>
          <table class="sig">
            <thead><tr><th>Source</th><th>Introduced</th><th>Fixed</th><th>Release</th><th /></tr></thead>
            <tbody>
              <tr v-for="(r, n) in data.advisory_ranges" :key="n" :class="{ used: r.used_for_match }">
                <td><code class="src">{{ r.source }}</code></td>
                <td class="mono">{{ r.introduced || '—' }}</td>
                <td class="mono">{{ r.fixed || '—' }}</td>
                <td class="muted">{{ r.distro_release || '—' }}</td>
                <td><span v-if="r.used_for_match" class="used-tag">used</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <SuppressDialog
        v-if="suppressing"
        :finding-id="String(route.params.id)"
        :vulnerability-id="data.vulnerability.id"
        :asset="data.asset.display_name"
        @close="suppressing = false"
        @done="suppressed"
      />
    </template>
  </div>
</template>

<style scoped>
.crumbs { display: flex; align-items: center; gap: .4rem; font-size: .76rem;
          color: var(--ink-muted); margin-bottom: .75rem; }
.crumbs a { color: var(--ink-muted); }
.head { display: flex; align-items: flex-start; justify-content: space-between;
        gap: 1.5rem; margin-bottom: .9rem; }
.headmain { display: flex; flex-direction: column; gap: .4rem; min-width: 0; }
.titleline { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
.titleline h1 { margin: 0; font-size: 1.28rem; font-weight: 640; letter-spacing: -0.015em; }
.subline { display: flex; gap: .55rem; flex-wrap: wrap; font-size: .79rem; color: var(--ink-2); }
.subline .sep { color: var(--rule); }
.subline .gap { color: var(--warn-ink); }
.headside { flex-shrink: 0; display: flex; align-items: flex-start; gap: 1rem; }
.headacts { display: flex; gap: .4rem; padding-top: .2rem; }
.banner.suppressed { border-left-color: var(--ink-muted); }
.fineline { display: block; margin-top: .3rem; font-size: .72rem; color: var(--ink-muted); }
.scorefig { display: flex; flex-direction: column; align-items: flex-end; gap: .1rem; }
.scorefig .n { font-size: 1.7rem; font-weight: 600; line-height: 1; }
.scorefig .of { font-size: .7rem; color: var(--ink-muted); }
.hatchbox { width: 34px; height: 24px; border-radius: 5px; border: 1px dashed var(--rule); }

.banner {
  border: 1px solid var(--rule); border-left: 3px solid var(--rule); border-radius: 8px;
  background: var(--surface); padding: .6rem .8rem; font-size: .81rem; line-height: 1.55;
  color: var(--ink-2); margin-bottom: .8rem;
}
.banner.warn { border-left-color: var(--warn); }
.banner strong { color: var(--ink); }

.tabs { display: flex; gap: 1.3rem; border-bottom: 1px solid var(--rule); margin-bottom: 1rem; }
.tab {
  font: inherit; font-size: .82rem; font-weight: 500; padding: .5rem .1rem;
  border: 0; background: transparent; color: var(--ink-muted); cursor: pointer;
  border-bottom: 2px solid transparent;
}
.tab:hover { color: var(--ink); }
.tab.on { color: var(--ink); font-weight: 600; border-bottom-color: var(--ink); }

.cols { display: flex; gap: 1.1rem; align-items: flex-start; }
.main { flex-grow: 1; min-width: 0; display: flex; flex-direction: column; gap: .65rem; }
.side { width: 268px; flex-shrink: 0; display: flex; flex-direction: column; gap: .65rem; }
.narrow { max-width: 52rem; display: flex; flex-direction: column; gap: .65rem; }

.card { border: 1px solid var(--rule); border-radius: 10px; background: var(--surface);
        padding: .85rem 1rem; }
.card.overruled { border-left: 3px solid var(--warn); }
.lbl.warn { color: var(--warn-ink); }
.verdicthead { display: flex; align-items: baseline; gap: .65rem; margin-bottom: .45rem; flex-wrap: wrap; }
.verdict { font-size: .95rem; font-weight: 640; }
.conf { font-size: .76rem; color: var(--ink-muted); }
.rationale { margin: 0; font-size: .85rem; line-height: 1.6; color: var(--ink-2); }

.sig { width: 100%; border-collapse: collapse; margin-top: .55rem; }
.sig th { padding: 0 .6rem .4rem 0; }
.sig td { padding: .42rem .6rem .42rem 0; border-top: 1px solid var(--rule);
          font-size: .79rem; vertical-align: top; }
.sname { color: var(--ink-2); }
.sval { font-weight: 600; }
.src { font-size: .72rem; }
.sig tr.used { background: var(--plane); }
.used-tag { font-size: .62rem; text-transform: uppercase; letter-spacing: .04em;
            border: 1px solid var(--rule); border-radius: 3px; padding: 0 .25rem; }

.corrections, .overrides { margin: .5rem 0 0; padding-left: 1.1rem;
                           display: flex; flex-direction: column; gap: .4rem; }
.unknowns { margin: .5rem 0 0; padding-left: 0; list-style: none;
            display: flex; flex-direction: column; gap: .4rem; }
.unknowns li { display: flex; gap: .5rem; align-items: baseline; }
.corrections li, .unknowns li, .overrides li { font-size: .81rem; line-height: 1.55; color: var(--ink-2); }
.hatchdot { width: 11px; height: 11px; flex-shrink: 0; border-radius: 2px;
            border: 1px solid var(--rule); transform: translateY(1px); }
.fine { margin: .6rem 0 0; font-size: .72rem; line-height: 1.5; color: var(--ink-muted); }

.card.blocked { border-left: 3px solid var(--warn); }
.fixsummary { margin: .35rem 0 0; font-size: .92rem; line-height: 1.55; color: var(--ink); }
.cmdrow { display: flex; align-items: center; gap: .5rem; margin: .7rem 0 .2rem; }
.cmd { flex-grow: 1; min-width: 0; overflow-x: auto; white-space: pre;
       background: var(--plane); border: 1px solid var(--rule); border-radius: 6px;
       padding: .45rem .6rem; font-size: .78rem; }

.kv { display: flex; justify-content: space-between; gap: .6rem; padding: .24rem 0;
      font-size: .79rem; color: var(--ink-2); }
.details { margin: .6rem 0 0; font-size: .81rem; line-height: 1.6; color: var(--ink-2);
           white-space: pre-line; }
.ev { padding: .5rem 0; border-top: 1px solid var(--rule); }
.evhead { display: flex; justify-content: space-between; gap: .6rem; font-size: .72rem; }
.evclaim { font-size: .81rem; color: var(--ink-2); margin-top: .2rem; }

.unassessed {
  font-size: .66rem; text-transform: uppercase; letter-spacing: .04em; color: var(--ink-muted);
  border: 1px dashed var(--rule); border-radius: 4px; padding: .15rem .38rem; white-space: nowrap;
}
.kevflag { background: var(--sev-critical); color: var(--sev-on-dark);
           padding: 0 .22rem; border-radius: 3px; margin-left: .22rem; }

@media (max-width: 1080px) {
  .cols { flex-direction: column; }
  .side { width: 100%; flex-direction: row; flex-wrap: wrap; }
  .side .card { flex: 1 1 240px; }
}
</style>
