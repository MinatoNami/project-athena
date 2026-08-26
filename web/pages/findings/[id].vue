<script setup lang="ts">
const route = useRoute()
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data: f } = await useAsyncData(`finding-${route.params.id}`, () =>
  api<any>(`findings/${route.params.id}`),
)
useHead({ title: () => f.value?.vulnerability?.id || 'Finding' })

const riskEvidence = computed(() =>
  (f.value?.evidence || []).find((e: any) => e.kind === 'risk'),
)
const riskFactors = computed(() => riskEvidence.value?.value?.factors || null)
const riskOverrides = computed(() => riskEvidence.value?.value?.overrides || [])

function formatSignal(value: any) {
  if (value === true) return 'yes'
  if (value === false) return 'no'
  return String(value)
}

// "unknown" is a legitimate answer, not a failure — it reads as neither yes nor no.
function signalClass(value: any) {
  if (value === true) return 'sig-yes'
  if (value === false) return 'sig-no'
  return 'muted'
}
</script>

<template>
  <div v-if="f" class="wrap">
    <NuxtLink to="/findings" class="muted">← Findings</NuxtLink>
    <h1>{{ f.vulnerability.id }}</h1>
    <p class="sub">
      <SeverityChip
        v-if="f.risk_band"
        :severity="f.risk_band"
        :kev="f.vulnerability.kev"
      />
      <span v-else class="unassessed">unassessed</span>
      <span v-if="f.risk_score != null" class="muted"> {{ f.risk_score }}/100</span>
      <span style="margin-left:.6rem">{{ f.vulnerability.summary || 'No summary published.' }}</span>
    </p>

    <div v-if="f.not_yet_investigated" class="caveat">
      <strong>Candidate match only.</strong>
      This is a version comparison. Nothing has checked whether the affected component
      runs, is reachable, or is exploitable on this asset.
      <template v-if="f.triage?.disposition === 'deprioritise'">
        Triage judged a full investigation unlikely to change the picture, so it has
        not been queued — but that is a judgement about priority, not a conclusion
        that the finding does not apply.
      </template>
      <template v-else-if="f.triage?.disposition === 'investigate'">
        Queued for investigation.
      </template>
    </div>

    <div v-if="f.investigation" class="card">
      <h2>Verdict</h2>
      <p class="verdict-line">
        <strong>{{ f.investigation.verdict.replace('_', ' ') }}</strong>
        <span class="muted">
          · confidence {{ (f.investigation.confidence * 100).toFixed(0) }}%
          · {{ f.investigation.model }}
        </span>
      </p>
      <UntrustedText v-if="f.investigation.rationale" :text="f.investigation.rationale" class="rationale" />

      <p class="muted small">
        Established by calling {{ f.investigation.tools_called.join(', ') || 'no tools' }}
        · {{ f.investigation.tokens.toLocaleString() }} tokens
        · {{ (f.investigation.duration_ms / 1000).toFixed(1) }}s
        <template v-if="f.investigation.shared_with_findings">
          · this answer is shared with {{ f.investigation.shared_with_findings }} other
          finding(s) whose relevant facts are identical
        </template>
      </p>

      <!-- Where the model asserted something it could not support and code overruled
           it. The clearest available signal of how much to trust this verdict, so it
           is shown rather than tucked away. -->
      <div v-if="f.investigation.corrections?.length" class="corrections">
        <strong>{{ f.investigation.corrections.length }} claim(s) were not supported by
          evidence and were downgraded:</strong>
        <ul>
          <li v-for="(c, i) in f.investigation.corrections" :key="i">{{ c }}</li>
        </ul>
      </div>

      <div v-if="f.investigation.uncertainties?.length" class="uncertain">
        <strong>Not determined:</strong>
        <ul>
          <li v-for="(u, i) in f.investigation.uncertainties" :key="i">
            <UntrustedText :text="u" />
          </li>
        </ul>
      </div>

      <table class="signals">
        <thead><tr><th>signal</th><th>value</th><th>confidence</th><th>from</th></tr></thead>
        <tbody>
          <tr v-for="(sig, name) in f.investigation.signals" :key="name">
            <td>{{ String(name).replace(/_/g, ' ') }}</td>
            <td>
              <span :class="signalClass(sig.value)">{{ formatSignal(sig.value) }}</span>
            </td>
            <td class="muted">{{ (sig.confidence * 100).toFixed(0) }}%</td>
            <td class="muted small">{{ (sig.evidence || []).join(', ') || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="riskFactors" class="card">
      <h2>Why this score</h2>
      <p class="muted small">
        Risk is a deterministic function of these factors. The model supplies the
        values; the number is arithmetic, not a judgement.
      </p>
      <table class="kv">
        <tbody>
          <tr v-for="(v, k) in riskFactors" :key="k">
            <th>{{ String(k).replace(/_/g, ' ') }}</th>
            <td>{{ typeof v === 'number' ? v.toFixed(3) : v }}</td>
          </tr>
        </tbody>
      </table>
      <ul v-if="riskOverrides.length" class="overrides">
        <li v-for="(o, i) in riskOverrides" :key="i">{{ o }}</li>
      </ul>
    </div>

    <div class="card">
      <h2>What matched</h2>
      <table class="kv">
        <tbody>
          <tr><th>Asset</th>
            <td><NuxtLink :to="`/assets/${f.asset.id}`">{{ f.asset.display_name }}</NuxtLink>
              <span class="muted"> · {{ f.asset.kind }} · tier {{ f.asset.tier }}</span></td></tr>
          <tr><th>Installed</th>
            <td><code>{{ f.component.name }} {{ f.component.version }}</code>
              <span class="muted"> · {{ f.component.ecosystem }}</span></td></tr>
          <tr><th>Fixed in</th>
            <td>
              {{ f.fixed_version || 'no fix recorded' }}
              <div v-if="f.fix_channel && f.fix_channel !== 'standard'" class="entitlement">
                Delivered through <strong>{{ f.fix_channel.toUpperCase() }}</strong>.
                This needs an Ubuntu Pro entitlement — without one, this package
                cannot be upgraded on this host.
              </div>
            </td></tr>
          <tr v-if="f.matched_source"><th>Matched by</th>
            <td class="muted">{{ f.matched_source }}<template v-if="f.matched_release">
              · release {{ f.matched_release }}</template></td></tr>
          <tr><th>Match</th>
            <td>{{ f.match_method }}
              <span class="muted">({{ (f.match_confidence * 100).toFixed(0) }}% — how the
                match was made, not whether it is exploitable here)</span></td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Evidence</h2>
      <!-- Every claim traces to a row. A conclusion with no evidence is a bug. -->
      <ul class="evidence">
        <li v-for="(e, i) in f.evidence" :key="i">
          <span class="kind">{{ e.kind.replace('_', ' ') }}</span>
          <UntrustedText :text="e.claim" />
          <div v-if="e.source_ref" class="muted small">{{ e.source_ref }}</div>
        </li>
        <li v-if="!f.evidence.length" class="muted">No evidence recorded — this is a defect.</li>
      </ul>
    </div>

    <div class="card">
      <h2>Advisory ranges</h2>
      <p class="muted small">
        Every range published for this package. Sources disagree by design: an
        upstream advisory cannot know whether a distribution backported the fix.
      </p>
      <table>
        <thead><tr><th>source</th><th>release</th><th>introduced</th><th>fixed</th><th></th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in f.advisory_ranges" :key="i" :class="{ used: r.used_for_match }">
            <td><code>{{ r.source }}</code> <span class="muted">auth {{ r.authority }}</span></td>
            <td>{{ r.distro_release || '—' }}</td>
            <td class="muted">{{ r.introduced || '0' }}</td>
            <td>
              {{ r.fixed || r.last_affected || '—' }}
              <span v-if="r.channel && r.channel !== 'standard'" class="channel">{{ r.channel }}</span>
            </td>
            <td class="muted small">{{ r.used_for_match ? 'used for this match' : '' }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Advisory</h2>
      <p class="muted small">
        CVSS {{ f.vulnerability.cvss_score ?? '—' }}
        <template v-if="f.vulnerability.cvss_vector"> · <code>{{ f.vulnerability.cvss_vector }}</code></template>
        <template v-if="f.vulnerability.epss_score"> · EPSS {{ (f.vulnerability.epss_score * 100).toFixed(1) }}%</template>
        · revision {{ f.vulnerability.revision }}
      </p>
      <p v-if="f.vulnerability.aliases?.length" class="muted small">
        Also known as {{ f.vulnerability.aliases.join(', ') }}
      </p>
      <UntrustedText v-if="f.vulnerability.details" :text="f.vulnerability.details" class="details" />
      <ul v-if="f.vulnerability.references?.length" class="refs">
        <!-- Advisory text and links are attacker-influenceable, so URLs are shown as
             text rather than rendered as live anchors. -->
        <li v-for="(r, i) in f.vulnerability.references.slice(0, 8)" :key="i" class="muted small">
          {{ r.type }}: {{ r.url }}
        </li>
      </ul>
    </div>
  </div>
</template>

<style scoped>
.caveat {
  border-left: 3px solid var(--warn); background: var(--surface);
  padding: .7rem .9rem; border-radius: 4px; font-size: .88rem; margin-bottom: 1rem;
  color: var(--ink-2);
}
.kv th { text-align: left; width: 8rem; vertical-align: top; padding: .35rem .5rem .35rem 0; }
.kv td { border: none; padding: .35rem 0; }
.evidence { list-style: none; padding: 0; margin: 0; }
.evidence li { padding: .5rem 0; border-top: 1px solid var(--rule); font-size: .9rem; }
.evidence li:first-child { border-top: none; }
.kind {
  display: inline-block; font-size: .68rem; text-transform: uppercase; letter-spacing: .05em;
  color: var(--ink-muted); margin-right: .5rem;
}
.used { background: var(--plane); font-weight: 500; }
.small { font-size: .8rem; }
.details { display: block; white-space: pre-wrap; font-size: .87rem; color: var(--ink-2); max-height: 22rem; overflow: auto; }
.refs { padding-left: 1.1rem; margin: .6rem 0 0; }
.unassessed {
  font-size: .72rem; text-transform: uppercase; letter-spacing: .04em;
  color: var(--ink-muted); border: 1px dashed var(--rule);
  border-radius: 4px; padding: .14rem .4rem;
}
.verdict-line { margin: 0 0 .5rem; font-size: 1rem; }
.rationale { display: block; font-size: .9rem; color: var(--ink-2); margin-bottom: .7rem; }
.corrections {
  border-left: 3px solid var(--warn); padding: .5rem .8rem; margin: .8rem 0;
  font-size: .85rem; background: var(--plane); border-radius: 4px;
}
.corrections ul, .uncertain ul { margin: .3rem 0 0; padding-left: 1.1rem; }
.uncertain { font-size: .85rem; color: var(--ink-2); margin: .8rem 0; }
.signals { margin-top: .9rem; }
.sig-yes { color: var(--crit); font-weight: 600; }
.sig-no { color: var(--good); }
.overrides { margin: .7rem 0 0; padding-left: 1.1rem; font-size: .85rem; color: var(--ink-2); }
.entitlement {
  margin-top: .35rem; font-size: .82rem; color: var(--ink-2);
  border-left: 2px solid var(--warn); padding-left: .5rem;
}
.channel {
  font-size: .65rem; text-transform: uppercase; letter-spacing: .04em;
  border: 1px solid var(--rule); border-radius: 3px; padding: 0 .25rem;
  color: var(--warn-ink); margin-left: .3rem;
}
</style>
