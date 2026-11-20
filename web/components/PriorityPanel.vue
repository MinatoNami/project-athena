<script setup lang="ts">
/**
 * Exploitability, beside the score rather than inside it.
 *
 * The risk band answers "how bad is this here?" with Athena's own arithmetic. This
 * panel answers the questions people ask before they believe it — is it being
 * exploited, how likely is it to be, what does the vector say — with the public
 * facts behind each, and the SSVC outcome those facts imply in CISA's vocabulary.
 *
 * Every decision point shows the fact it was read from. A point Athena had to
 * assume is hatched, the way every not-observed value is (rule 1): the outcome is
 * only as solid as its weakest input, and that has to be visible.
 */
const props = defineProps<{ p: any }>()

const ssvc = computed(() => props.p?.ssvc)
const STEPS = [
  { key: 'exploitation', label: 'Exploitation' },
  { key: 'automatable', label: 'Automatable' },
  { key: 'technical_impact', label: 'Technical impact' },
  { key: 'mission_wellbeing', label: 'Mission & well-being' },
]

const kev = computed(() => props.p?.kev)
const dl = computed(() => props.p?.deadline)
const fromCisa = computed(() => !!props.p?.cisa_ssvc?.published)

const DL_INPUTS = [
  { key: 'exposed', label: 'Publicly exposed' },
  { key: 'kev', label: 'In KEV' },
  { key: 'automatable', label: 'Automatable' },
  { key: 'total_impact', label: 'Total impact' },
]
const dlText = computed(() => {
  const d = dl.value
  if (!d) return null
  if (d.on_upgrade) return 'Fix in the next system upgrade'
  const left = d.days_left
  const when = left < 0 ? `${-left} day${left === -1 ? '' : 's'} overdue`
    : left === 0 ? 'due today' : `${left} day${left === 1 ? '' : 's'} left`
  return `${d.days}-day deadline · due ${d.due} · ${when}`
})
const epss = computed(() => props.p?.epss)
const cvss = computed(() => props.p?.cvss)

const dueText = computed(() => {
  const d = kev.value?.days_to_due
  if (d == null) return null
  if (d < 0) return `${-d} day${d === -1 ? '' : 's'} overdue`
  if (d === 0) return 'due today'
  return `${d} day${d === 1 ? '' : 's'} left`
})

/** CVSS metrics in words, so the vector is readable without the spec open. */
const METRICS: Record<string, [string, Record<string, string>]> = {
  AV: ['Attack vector', { N: 'network', A: 'adjacent', L: 'local', P: 'physical' }],
  AC: ['Complexity', { L: 'low', H: 'high' }],
  AT: ['Attack requirements', { N: 'none', P: 'present' }],
  PR: ['Privileges', { N: 'none', L: 'low', H: 'high' }],
  UI: ['User interaction', { N: 'none', R: 'required', P: 'passive', A: 'active' }],
  S: ['Scope', { U: 'unchanged', C: 'changed' }],
  C: ['Confidentiality', { H: 'high', L: 'low', N: 'none' }],
  I: ['Integrity', { H: 'high', L: 'low', N: 'none' }],
  A: ['Availability', { H: 'high', L: 'low', N: 'none' }],
  VC: ['Confidentiality', { H: 'high', L: 'low', N: 'none' }],
  VI: ['Integrity', { H: 'high', L: 'low', N: 'none' }],
  VA: ['Availability', { H: 'high', L: 'low', N: 'none' }],
}
/** The value of each metric that most favours an attacker, emphasised in the list. */
const WORST: Record<string, string> = {
  AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', S: 'C',
  C: 'H', I: 'H', A: 'H', VC: 'H', VI: 'H', VA: 'H',
}
const metrics = computed(() => {
  const vector: string | null = cvss.value?.vector
  if (!vector) return []
  return vector.split('/').slice(1).flatMap((part) => {
    const [k, v] = part.split(':')
    const known = k ? METRICS[k] : undefined
    if (!k || !known || !v) return []
    return [{ key: k, label: known[0], value: known[1][v] ?? v, worst: WORST[k] === v }]
  })
})

function pct(v: number | null | undefined, digits = 1) {
  return v == null ? null : `${(v * 100).toFixed(digits)}%`
}
</script>

<template>
  <div class="prio">
    <div v-if="p?.malicious" class="card malware">
      <div class="lbl crit">Malicious package</div>
      <p>
        This is a published OpenSSF malicious-packages record, not a flaw in a
        legitimate release. Exploitation is not a question here: installing it was
        the attack. See <strong>Fix</strong> for removal and response.
      </p>
    </div>

    <!-- ══ SSVC ══ -->
    <div v-if="ssvc" class="card">
      <div class="ssvchead">
        <div>
          <div class="lbl">SSVC decision</div>
          <div class="outcome">
            <SsvcChip :outcome="ssvc.outcome" />
            <span class="meaning">{{ ssvc.meaning }}</span>
          </div>
        </div>
        <span class="fine framework">{{ ssvc.framework }}</span>
      </div>

      <ol class="path">
        <li
          v-for="s in STEPS" :key="s.key" class="step"
          :class="{ assumed: ssvc.points[s.key]?.assumed }"
        >
          <span class="lbl">{{ s.label }}</span>
          <span class="val" :class="{ hatch: ssvc.points[s.key]?.assumed }">
            {{ ssvc.points[s.key]?.value }}
          </span>
          <span class="basis">{{ ssvc.points[s.key]?.basis }}</span>
        </li>
      </ol>
      <ul v-if="ssvc.notes?.length" class="notes">
        <li v-for="(n, i) in ssvc.notes" :key="i">{{ n }}</li>
      </ul>
      <p class="fine">
        <template v-if="fromCisa">
          Exploitation, automatable and technical impact are CISA's own assessment of this
          CVE (Vulnrichment), except that a KEV listing always means active exploitation.
        </template>
        <template v-else>
          CISA has published no assessment for this identifier, so automatable and
          technical impact are mapped from the CVSS vector.
        </template>
        Mission &amp; well-being is what you have said about the asset; classify it to
        firm this up.
      </p>
    </div>

    <!-- ══ BOD 26-04 ══ -->
    <div v-if="dl" class="card">
      <div class="ssvchead">
        <div>
          <div class="lbl">Remediation deadline</div>
          <p class="dltext" :class="{ crit: dl.days_left != null && dl.days_left <= 0 }">{{ dlText }}</p>
        </div>
        <span class="fine framework">{{ dl.framework }}</span>
      </div>
      <div class="dlinputs">
        <span
          v-for="i in DL_INPUTS" :key="i.key" class="dlin"
          :class="{ assumed: dl.inputs[i.key]?.assumed }" :title="dl.inputs[i.key]?.basis"
        >
          {{ i.label }} <strong :class="{ hatch: dl.inputs[i.key]?.assumed }">{{ dl.inputs[i.key]?.value ? 'yes' : 'no' }}</strong>
        </span>
      </div>
      <ul v-if="dl.notes?.length" class="notes">
        <li v-for="(n, i) in dl.notes" :key="i">{{ n }}</li>
      </ul>
      <p class="fine">
        The clock started {{ dl.clock_start }} — the earlier of Athena first seeing this
        here and its addition to KEV. Binding on US federal agencies; a benchmark for
        everyone else. Hover an input for where it came from.
      </p>
    </div>

    <div class="grid">
      <!-- ══ Known exploitation ══ -->
      <div class="card">
        <div class="lbl">Known exploitation</div>
        <template v-if="kev?.listed">
          <p class="big crit">In CISA KEV</p>
          <div class="kv"><span>Added by CISA</span>
            <span class="muted">{{ kev.date_added || 'date not published' }}</span></div>
          <div class="kv"><span>CISA due date</span>
            <span :class="{ overdue: kev.days_to_due != null && kev.days_to_due < 0 }">
              {{ kev.due_date || '—' }}
              <span v-if="dueText" class="muted"> · {{ dueText }}</span>
            </span></div>
          <div class="kv"><span>Ransomware use</span>
            <span class="muted">{{ kev.ransomware ? 'known' : 'not known' }}</span></div>
          <p class="fine">
            The due date is the deadline CISA sets for federal agencies — a strong
            external benchmark, not a rule Athena enforces.
          </p>
        </template>
        <template v-else>
          <p class="big">Not in KEV</p>
          <p class="fine">
            Absence from the catalogue means CISA has not confirmed exploitation — not
            that none is happening.
          </p>
        </template>
      </div>

      <!-- ══ EPSS ══ -->
      <div class="card">
        <div class="lbl">Exploit likelihood (EPSS)</div>
        <template v-if="epss?.scored">
          <p class="big mono tnum">{{ pct(epss.score) }}</p>
          <div class="track"><span class="fill" :style="{ width: `${Math.max(2, (epss.percentile ?? 0) * 100)}%` }" /></div>
          <p class="fine">
            Probability of exploitation activity in the next 30 days.
            <template v-if="epss.percentile != null && epss.percentile >= 0.99">
              Among the top 1% of scored CVEs.
            </template>
            <template v-else-if="epss.percentile != null">
              Higher than {{ pct(epss.percentile, 0) }} of scored CVEs.
            </template>
          </p>
        </template>
        <template v-else>
          <p class="big"><span class="hatchbox hatch" /> not scored</p>
          <p class="fine">
            FIRST has not published a score for this identifier — usually because it is
            new or not a CVE. Athena assumes some pressure rather than none.
          </p>
        </template>
      </div>

      <!-- ══ CVSS ══ -->
      <div class="card">
        <div class="lbl">CVSS {{ cvss?.version || '' }}</div>
        <template v-if="cvss?.vector">
          <p class="big mono tnum">
            {{ cvss.score != null ? cvss.score.toFixed(1) : '—' }}
            <span v-if="cvss.score == null" class="fine"> v4 is recorded, not scored</span>
          </p>
          <div class="metrics">
            <span v-for="m in metrics" :key="m.key" class="metric" :class="{ worst: m.worst }">
              {{ m.label }} <strong>{{ m.value }}</strong>
            </span>
          </div>
          <p class="fine">
            {{ cvss.computed_from_vector
              ? 'Base score computed by Athena from the published vector.'
              : cvss.score != null ? 'Score as published by the advisory.'
              : 'The severity word published with the advisory is used instead.' }}
          </p>
        </template>
        <template v-else>
          <p class="big"><span class="hatchbox hatch" /> no vector</p>
          <p class="fine">The advisory publishes no CVSS vector; its severity word is used.</p>
        </template>
      </div>
    </div>
  </div>
</template>

<style scoped>
.prio { display: flex; flex-direction: column; gap: .8rem; }
.card { border: 1px solid var(--rule); border-radius: 9px; background: var(--surface); padding: .9rem 1rem; }
.malware { border: 1.5px solid var(--crit); }
.malware p { margin: .4rem 0 0; font-size: .85rem; line-height: 1.55; color: var(--ink-2); }
.lbl.crit, .crit { color: var(--crit); }
.ssvchead { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; }
.outcome { display: flex; align-items: center; gap: .6rem; margin-top: .35rem; flex-wrap: wrap; }
.meaning { font-size: .84rem; color: var(--ink-2); }
.framework { white-space: nowrap; }

.path { list-style: none; padding: 0; margin: .9rem 0 .4rem; display: grid;
        grid-template-columns: repeat(4, 1fr); gap: .5rem; counter-reset: step; }
.step { position: relative; border: 1px solid var(--rule); border-radius: 8px; padding: .55rem .65rem;
        display: flex; flex-direction: column; gap: .25rem; background: var(--plane); }
.step:not(:last-child)::after {
  content: '›'; position: absolute; right: -.48rem; top: 50%; transform: translateY(-50%);
  color: var(--ink-muted); font-size: .9rem; background: var(--surface); line-height: 1;
}
.step.assumed { border-style: dashed; }
.val { font-weight: 640; font-size: .92rem; text-transform: capitalize; padding: 0 .15rem;
       align-self: flex-start; border-radius: 3px; }
.basis { font-size: .72rem; color: var(--ink-muted); line-height: 1.4; }
.dltext { margin: .3rem 0 0; font-size: .92rem; font-weight: 600; }
.dlinputs { display: flex; flex-wrap: wrap; gap: .4rem; margin: .7rem 0 .2rem; }
.dlin { font-size: .74rem; padding: .18rem .45rem; border: 1px solid var(--rule); border-radius: 5px;
        color: var(--ink-muted); background: var(--plane); cursor: help; }
.dlin strong { color: var(--ink); font-weight: 600; padding: 0 .1rem; border-radius: 3px; }
.dlin.assumed { border-style: dashed; }
.notes { margin: .5rem 0 0; padding-left: 1.1rem; font-size: .78rem; color: var(--warn-ink); }

.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: .8rem; }
.big { font-size: 1.15rem; font-weight: 640; margin: .35rem 0 .45rem; display: flex; align-items: center; gap: .4rem; }
.kv { display: flex; justify-content: space-between; gap: .6rem; font-size: .8rem; padding: .22rem 0;
      border-top: 1px solid var(--rule); }
.overdue { color: var(--crit); font-weight: 600; }
.fine { font-size: .72rem; color: var(--ink-muted); margin: .5rem 0 0; line-height: 1.45; }
.track { height: 4px; border-radius: 2px; background: var(--rule); overflow: hidden; }
.fill { display: block; height: 100%; background: var(--ink-2); }
.metrics { display: flex; flex-wrap: wrap; gap: .3rem; }
.metric { font-size: .68rem; padding: .08rem .35rem; border: 1px solid var(--rule); border-radius: 4px;
          color: var(--ink-muted); background: var(--plane); }
.metric strong { color: var(--ink-2); font-weight: 600; }
.metric.worst { border-color: var(--ink-muted); }
.metric.worst strong { color: var(--ink); }
.hatchbox { display: inline-block; width: 1.6rem; height: .85rem; border-radius: 3px; border: 1px dashed var(--rule); }

@media (max-width: 1080px) {
  .path { grid-template-columns: 1fr 1fr; }
  .step::after { display: none; }
  .grid { grid-template-columns: 1fr; }
}
</style>
