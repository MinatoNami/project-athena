<script setup lang="ts">
const route = useRoute()
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data: f } = await useAsyncData(`finding-${route.params.id}`, () =>
  api<any>(`findings/${route.params.id}`),
)
useHead({ title: () => f.value?.vulnerability?.id || 'Finding' })
</script>

<template>
  <div v-if="f" class="wrap">
    <NuxtLink to="/findings" class="muted">← Findings</NuxtLink>
    <h1>{{ f.vulnerability.id }}</h1>
    <p class="sub">
      <SeverityChip :severity="f.vulnerability.provisional_severity" :kev="f.vulnerability.kev" />
      <span style="margin-left:.6rem">{{ f.vulnerability.summary || 'No summary published.' }}</span>
    </p>

    <div v-if="f.not_yet_investigated" class="caveat">
      <strong>Candidate match only.</strong>
      This is a version comparison. Athena has not checked whether the affected
      component is running, reachable, or exploitable on this asset — that
      investigation is not built yet.
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
          <tr><th>Fixed in</th><td>{{ f.fixed_version || 'no fix recorded' }}</td></tr>
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
            <td>{{ r.fixed || r.last_affected || '—' }}</td>
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
</style>
