<script setup lang="ts">
/**
 * Intelligence: where every fact on every finding comes from, and how old it is.
 *
 * Stale intelligence looks exactly like a quiet week (§10 rule 6), so each source
 * states its age and its last error, and "never fetched" is its own state rather
 * than an old timestamp. Since April 2026 the NVD no longer enriches most CVEs,
 * which makes per-source provenance more than housekeeping: a severity, an
 * exploitation flag and a decision point may each come from a different publisher.
 */
useHead({ title: 'Intelligence' })
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data, pending, error, refresh } = await useAsyncData('intel', () =>
  api<any>('intel/sources'),
)
useEvents(['jobs'], refresh)

const refreshing = ref(false)
const note = ref<string | null>(null)
async function refreshAll() {
  refreshing.value = true
  note.value = null
  try {
    const res = await api<{ queued: number }>('intel/refresh', { method: 'POST' })
    note.value = res.queued
      ? `${res.queued} fetch${res.queued === 1 ? '' : 'es'} queued. Ages update as each finishes.`
      : 'Every source already has a fetch queued.'
  } catch (e: any) {
    note.value = e?.data?.detail || 'The refresh could not be queued.'
  } finally {
    refreshing.value = false
  }
}

/** What each source contributes, in a sentence, so a row is not just a name. */
const ROLE: Record<string, string> = {
  kev: 'CISA Known Exploited Vulnerabilities — confirmed exploitation, due dates, forensic-triage flags.',
  epss: 'FIRST EPSS — probability of exploitation activity in the next 30 days.',
  vulnrichment: "CISA Vulnrichment — CISA's own SSVC assessment per CVE.",
}
function role(name: string) {
  if (name.startsWith('osv:')) {
    return `OSV ${name.slice(4)} — affected ranges, fixed versions and severities; includes OpenSSF malicious-package (MAL-) records.`
  }
  return ROLE[name] ?? ''
}

function age(seconds: number | null) {
  if (seconds == null) return null
  if (seconds < 5400) return `${Math.max(1, Math.round(seconds / 60))} min`
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h`
  return `${Math.round(seconds / 86400)} d`
}
function stale(s: any) {
  if (s.never_succeeded) return true
  const limit = s.name === 'epss' ? 2 * 86400 : s.name === 'vulnrichment' ? 2 * 86400 : 6 * 3600
  return (s.age_seconds ?? Infinity) > limit
}

const epssModel = computed(() => {
  const cursor: string | undefined = data.value?.sources?.find((s: any) => s.name === 'epss')?.cursor
  if (!cursor) return null
  const [model, date] = cursor.split('@')
  return { model, date: date?.slice(0, 10) }
})

const ssvc = computed(() => data.value?.cisa_ssvc)
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Intelligence</h1>
        <p>
          Every source Athena correlates against, how fresh it is, and what it
          contributes. A source that has not been fetched recently is a reason to
          distrust a quiet day.
        </p>
      </div>
      <div class="actions">
        <button class="btn primary" :disabled="refreshing" @click="refreshAll">
          {{ refreshing ? 'Queuing…' : 'Refresh all sources' }}
        </button>
      </div>
    </div>
    <p v-if="note" class="note">{{ note }}</p>

    <RowSkeleton v-if="pending && !data" :rows="4" />
    <StateBlock v-else-if="error" kind="error" title="Cannot reach Athena">
      The core service did not answer.
      <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
    </StateBlock>

    <template v-else-if="data">
      <div class="tiles card">
        <StatTile label="Advisories" :value="data.advisories?.toLocaleString()" of="in the corpus" />
        <StatTile label="Known exploited" :value="data.kev_advisories?.toLocaleString()" of="CISA KEV" />
        <StatTile label="Malicious packages" :value="data.malicious_advisories?.toLocaleString()"
                  of="OpenSSF MAL- records, not withdrawn" />
        <StatTile
          label="CISA SSVC"
          :value="ssvc ? ssvc.published : null"
          :of="ssvc ? `of ${ssvc.cves_with_findings} CVEs with findings (${ssvc.checked} checked)` : undefined"
          :progress="ssvc?.cves_with_findings ? ssvc.checked / ssvc.cves_with_findings : null"
          hint="not yet checked"
        />
        <StatTile
          label="EPSS model"
          :value="epssModel?.model ?? null"
          :of="epssModel?.date ? `scores of ${epssModel.date}` : undefined"
          hint="no EPSS fetch has recorded its model yet"
        />
      </div>

      <div class="card">
        <span class="lbl">Sources</span>
        <table class="sources">
          <thead>
            <tr><th>Source</th><th>Contributes</th><th>Age</th><th>Records</th><th>Last error</th></tr>
          </thead>
          <tbody>
            <tr v-for="s in data.sources" :key="s.name" :class="{ stale: stale(s) }">
              <td class="name">
                <span class="dot" :class="stale(s) ? 'down' : 'live'" />
                <code>{{ s.name }}</code>
              </td>
              <td class="role">{{ role(s.name) }}</td>
              <td class="mono tnum">
                <span v-if="s.never_succeeded" class="never hatch">never fetched</span>
                <template v-else>{{ age(s.age_seconds) }}</template>
              </td>
              <td class="mono tnum">{{ (s.advisories ?? 0).toLocaleString() }}</td>
              <td class="errcell">
                <UntrustedText v-if="s.last_error" :text="s.last_error" />
                <span v-else class="muted">—</span>
              </td>
            </tr>
            <tr v-if="!data.sources?.length">
              <td colspan="5" class="muted">
                No source has been fetched. Nothing has been correlated — not a clean result.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card notes">
        <span class="lbl">How these combine</span>
        <ul>
          <li>
            <strong>CVSS</strong> base scores are computed by Athena from the published v3
            vector. v4 vectors are recorded and read for decision points, but not scored.
          </li>
          <li>
            <strong>SSVC</strong> uses CISA's own assessment where Vulnrichment has one,
            and otherwise maps the CVSS vector — every decision point says which.
          </li>
          <li>
            <strong>BOD 26-04</strong> deadlines are computed per asset as a benchmark: they
            bind US federal agencies, and are a widely recognised yardstick for everyone else.
          </li>
          <li>
            <strong>Malicious packages</strong> are treated as compromise, not as flaws: they
            lead the queue, and their remediation is removal and credential rotation.
            Withdrawn reports stop ranking.
          </li>
        </ul>
      </div>
    </template>
  </div>
</template>

<style scoped>
.tiles { display: flex; flex-wrap: wrap; gap: 1.6rem; padding: .9rem 1rem; margin-bottom: 1rem; }
.card { margin-bottom: 1rem; }
.sources { margin-top: .5rem; }
.sources td { vertical-align: top; }
.name { white-space: nowrap; }
.role { font-size: .78rem; color: var(--ink-2); max-width: 34rem; }
.errcell { font-size: .74rem; color: var(--crit); max-width: 18rem; word-break: break-word; }
tr.stale .name code { color: var(--warn-ink); }
.never { font-size: .7rem; padding: .05rem .3rem; border: 1px dashed var(--rule); border-radius: 3px;
         font-family: system-ui, sans-serif; }
.notes ul { margin: .5rem 0 0; padding-left: 1.1rem; font-size: .82rem; color: var(--ink-2); line-height: 1.55; }
.note { font-size: .82rem; color: var(--ink-2); }
@media (max-width: 860px) { .role { display: none; } }
</style>
