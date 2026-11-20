<script setup lang="ts">
/**
 * One asset: is it read, what is in it, and what happened last time we looked.
 *
 * The page used to answer the third question with the scanner's stderr. Outcomes
 * are now stated in words and the raw text kept behind a disclosure — the engineer
 * who wants it loses nothing, and the reader who does not is no longer shown a
 * failure they cannot act on.
 */
const route = useRoute()
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data: asset, refresh } = await useAsyncData(`asset-${route.params.id}`, () =>
  api<any>(`assets/${route.params.id}`),
)
const scanning = ref(false)
const scanNote = ref<{ text: string; failed: boolean } | null>(null)
const showPackages = ref(false)
const openRun = ref<string | null>(null)
useHead({ title: () => asset.value?.display_name || 'Asset' })

// A host is not scanned from here — its node is asked to observe again — so the
// button says what it will actually do.
const scanLabel = computed(() =>
  asset.value?.scan?.action === 'collect' ? 'Collect now' : 'Rescan',
)

async function rescan() {
  scanning.value = true
  scanNote.value = null
  try {
    const res = await api<{ message?: string }>(`assets/${route.params.id}/scan`, {
      method: 'POST',
    })
    scanNote.value = { text: res.message || 'Scan queued.', failed: false }
  } catch (e: any) {
    // This used to be swallowed: the button went back to idle whether or not
    // anything had been queued, so a refusal was indistinguishable from a scan.
    scanNote.value = {
      text: e?.data?.detail || e?.message || 'The scan could not be queued.',
      failed: true,
    }
  } finally {
    scanning.value = false
  }
}
useEvents(['assets'], refresh)

/** What is actually inside, by ecosystem — the shape of the dependency surface. */
const ecosystems = computed(() => {
  const counts = new Map<string, number>()
  for (const c of asset.value?.components ?? []) {
    counts.set(c.ecosystem || 'unknown', (counts.get(c.ecosystem || 'unknown') ?? 0) + 1)
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([label, value]) => ({ label, value }))
})

/** Unknown is not zero: an unread asset gets a dashed row, not an empty chart. */
const ecosystemRows = computed(() =>
  asset.value?.never_inventoried
    ? [{ label: 'contents', value: null, hint: 'never read' }]
    : ecosystems.value,
)

const runs = computed(() =>
  (asset.value?.scan_runs ?? []).map((r: any) => ({ ...r, outcome: scanOutcome(r) })),
)

// The inventory verdict comes from the latest *inventory* run. A secrets scan that
// finished after it says nothing about which packages are installed.
const lastRun = computed(
  () => runs.value.find((r: any) => !CODE_SCAN_KINDS.includes(r.kind)) ?? null,
)

const exporting = ref<string | null>(null)
async function exportDoc(kind: 'sbom' | 'vex') {
  exporting.value = kind
  scanNote.value = null
  const safe = String(asset.value?.display_name ?? 'asset').replace(/[^A-Za-z0-9._-]+/g, '-')
  try {
    if (kind === 'sbom') {
      await downloadJson(`assets/${route.params.id}/sbom`, `${safe}.cdx.json`)
    } else {
      await downloadJson(`export/openvex?asset_id=${route.params.id}`, `${safe}.openvex.json`)
    }
  } catch (e: any) {
    scanNote.value = { text: e?.data?.detail || 'The export could not be produced.', failed: true }
  } finally {
    exporting.value = null
  }
}
</script>

<template>
  <div v-if="asset" class="page">
    <nav class="crumbs">
      <NuxtLink to="/assets">Assets</NuxtLink>
      <span>/</span>
      <span>{{ asset.display_name }}</span>
    </nav>

    <div class="page-head">
      <div class="page-title">
        <h1>{{ asset.display_name }}</h1>
        <p>{{ asset.kind }} · <code>{{ asset.identity_key }}</code></p>
      </div>
      <div class="actions">
        <button class="btn" :disabled="!!exporting" title="CycloneDX 1.6 SBOM of what was last observed"
                @click="exportDoc('sbom')">
          {{ exporting === 'sbom' ? 'Exporting…' : 'SBOM' }}
        </button>
        <button class="btn" :disabled="!!exporting"
                title="OpenVEX: not_affected only where a person decided it" @click="exportDoc('vex')">
          {{ exporting === 'vex' ? 'Exporting…' : 'VEX' }}
        </button>
        <button v-if="asset.scan?.supported" class="btn" :disabled="scanning" @click="rescan">
          {{ scanning ? 'Queued…' : scanLabel }}
        </button>
      </div>
    </div>

    <p v-if="scanNote" :class="scanNote.failed ? 'err' : 'note'">{{ scanNote.text }}</p>
    <p v-else-if="asset.scan && !asset.scan.supported" class="note">{{ asset.scan.reason }}</p>

    <div class="tiles">
      <div class="tile-slot">
        <span class="lbl">Last read</span>
        <FreshnessIndicator
          :at="asset.last_inventoried_at"
          :never-inventoried="asset.never_inventoried"
          :stale="asset.stale"
        />
      </div>
      <StatTile
        label="Packages"
        :value="asset.never_inventoried ? null : asset.component_count?.toLocaleString()"
        :of="asset.never_inventoried ? undefined : `in ${ecosystems.length || 1} ecosystems`"
        hint="unknown, not zero"
      />
      <StatTile
        label="Importance"
        :value="asset.criticality ?? '—'"
        :of="asset.criticality === null ? 'unset — scored as middling' : 'of 5'"
        :status="asset.criticality === null ? 'warn' : null"
      />
      <StatTile label="Placement" :value="asset.tier" :of="`${asset.exposure}-facing`" />
    </div>

    <div class="cols">
      <ChartFrame
        title="What is in it"
        :note="asset.never_inventoried ? 'nothing has read this asset' : 'top ecosystems by package count'"
        :empty="!asset.never_inventoried && !ecosystems.length"
        empty-text="Read successfully, and nothing was found inside."
        :table="{
          columns: ['Ecosystem', 'Packages'],
          rows: ecosystems.map(e => [e.label, e.value]),
        }"
      >
        <ChartBars
          :rows="ecosystemRows"
          unit="packages"
          :summary="`Package count by ecosystem for ${asset.display_name}`"
        />
      </ChartFrame>

      <div class="card runs">
        <div class="runhead">
          <span class="lbl">Every time we looked</span>
          <span v-if="lastRun" class="state" :class="lastRun.outcome.state">
            {{ lastRun.outcome.state === 'covered' ? '✓ read'
              : lastRun.outcome.state === 'partial' ? '◐ partly read' : '⃠ unread' }}
          </span>
        </div>

        <p v-if="!runs.length" class="muted">Never looked at. Contents unknown, not clean.</p>

        <div v-for="r in runs" :key="r.id" class="run">
          <span class="mark" :class="r.outcome.state" aria-hidden="true">
            {{ r.outcome.state === 'covered' ? '✓' : r.outcome.state === 'partial' ? '◐' : '⃠' }}
          </span>
          <div class="runbody">
            <div class="runline">
              <span>{{ r.outcome.headline }}</span>
              <span class="when">{{ new Date(r.started_at).toLocaleDateString() }}</span>
            </div>
            <button
              v-if="r.outcome.detail"
              class="disclose"
              @click="openRun = openRun === r.id ? null : r.id"
            >
              {{ openRun === r.id ? 'Hide' : 'Scanner output' }} · {{ r.tool }}
            </button>
            <pre v-if="openRun === r.id" class="raw">{{ r.outcome.detail }}</pre>
          </div>
        </div>
      </div>
    </div>

    <div v-if="asset.kind === 'repository'" class="card codecard">
      <div class="lbl codelbl">Secrets &amp; configuration in this repository</div>
      <CodeFindingsPanel :asset-id="String(route.params.id)" compact />
    </div>

    <div v-if="asset.merge_candidates?.length" class="card">
      <span class="lbl">Possible duplicates — never merged automatically</span>
      <ul class="merges">
        <li v-for="m in asset.merge_candidates" :key="m.id">
          {{ m.reason }} <span class="muted">({{ m.confidence }})</span>
        </li>
      </ul>
    </div>

    <div class="card">
      <button class="disclose" @click="showPackages = !showPackages">
        {{ showPackages ? 'Hide' : 'Show' }} all {{ asset.component_count?.toLocaleString() ?? 0 }}
        packages
      </button>
      <table v-if="showPackages && !asset.never_inventoried">
        <thead><tr><th>package</th><th>version</th><th>ecosystem</th><th>scope</th></tr></thead>
        <tbody>
          <tr v-for="c in asset.components" :key="c.id">
            <td>{{ c.name }}</td>
            <td class="mono">{{ c.version }}</td>
            <td class="muted">{{ c.ecosystem }}</td>
            <td class="muted">{{ c.scope }}</td>
          </tr>
          <tr v-if="!asset.components?.length">
            <td colspan="4" class="muted">No packages found.</td>
          </tr>
        </tbody>
      </table>
      <p v-else-if="showPackages" class="muted">
        Not read, so this list is unknown rather than empty.
      </p>
    </div>
  </div>
</template>

<style scoped>
.crumbs { display: flex; align-items: center; gap: .4rem; font-size: .76rem;
          color: var(--ink-muted); margin-bottom: .75rem; }
.crumbs a { color: var(--ink-muted); }

.tiles { display: flex; flex-wrap: wrap; gap: 1.6rem; padding: .8rem .95rem;
         border: 1px solid var(--rule); border-radius: 9px; background: var(--surface);
         margin-bottom: 1rem; }
.tile-slot { display: flex; flex-direction: column; gap: .3rem; }

.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; align-items: start;
        margin-bottom: 1rem; }
.card { margin: 0; padding: .7rem .85rem .75rem; }

.runhead { display: flex; align-items: center; justify-content: space-between;
           gap: .5rem; margin-bottom: .5rem; }
.state { font-size: .72rem; font-weight: 600; }
.run { display: flex; gap: .55rem; padding: .4rem 0; border-top: 1px solid var(--rule); }
.run:first-of-type { border-top: 0; }
.runbody { flex-grow: 1; min-width: 0; }
.runline { display: flex; gap: .6rem; justify-content: space-between; font-size: .8rem;
           color: var(--ink-2); }
.when { color: var(--ink-muted); font-size: .72rem; white-space: nowrap; }
.mark { flex-shrink: 0; width: 1rem; text-align: center; font-size: .82rem; }
.covered { color: var(--good); }
.partial { color: var(--warn-ink); }
.unknown { color: var(--crit); }

.disclose { font: inherit; font-size: .71rem; padding: 0; border: 0; background: none;
            color: var(--ink-muted); cursor: pointer; text-decoration: underline;
            text-underline-offset: 2px; }
.disclose:hover { color: var(--ink); }
.raw { margin: .35rem 0 0; padding: .5rem .6rem; background: var(--plane);
       border: 1px solid var(--rule); border-radius: 6px; font-size: .7rem;
       white-space: pre-wrap; word-break: break-word; color: var(--ink-2); max-height: 11rem;
       overflow: auto; }
.codecard { margin-bottom: 1rem; }
.codelbl { margin-bottom: .6rem; }
.merges { margin: .4rem 0 0; padding-left: 1.1rem; font-size: .8rem; color: var(--ink-2); }

@media (max-width: 1000px) { .cols { grid-template-columns: 1fr; } }
</style>
