<script setup lang="ts">
useHead({ title: 'Metrics' })

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data, pending, error, refresh } = await useAsyncData('metrics', () => api<any>('metrics'))
const { severity } = useChartTheme()

function formatted(m: any) {
  if (m.value === null) return null
  if (m.unit === 'tokens') return m.value.toLocaleString()
  if (m.unit === '%') return `${m.value}%`
  if (m.unit === 'hours') return `${m.value}h`
  if (m.unit === 'days') return `${m.value}d`
  return String(m.value)
}

function suffix(m: any) {
  return m.unit === '%' ? '%' : m.unit === 'hours' ? 'h' : m.unit === 'days' ? 'd' : ''
}

function progress(m: any) {
  if (m.value === null || m.target_mvp === null || !m.target_mvp) return null
  const share = m.lower_is_better ? m.target_mvp / m.value : m.value / m.target_mvp
  return Math.max(0, Math.min(1, share))
}

const STATUS: Record<string, 'good' | 'bad' | 'warn' | null> = {
  meeting: 'good', missing: 'bad', no_target: null, unknown: 'warn', not_implemented: null,
}

const measured = computed(() => data.value?.metrics?.filter((m: any) => m.value !== null) ?? [])
const unanswered = computed(() => data.value?.metrics?.filter((m: any) => m.value === null) ?? [])

const slaRows = computed(() =>
  (data.value?.sla?.bands ?? []).map((b: any) => ({
    label: b.band,
    value: b.open,
    color: severity.value[b.band],
    hint: b.status === 'none_open'
      ? 'none open'
      : b.late ? `${b.late} past ${b.target_days}d` : `within ${b.target_days}d`,
  })),
)
const anyOpen = computed(() => slaRows.value.some((r: any) => r.value > 0))

const slaTable = computed(() => ({
  columns: ['Band', 'Target', 'Open', 'Overdue', 'Oldest'],
  rows: (data.value?.sla?.bands ?? []).map((b: any) => [
    b.band, `${b.target_days}d`, b.open, b.late,
    b.oldest_days !== null ? `${b.oldest_days}d` : '—',
  ]),
}))

const overdue = computed(() =>
  (data.value?.sla?.bands ?? []).reduce((n: number, b: any) => n + (b.late ?? 0), 0),
)
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Metrics</h1>
        <p>Each number carries the denominator it was computed over.</p>
      </div>
      <div class="actions"><button class="btn" @click="refresh()">Refresh</button></div>
    </div>

    <RowSkeleton v-if="pending" :rows="4" />

    <StateBlock v-else-if="error" kind="error" title="Cannot read metrics">
      The core service did not answer.
      <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
    </StateBlock>

    <template v-else-if="data">
      <div class="summary">
        <StatTile
          label="Measurable today"
          :value="`${data.summary.measured} of ${data.summary.total}`"
          :progress="data.summary.total ? data.summary.measured / data.summary.total : null"
        />
        <StatTile
          v-if="data.summary.missing_target"
          label="Short of target" :value="data.summary.missing_target" status="bad"
        />
        <StatTile
          v-if="data.summary.not_implemented"
          label="Need unbuilt features" :value="data.summary.not_implemented" of="not measurable"
        />
        <StatTile
          v-if="data.summary.not_enough_data"
          label="Too little data" :value="data.summary.not_enough_data" of="not measurable"
        />
        <StatTile
          v-if="overdue" label="Overdue findings" :value="overdue" of="past band target" status="bad"
        />
      </div>

      <div class="grid">
        <div
          v-for="m in measured" :key="m.id" class="card"
          :class="{ missing: m.status === 'missing', meeting: m.status === 'meeting' }"
        >
          <StatTile
            :label="m.label"
            :value="formatted(m)"
            :of="`over ${m.denominator.toLocaleString()} ${m.denominator_label}`"
            :progress="progress(m)"
            :status="STATUS[m.status]"
            goal
            :target="m.target_mvp === null
              ? undefined
              : `target ${m.lower_is_better ? 'under' : 'over'} ${m.target_mvp}${suffix(m)}`"
          />
          <p class="desc">{{ m.description }}</p>
          <p v-if="m.note" class="note">{{ m.note }}</p>
        </div>
      </div>

      <h2 class="section">What cannot be answered yet</h2>
      <div class="grid">
        <div v-for="m in unanswered" :key="m.id" class="card gapcard">
          <StatTile
            :label="m.label"
            :value="null"
            :hint="m.status === 'not_implemented' ? 'needs a feature that does not exist yet'
              : 'not enough data to say'"
          />
          <p class="desc">{{ m.description }}</p>
          <p v-if="m.note" class="note">{{ m.note }}</p>
        </div>
      </div>

      <h2 class="section">How long findings have been open</h2>
      <ChartFrame
        title="Open by band"
        :note="overdue ? `${overdue} past target — see each band` : anyOpen ? 'all within target' : undefined"
        :empty="!anyOpen"
        empty-text="Nothing open."
        :table="slaTable"
      >
        <ChartBars :rows="slaRows" unit="findings" summary="Open findings by severity band" />
      </ChartFrame>
      <p class="note">{{ data.sla.note }}</p>
    </template>
  </div>
</template>

<style scoped>
.summary {
  display: flex; gap: 1.8rem; flex-wrap: wrap;
  border: 1px solid var(--rule); border-radius: 9px; background: var(--surface);
  padding: .72rem .95rem; margin-bottom: 1rem;
}
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(19rem, 1fr)); gap: .7rem; }
.section { font-size: .7rem; margin: 1.5rem 0 .7rem; }
.card { border: 1px solid var(--rule); border-radius: 10px; background: var(--surface);
        padding: .8rem .95rem; margin: 0; }
.card.missing { border-left: 3px solid var(--crit); }
.card.meeting { border-left: 3px solid var(--good); }
.card.gapcard { border-left: 3px dashed var(--rule); }
.desc { margin: .45rem 0 0; font-size: .76rem; line-height: 1.5; color: var(--ink-2); }
.note { margin: .5rem 0 0; font-size: .71rem; line-height: 1.5; color: var(--ink-muted); }
</style>
