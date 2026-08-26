<script setup lang="ts">
/**
 * The success metrics.
 *
 * Every card shows its denominator and its status. The page leads with how much of
 * itself it cannot answer, because a dashboard where four of ten cards are empty and
 * you have to notice one by one is a dashboard that reads as healthier than it is.
 *
 * Nothing renders a zero for something unbuilt. A zero and an absence look identical
 * in a chart and mean opposite things.
 */
useHead({ title: 'Metrics' })

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data, pending, error, refresh } = await useAsyncData('metrics', () =>
  api<any>('metrics'),
)

const STATUS_LABEL: Record<string, string> = {
  meeting: 'Meeting target',
  missing: 'Short of target',
  no_target: 'No target set',
  unknown: 'Not enough data',
  not_implemented: 'Not built yet',
}

function formatted(m: any) {
  if (m.value === null) return '—'
  if (m.unit === 'tokens') return m.value.toLocaleString()
  if (m.unit === '%') return `${m.value}%`
  if (m.unit === 'hours') return `${m.value}h`
  if (m.unit === 'days') return `${m.value}d`
  return String(m.value)
}

function targetText(m: any) {
  if (m.target_mvp === null) return null
  const arrow = m.lower_is_better ? 'under' : 'over'
  const unit = m.unit === '%' ? '%' : m.unit === 'hours' ? 'h' : m.unit === 'days' ? 'd' : ''
  return `${arrow} ${m.target_mvp}${unit} · mature ${m.target_mature}${unit}`
}

const measured = computed(() => data.value?.metrics?.filter((m: any) => m.value !== null) ?? [])
const unanswered = computed(() =>
  data.value?.metrics?.filter((m: any) => m.value === null) ?? [],
)
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Metrics</h1>
        <p>
          Every number here carries the denominator it was computed over. A rate
          without one is an assertion.
        </p>
      </div>
      <div class="actions"><button class="btn" @click="refresh()">Refresh</button></div>
    </div>

    <RowSkeleton v-if="pending" :rows="4" />

    <StateBlock v-else-if="error" kind="error" title="Cannot read metrics">
      The core service did not answer.
      <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
    </StateBlock>

    <template v-else-if="data">
      <!-- Led with, not discovered card by card. -->
      <div class="summary">
        <span>
          <strong>{{ data.summary.measured }} of {{ data.summary.total }}</strong>
          can be measured today.
        </span>
        <span v-if="data.summary.not_implemented" class="gap">
          {{ data.summary.not_implemented }} need features that do not exist yet
        </span>
        <span v-if="data.summary.not_enough_data" class="gap">
          {{ data.summary.not_enough_data }} lack the data to say
        </span>
        <span v-if="data.summary.missing_target" class="bad">
          {{ data.summary.missing_target }} short of target
        </span>
      </div>

      <div class="grid">
        <div
          v-for="m in measured" :key="m.id" class="card"
          :class="{ missing: m.status === 'missing', meeting: m.status === 'meeting' }"
        >
          <div class="lbl">{{ m.label }}</div>
          <div class="figure">
            <span class="mono tnum val">{{ formatted(m) }}</span>
            <span class="status" :class="m.status">{{ STATUS_LABEL[m.status] }}</span>
          </div>
          <p class="desc">{{ m.description }}</p>
          <div class="foot">
            <span class="denom">
              over <span class="mono tnum">{{ m.denominator.toLocaleString() }}</span>
              {{ m.denominator_label }}
            </span>
            <span v-if="targetText(m)" class="target">Target {{ targetText(m) }}</span>
          </div>
          <p v-if="m.note" class="note">{{ m.note }}</p>
        </div>
      </div>

      <!-- The gaps get the same treatment as the numbers, not a footnote. -->
      <h2 class="section">What cannot be answered yet</h2>
      <div class="grid">
        <div v-for="m in unanswered" :key="m.id" class="card gapcard">
          <div class="lbl">{{ m.label }}</div>
          <div class="figure">
            <span class="hatchbox hatch" />
            <span class="status" :class="m.status">{{ STATUS_LABEL[m.status] }}</span>
          </div>
          <p class="desc">{{ m.description }}</p>
          <div class="foot">
            <span class="denom">would be measured over {{ m.denominator_label }}</span>
            <span v-if="targetText(m)" class="target">Target {{ targetText(m) }}</span>
          </div>
          <p v-if="m.note" class="note">{{ m.note }}</p>
        </div>
      </div>

      <h2 class="section">How long findings have been open</h2>
      <div class="card sla">
        <table>
          <thead>
            <tr><th>Band</th><th>Target</th><th>Open</th><th>Late</th><th>Oldest</th><th /></tr>
          </thead>
          <tbody>
            <tr v-for="b in data.sla.bands" :key="b.band">
              <td><SeverityChip :severity="b.band" /></td>
              <td class="mono tnum">{{ b.target_days }}d</td>
              <td class="mono tnum">{{ b.open }}</td>
              <td class="mono tnum" :class="{ bad: b.late }">{{ b.late }}</td>
              <td class="mono tnum muted">{{ b.oldest_days !== null ? `${b.oldest_days}d` : '—' }}</td>
              <td>
                <!-- An empty band is not a band meeting its target. -->
                <span class="status" :class="b.status">
                  {{ b.status === 'none_open' ? 'Nothing open'
                    : b.status === 'late' ? 'Overdue' : 'Within target' }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="note">{{ data.sla.note }}</p>
      </div>
    </template>
  </div>
</template>

<style scoped>
.summary {
  display: flex; gap: 1.2rem; flex-wrap: wrap; align-items: baseline;
  border: 1px solid var(--rule); border-radius: 9px; background: var(--surface);
  padding: .65rem .9rem; font-size: .82rem; color: var(--ink-2); margin-bottom: 1rem;
}
.summary strong { color: var(--ink); font-weight: 600; }
.summary .gap { color: var(--ink-muted); }
.summary .bad { color: var(--crit); font-weight: 600; }

.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(19rem, 1fr)); gap: .7rem; }
.section { font-size: .7rem; margin: 1.5rem 0 .7rem; }
.card { border: 1px solid var(--rule); border-radius: 10px; background: var(--surface); padding: .85rem 1rem; }
.card.missing { border-left: 3px solid var(--crit); }
.card.meeting { border-left: 3px solid var(--good); }
.card.gapcard { border-left: 3px dashed var(--rule); }
.figure { display: flex; align-items: baseline; gap: .6rem; margin: .35rem 0 .4rem; flex-wrap: wrap; }
.val { font-size: 1.5rem; font-weight: 600; letter-spacing: -0.02em; }
.hatchbox { display: inline-block; width: 40px; height: 22px; border-radius: 5px;
            border: 1px dashed var(--rule); }
.status { font-size: .64rem; text-transform: uppercase; letter-spacing: .05em; font-weight: 600;
          border: 1px solid var(--rule); border-radius: 4px; padding: .1rem .35rem;
          color: var(--ink-muted); white-space: nowrap; }
.status.meeting, .status.within_target { color: var(--good); border-color: var(--good); }
.status.missing, .status.late { color: var(--crit); border-color: var(--crit); }
.status.not_implemented, .status.unknown, .status.none_open { border-style: dashed; }
.desc { margin: 0; font-size: .78rem; line-height: 1.5; color: var(--ink-2); }
.foot { display: flex; flex-direction: column; gap: .15rem; margin-top: .5rem;
        font-size: .7rem; color: var(--ink-muted); }
.note { margin: .5rem 0 0; font-size: .71rem; line-height: 1.5; color: var(--ink-muted); }
.sla table { width: 100%; }
.sla td { vertical-align: middle; }
.bad { color: var(--crit); font-weight: 600; }
</style>
