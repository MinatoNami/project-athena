<script setup lang="ts">
/**
 * Activity — the audit trail, read as a timeline.
 *
 * The shell linked here before this page existed, which produced a raw Nuxt 404.
 * The link is worth keeping rather than removing: the hash-chained trail is a real
 * feature and there was no way to see it, so "who changed what" was answerable only
 * from the database.
 *
 * The chain's integrity is stated at the top rather than assumed. A trail nobody can
 * verify is a log, not an audit trail.
 */
useHead({ title: 'Activity' })

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const before = ref<number | null>(null)
const collected = ref<any[]>([])

const { data, pending, error, refresh } = await useAsyncData(
  'audit',
  () => api<any>(`audit?limit=100${before.value ? `&before_seq=${before.value}` : ''}`),
  { watch: [before] },
)
const { data: chain } = await useAsyncData('audit-verify', () =>
  api<{ intact: boolean; checked: number; first_divergence?: any }>('audit/verify'),
)

watchEffect(() => {
  if (!data.value?.events) return
  const seen = new Set(collected.value.map(e => e.seq))
  for (const e of data.value.events) if (!seen.has(e.seq)) collected.value.push(e)
  collected.value.sort((a, b) => b.seq - a.seq)
})

/**
 * Actions in the operator's words. Anything unmapped falls back to the raw verb
 * rather than a friendly guess — inventing a description for an action nobody
 * anticipated is how an audit trail starts lying.
 */
const VERBS: Record<string, string> = {
  ASSET_CLASSIFIED: 'classified an asset',
  ASSET_REGISTERED: 'registered an asset',
  SCAN_REQUESTED: 'requested a scan',
  LOGIN: 'signed in',
  LOGIN_FAILED: 'failed to sign in',
  LOGOUT: 'signed out',
  STEP_UP: 're-authenticated',
  STEP_UP_FAILED: 'failed to re-authenticate',
  JOB_ENQUEUED: 'enqueued a job',
  NODE_ENROLLED: 'enrolled a node',
  NODE_REMOVED: 'removed a node',
  INTEL_REFRESH_REQUESTED: 'requested an intelligence refresh',
  BOOTSTRAP: 'created the first account',
}
function verb(action: string) {
  return VERBS[action] ?? action.toLowerCase().replace(/_/g, ' ')
}
function isFailure(action: string) {
  return action.endsWith('_FAILED') || action.includes('DENIED')
}
function subjectLabel(subject: string) {
  const [kind, id] = subject.split(':')
  return { kind, id: id ?? '' }
}
function when(at: string) {
  return new Date(at).toLocaleString()
}

function loadMore() {
  if (data.value?.next_before_seq) before.value = data.value.next_before_seq
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Activity</h1>
        <p>
          Every consequential action, in the order it happened. Each entry is chained to
          the one before it, so the record cannot be edited after the fact without the
          chain failing to verify.
        </p>
      </div>
      <div class="actions">
        <button class="btn" @click="refresh()">Refresh</button>
      </div>
    </div>

    <!-- Integrity is the claim this page rests on, so it is stated rather than assumed. -->
    <div v-if="chain" class="chain" :class="{ broken: !chain.intact }">
      <span class="dot" :class="chain.intact ? 'live' : 'down'" />
      <span>
        <strong>{{ chain.intact ? 'Chain intact' : 'CHAIN BROKEN' }}</strong>
        · {{ chain.checked.toLocaleString() }} events verified from genesis
      </span>
      <span v-if="!chain.intact" class="warnmsg">
        Everything below this point is no longer trustworthy as a record.
      </span>
    </div>

    <RowSkeleton v-if="pending && !collected.length" :rows="6" />

    <StateBlock v-else-if="error" kind="error" title="Cannot read the audit trail">
      The core service did not answer.
      <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
    </StateBlock>

    <StateBlock
      v-else-if="!collected.length" kind="never" title="Nothing has happened yet"
    >
      No consequential action has been recorded. That is an empty trail, not a clean one.
    </StateBlock>

    <div v-else class="trail">
      <div v-for="e in collected" :key="e.seq" class="entry">
        <div class="seq mono tnum">{{ e.seq }}</div>
        <div class="line">
          <div class="what">
            <span class="actor">{{ e.actor }}</span>
            <span class="verb" :class="{ bad: isFailure(e.action) }">{{ verb(e.action) }}</span>
            <code v-if="e.subject" class="subject">{{ subjectLabel(e.subject).kind }}
              <span class="sid">{{ subjectLabel(e.subject).id.slice(0, 12) }}</span></code>
          </div>
          <div class="meta">
            <span>{{ when(e.at) }}</span>
            <code class="hash" :title="`Chain hash ${e.hash}`">{{ e.hash.slice(0, 10) }}</code>
          </div>
        </div>
      </div>

      <div v-if="data?.next_before_seq" class="more">
        <button class="btn" :disabled="pending" @click="loadMore">
          {{ pending ? 'Loading…' : 'Load older' }}
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.chain {
  border: 1px solid var(--rule); border-left: 3px solid var(--good); border-radius: 8px;
  background: var(--surface); padding: .55rem .8rem; display: flex; align-items: center;
  gap: .6rem; font-size: .8rem; color: var(--ink-2); margin-bottom: .9rem; flex-wrap: wrap;
}
.chain.broken { border-left-color: var(--crit); }
.chain strong { color: var(--ink); }
.warnmsg { color: var(--crit); font-weight: 600; }

.trail {
  border: 1px solid var(--rule); border-radius: 10px; background: var(--surface);
  overflow: hidden; max-width: 66rem;
}
.entry { display: flex; gap: .8rem; padding: .5rem .85rem; border-top: 1px solid var(--rule); }
.entry:first-child { border-top: 0; }
.entry:hover { background: var(--plane); }
.seq { width: 4rem; flex-shrink: 0; font-size: .72rem; color: var(--ink-muted); padding-top: .1rem; }
.line { flex-grow: 1; min-width: 0; display: flex; align-items: baseline;
        justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
.what { display: flex; align-items: baseline; gap: .45rem; flex-wrap: wrap; min-width: 0; }
.actor { font-size: .81rem; font-weight: 600; }
.verb { font-size: .81rem; color: var(--ink-2); }
.verb.bad { color: var(--crit); font-weight: 600; }
.subject { font-size: .73rem; color: var(--ink-muted); }
.sid { opacity: .75; }
.meta { display: flex; gap: .7rem; align-items: baseline; font-size: .72rem; color: var(--ink-muted); }
.hash { font-size: .68rem; opacity: .7; }
.more { padding: .7rem .85rem; border-top: 1px solid var(--rule); }
</style>
