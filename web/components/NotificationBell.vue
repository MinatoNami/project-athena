<script setup lang="ts">
/**
 * The notification inbox.
 *
 * Counts are shown separately for urgent and routine. A single badge would make an
 * actively exploited flaw look identical to nine routine assessments, which is the
 * flattening the grouping and throttling exist to undo.
 */
const open = ref(false)

const { data, refresh } = await useAsyncData('notifications', () =>
  api<any>('notifications?limit=30').catch(() => null),
)

useEvents(['findings'], refresh)

const unread = computed(() => data.value?.unread ?? 0)
const urgent = computed(() => data.value?.urgent_unread ?? 0)

async function markRead(id: string) {
  await api(`notifications/${id}/read`, { method: 'POST' })
  await refresh()
}
async function markAll() {
  await api('notifications/read-all', { method: 'POST' })
  await refresh()
}

function when(at: string | null) {
  if (!at) return ''
  const seconds = (Date.now() - new Date(at).getTime()) / 1000
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))}m ago`
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`
  return `${Math.round(seconds / 86400)}d ago`
}
</script>

<template>
  <div class="bell">
    <button
      class="trigger" :class="{ on: open }"
      :aria-label="`Notifications, ${unread} unread`" @click="open = !open"
    >
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M18 9a6 6 0 10-12 0c0 5-2 6.5-2 6.5h16S18 14 18 9z" />
        <path d="M13.7 19a2 2 0 01-3.4 0" />
      </svg>
      <span class="label">Inbox</span>
      <span v-if="urgent" class="count urgent">{{ urgent }}</span>
      <span v-else-if="unread" class="count">{{ unread }}</span>
    </button>

    <div v-if="open" class="panel">
      <div class="head">
        <span class="lbl">Inbox</span>
        <button v-if="unread" class="linkish" @click="markAll">Mark all read</button>
      </div>

      <p v-if="!data?.notifications?.length" class="empty">
        Nothing yet. You are told when a finding is scored into a band worth acting on,
        or when something you set aside comes back.
      </p>

      <ul v-else class="items">
        <li
          v-for="n in data.notifications" :key="n.id"
          class="item" :class="{ unread: !n.read_at, urgent: n.urgency === 'urgent' }"
          @click="markRead(n.id)"
        >
          <div class="top">
            <span class="title">{{ n.title }}</span>
            <span class="ago">{{ when(n.sent_at || n.created_at) }}</span>
          </div>
          <p v-if="n.body" class="body">{{ n.body }}</p>
          <div class="meta">
            <!-- The count is the grouping made visible: one message, many assets. -->
            <span v-if="n.occurrence_count > 1" class="rollup">
              across {{ n.occurrence_count }} assets
            </span>
            <span v-if="n.subjects?.length" class="subjects">
              {{ n.subjects.slice(0, 3).join(', ') }}<template v-if="n.subjects_truncated">…</template>
            </span>
            <!-- Held is not failed, and the difference matters to whoever is waiting. -->
            <span v-if="n.digested" class="digested" title="Held back by the throttle, not lost">
              in digest
            </span>
          </div>
        </li>
      </ul>

      <p v-if="data?.held_for_digest" class="fine">
        {{ data.held_for_digest }} held for the digest so the urgent ones stay findable.
      </p>
    </div>
  </div>
</template>

<style scoped>
.bell { position: relative; }
.trigger {
  display: flex; align-items: center; gap: .6rem; width: 100%;
  padding: .44rem .62rem; border-radius: 7px; border: 0; background: transparent;
  color: var(--ink-2); font: inherit; font-size: .87rem; cursor: pointer; text-align: left;
}
.trigger:hover, .trigger.on { background: var(--plane); color: var(--ink); }
.trigger svg { color: var(--ink-muted); flex-shrink: 0; }
.label { flex-grow: 1; }
.count {
  font-family: ui-monospace, Menlo, monospace; font-size: .68rem; font-weight: 600;
  padding: .05rem .3rem; border-radius: 4px; background: var(--rule); color: var(--ink);
}
.count.urgent { background: var(--sev-critical); color: var(--sev-on-dark); }

.panel {
  position: absolute; left: 0; bottom: calc(100% + .4rem); width: 22rem; z-index: 40;
  background: var(--surface); border: 1px solid var(--rule); border-radius: 10px;
  padding: .6rem; max-height: 70vh; overflow: auto;
  box-shadow: 0 10px 30px rgba(0, 0, 0, .18);
}
.head { display: flex; align-items: center; justify-content: space-between; padding: .1rem .3rem .5rem; }
.linkish {
  background: none; border: 0; padding: 0; font: inherit; font-size: .7rem;
  color: var(--ink-muted); cursor: pointer; text-decoration: underline;
}
.linkish:hover { color: var(--ink); }
.empty { margin: .3rem; font-size: .78rem; line-height: 1.5; color: var(--ink-muted); }
.items { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
.item { padding: .5rem .55rem; border-radius: 7px; cursor: pointer; }
.item:hover { background: var(--plane); }
.item.unread { background: var(--plane); }
.item.unread.urgent { box-shadow: inset 2px 0 0 var(--sev-critical); }
.top { display: flex; align-items: baseline; justify-content: space-between; gap: .5rem; }
.title { font-size: .8rem; font-weight: 600; }
.item:not(.unread) .title { font-weight: 500; color: var(--ink-2); }
.ago { font-size: .68rem; color: var(--ink-muted); white-space: nowrap; }
.body {
  margin: .2rem 0 0; font-size: .74rem; line-height: 1.45; color: var(--ink-2);
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.meta { display: flex; gap: .5rem; flex-wrap: wrap; margin-top: .3rem; font-size: .68rem;
        color: var(--ink-muted); }
.rollup { font-weight: 600; color: var(--ink-2); }
.digested { border: 1px dashed var(--rule); border-radius: 3px; padding: 0 .22rem; }
.fine { margin: .5rem .3rem 0; font-size: .68rem; color: var(--ink-muted); }
</style>
