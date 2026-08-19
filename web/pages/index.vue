<script setup lang="ts">
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data: jobs, refresh } = await useAsyncData('jobs', () =>
  api<{ jobs: any[]; known_kinds: string[] }>('jobs?limit=10'),
)
const { data: audit } = await useAsyncData('audit', () =>
  api<{ intact: boolean; checked: number }>('audit/verify'),
)

const connected = ref(false)
const enqueuing = ref(false)

async function enqueueProbe() {
  enqueuing.value = true
  try {
    await api('jobs', {
      method: 'POST',
      body: { kind: 'system.echo', key: `probe-${Date.now()}`, payload: { from: 'dashboard' } },
    })
  } finally {
    enqueuing.value = false
  }
}

// SSE carries identity only; the client refetches so authorisation is re-checked
// on the normal read path (docs/TECHNICAL_DESIGN.md §16).
onMounted(() => {
  const source = new EventSource('/api/events?topics=jobs')
  source.onopen = () => (connected.value = true)
  source.onerror = () => (connected.value = false)
  source.addEventListener('jobs', () => refresh())
  onBeforeUnmount(() => source.close())
})

async function logout() {
  await api('auth/logout', { method: 'POST' })
  await navigateTo('/login')
}
</script>

<template>
  <div class="wrap">
    <div style="display:flex;justify-content:space-between;align-items:baseline">
      <h1>{{ $config.public.appName }}</h1>
      <span class="muted">
        <span class="dot" :class="connected ? 'live' : 'down'" />
        {{ connected ? 'live' : 'reconnecting' }} · {{ me?.email }}
        <button class="secondary" style="margin-left:1rem;padding:.3rem .7rem" @click="logout">
          Sign out
        </button>
      </span>
    </div>
    <p class="sub">Foundations (M0). Inventory, correlation, and investigation arrive in M1–M3.</p>

    <div class="card">
      <h2>Security posture</h2>
      <p class="muted">
        No assets registered yet, so there is nothing to report. This is
        <strong>not observed</strong>, not a clean result — asset registration lands in M1.
      </p>
    </div>

    <div class="card">
      <h2>Audit chain</h2>
      <p style="margin:0">
        <span class="dot" :class="audit?.intact ? 'live' : 'down'" />
        {{ audit?.intact ? 'Intact' : 'BROKEN' }} · {{ audit?.checked ?? 0 }} events verified
      </p>
    </div>

    <div class="card">
      <h2>Queue</h2>
      <button :disabled="enqueuing" @click="enqueueProbe">Enqueue probe job</button>
      <table style="margin-top:1rem">
        <thead>
          <tr><th>id</th><th>kind</th><th>attempts</th><th>state</th></tr>
        </thead>
        <tbody>
          <tr v-for="j in jobs?.jobs ?? []" :key="j.id">
            <td>{{ j.id }}</td>
            <td><code>{{ j.kind }}</code></td>
            <td>{{ j.attempts }}</td>
            <td>
              <template v-if="j.finished_at">{{ j.succeeded ? 'done' : 'failed' }}</template>
              <template v-else-if="j.started_at">running</template>
              <template v-else>queued</template>
            </td>
          </tr>
          <tr v-if="!(jobs?.jobs ?? []).length">
            <td colspan="4" class="muted">No jobs yet.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
