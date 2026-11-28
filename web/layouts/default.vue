<script setup lang="ts">
const { data: me } = await useMe()
const route = useRoute()

const { data: nav } = await useAsyncData('shell-nav', async () => {
  const [findings, coverage, audit] = await Promise.all([
    api<any>('findings?limit=1').catch(() => null),
    api<any>('coverage').catch(() => null),
    api<{ intact: boolean }>('audit/verify').catch(() => null),
  ])
  return { findings, coverage, audit }
})

const { data: intel } = await useAsyncData('shell-intel', () =>
  api<any>('intel/sources').catch(() => null),
)

const connected = useEventStatus()

const items = computed(() => [
  { to: '/', label: 'Today', glyph: 'today' },
  { to: '/findings', label: 'Findings', glyph: 'findings', count: nav.value?.findings?.group_count },
  { to: '/assets', label: 'Assets', glyph: 'assets', count: nav.value?.coverage?.assets_total },
  { to: '/code', label: 'Secrets & config', glyph: 'code' },
  { to: '/intel', label: 'Intelligence', glyph: 'intel' },
  { to: '/metrics', label: 'Metrics', glyph: 'metrics' },
  { to: '/activity', label: 'Activity', glyph: 'activity' },
  ...(showsAdminNav(me.value) ? [{ to: '/users', label: 'Users', glyph: 'users' }] : []),
])

const paletteOpen = ref(false)
const isMac = ref(true)
onMounted(() => {
  isMac.value = /Mac|iPhone|iPad/.test(navigator.platform)
  const onKey = (e: KeyboardEvent) => {
    if ((isMac.value ? e.metaKey : e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault()
      paletteOpen.value = !paletteOpen.value
      return
    }
    const t = e.target as HTMLElement | null
    const typing = t && (
      t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT'
      || t.isContentEditable
    )
    if (e.key === '/' && !typing && !paletteOpen.value) {
      e.preventDefault()
      paletteOpen.value = true
    }
  }
  window.addEventListener('keydown', onKey)
  onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
})

function isActive(to: string) {
  return to === '/' ? route.path === '/' : route.path.startsWith(to)
}

const intelAge = computed(() => {
  const sources = intel.value?.sources ?? []
  if (!sources.length) return null
  const ages = sources.map((s: any) => s.age_seconds).filter((a: any) => a !== null)
  if (ages.length < sources.length) return null
  return Math.max(...ages)
})

const intelLabel = computed(() => {
  const age = intelAge.value
  if (age === null) return 'never fetched'
  if (age < 5400) return `${Math.max(1, Math.round(age / 60))}m old`
  if (age < 172800) return `${Math.round(age / 3600)}h old`
  return `${Math.round(age / 86400)}d old`
})

const intelStale = computed(() => (intel.value ? !!intel.value.any_source_stale : true))

const audit = computed<'intact' | 'broken' | 'unknown'>(() =>
  nav.value?.audit == null ? 'unknown' : nav.value.audit.intact ? 'intact' : 'broken',
)

async function logout() {
  await api('auth/logout', { method: 'POST' })
  await navigateTo('/login')
}
</script>

<template>
  <div class="shell">
    <a class="skip" href="#main">Skip to content</a>
    <nav class="rail" aria-label="Primary">
      <NuxtLink to="/" class="brand">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M12 3l7 3v5.5c0 4.2-2.9 7.8-7 9.5-4.1-1.7-7-5.3-7-9.5V6l7-3z" />
          <path d="M9.5 12.2l1.9 1.9 3.6-4" />
        </svg>
        <span>{{ $config.public.appName }}</span>
      </NuxtLink>

      <button class="search" aria-label="Search and commands" aria-keyshortcuts="Meta+K Control+K"
              @click="paletteOpen = true">
        <NavGlyph name="search" />
        <span class="navlabel">Search</span>
        <kbd>{{ isMac ? '⌘' : 'Ctrl' }} K</kbd>
      </button>

      <ul class="navlist">
        <li v-for="item in items" :key="item.to">
          <NuxtLink :to="item.to" class="navitem" :class="{ on: isActive(item.to) }"
                    :aria-current="isActive(item.to) ? 'page' : undefined">
            <NavGlyph :name="item.glyph" />
            <span class="navlabel">{{ item.label }}</span>
            <span v-if="item.count != null" class="navcount">{{ item.count.toLocaleString() }}</span>
          </NuxtLink>
        </li>
      </ul>

      <div class="railfoot">
        <NotificationBell />

        <NuxtLink to="/intel" class="status intel" :class="{ warn: intelStale }">
          <span class="dot" :class="intelStale ? 'down' : 'live'" />
          Intelligence {{ intelLabel }}
        </NuxtLink>
        <NuxtLink to="/activity" class="status audit" :class="audit">
          <span class="dot" :class="audit === 'intact' ? 'live' : audit === 'broken' ? 'broken' : 'idle hatch'" />
          Audit chain {{ audit === 'intact' ? 'intact' : audit === 'broken' ? 'BROKEN' : 'not verified' }}
        </NuxtLink>
        <div class="status conn" :class="{ warn: !connected }" role="status">
          <span class="dot" :class="connected ? 'live' : 'down'" />
          {{ connected ? 'Live' : 'Reconnecting' }}
        </div>
        <div class="who">
          <span class="avatar">{{ (me?.email || '?').charAt(0).toUpperCase() }}</span>
          <NuxtLink to="/account" class="email" :title="`${me?.email ?? ''}: account security`">{{ me?.email }}</NuxtLink>
          <button class="signout" title="Sign out" aria-label="Sign out" @click="logout">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M14.5 16.5L19 12l-4.5-4.5" /><path d="M19 12H9" />
              <path d="M12 4.5H6.5A1.5 1.5 0 005 6v12a1.5 1.5 0 001.5 1.5H12" />
            </svg>
          </button>
        </div>
      </div>
    </nav>

    <main id="main" class="main" tabindex="-1">
      <HaltBanner v-if="me" :can-administer="showsAdminNav(me)" :mfa-enabled="!!me.mfa_enabled" />
      <slot />
    </main>
    <CommandPalette v-model:open="paletteOpen" />
  </div>
</template>

<style scoped>
.shell { display: flex; min-height: 100vh; background: var(--plane); }
.rail {
  width: 216px; flex-shrink: 0; border-right: 1px solid var(--rule);
  background: var(--surface); display: flex; flex-direction: column;
  padding: 1.1rem .75rem; gap: 1.4rem; position: sticky; top: 0; height: 100vh;
}
.brand {
  display: flex; align-items: center; gap: .55rem; padding: 0 .5rem;
  font-weight: 640; letter-spacing: -0.01em; color: var(--ink); text-decoration: none;
}
.search {
  display: flex; align-items: center; gap: .6rem; padding: .4rem .62rem; margin: -.6rem 0 -.4rem;
  border: 1px solid var(--rule); border-radius: 7px; background: var(--plane); color: var(--ink-muted);
  font-size: .82rem; font-weight: 400; cursor: pointer; text-align: left;
}
.search:hover { color: var(--ink); border-color: var(--ink-muted); }
.search kbd { font: 600 .62rem ui-monospace, SFMono-Regular, Menlo, monospace; border: 1px solid var(--rule);
              border-radius: 4px; padding: 0 .25rem; background: var(--surface); }
.navlist { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
.navitem {
  display: flex; align-items: center; gap: .6rem; padding: .44rem .62rem;
  border-radius: 7px; color: var(--ink-2); font-size: .87rem; text-decoration: none;
}
.navitem:hover { background: var(--plane); color: var(--ink); }
.navitem.on { background: var(--plane); color: var(--ink); font-weight: 560; }
.navlabel { flex-grow: 1; }
.navcount { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: .72rem; color: var(--ink-muted); }
.railfoot {
  margin-top: auto; border-top: 1px solid var(--rule); padding-top: .8rem;
  display: flex; flex-direction: column; gap: .45rem;
}
.status {
  display: flex; align-items: center; gap: .45rem; padding: 0 .5rem;
  font-size: .74rem; color: var(--ink-muted); text-decoration: none;
}
.status.warn { color: var(--warn-ink); font-weight: 500; }
.who { display: flex; align-items: center; gap: .45rem; margin-top: .4rem; padding: 0 .5rem; }
.avatar {
  width: 22px; height: 22px; border-radius: 50%; background: var(--plane);
  border: 1px solid var(--rule); display: flex; align-items: center;
  justify-content: center; font-size: .65rem; font-weight: 640; flex-shrink: 0;
}
.email {
  font-size: .74rem; color: var(--ink-2); overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; flex-grow: 1; text-decoration: none;
}
.email:hover { color: var(--ink); text-decoration: underline; }
.signout {
  background: none; border: 0; padding: .15rem; margin: 0; line-height: 0;
  color: var(--ink-muted); cursor: pointer; border-radius: 5px; flex-shrink: 0;
}
.signout:hover { color: var(--ink); background: var(--plane); }
.main { flex-grow: 1; min-width: 0; }
.main:focus { outline: none; }
.dot.broken { background: var(--bad); }
.dot.idle { border: 1px dashed var(--line-strong); background-color: transparent; }
.status.audit.broken { color: var(--ink); font-weight: 600; }

@media (max-width: 860px) {
  .shell { flex-direction: column; }
  .rail {
    width: auto; height: auto; position: static; flex-direction: row;
    align-items: center; gap: 1rem; padding: .7rem 1rem;
    border-right: 0; border-bottom: 1px solid var(--rule);
  }
  .navlist { flex-direction: row; gap: .2rem; }
  .navcount { display: none; }
  .railfoot { margin: 0 0 0 auto; border: 0; padding: 0; flex-direction: row; align-items: center; }
  .status, .who { display: none; }
  .search { margin: 0; }
  .search .navlabel, .search kbd { display: none; }
  .rail { flex-wrap: wrap; }
  .navlist { order: 3; flex-basis: 100%; overflow-x: auto; padding-bottom: .15rem;
             scrollbar-width: none; }
  .navlist::-webkit-scrollbar { display: none; }
  .navitem { white-space: nowrap; }
  .status.intel { display: flex; }
  .status.audit.broken, .status.conn.warn { display: flex; }
}
</style>
