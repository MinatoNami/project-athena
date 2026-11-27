<script setup lang="ts">
const open = defineModel<boolean>('open', { default: false })

const input = ref<HTMLInputElement | null>(null)
const text = ref('')
const active = ref(0)
const busy = ref(false)
const note = ref<string | null>(null)
let returnFocus: HTMLElement | null = null

interface Item {
  id: string
  group: string
  label: string
  hint?: string
  tone?: 'bad'
  confirm?: string
  run: () => Promise<void> | void
}

const go = (to: string) => async () => {
  close()
  await navigateTo(to)
}

const PAGES: Item[] = [
  { id: 'p-today', group: 'Go to', label: 'Today', hint: 'ranked worklist', run: go('/') },
  { id: 'p-findings', group: 'Go to', label: 'Findings', run: go('/findings') },
  { id: 'p-assets', group: 'Go to', label: 'Assets', run: go('/assets') },
  { id: 'p-code', group: 'Go to', label: 'Secrets & config', run: go('/code') },
  { id: 'p-intel', group: 'Go to', label: 'Intelligence', hint: 'feed health', run: go('/intel') },
  { id: 'p-classify', group: 'Go to', label: 'Classify assets', run: go('/assets/classify') },
  { id: 'p-metrics', group: 'Go to', label: 'Metrics', run: go('/metrics') },
  { id: 'p-activity', group: 'Go to', label: 'Activity', run: go('/activity') },
]

const ACTIONS: Item[] = [
  {
    id: 'a-refresh', group: 'Actions', label: 'Refresh all intelligence sources',
    hint: 'queues fetches', confirm: 'queue a fetch from every source', run: async () => {
      const res = await api<{ queued: number }>('intel/refresh', { method: 'POST' })
      note.value = `${res.queued} fetch${res.queued === 1 ? '' : 'es'} queued.`
    },
  },
  {
    id: 'a-vex', group: 'Actions', label: 'Export OpenVEX for the estate',
    hint: 'downloads JSON', confirm: 'download an audited VEX export', run: async () => {
      await downloadJson('export/openvex', 'athena.openvex.json')
      note.value = 'VEX document downloaded. The export is recorded in the audit log.'
    },
  },
]

const assets = ref<any[]>([])
const findingHits = ref<any[]>([])
let searchTimer: ReturnType<typeof setTimeout> | undefined
let searchSeq = 0

watch(open, async (value) => {
  if (!value) {
    nextTick(() => returnFocus?.focus?.())
    return
  }
  returnFocus = document.activeElement as HTMLElement | null
  text.value = ''
  note.value = null
  active.value = 0
  findingHits.value = []
  await nextTick()
  input.value?.focus()
  if (!assets.value.length) {
    api<any>('assets?limit=500').then(r => (assets.value = r.assets ?? [])).catch(() => {})
  }
})

const searching = ref(false)
const armed = ref<string | null>(null)

watch(text, (value) => {
  active.value = 0
  armed.value = null
  clearTimeout(searchTimer)
  const q = value.trim()
  if (q.length < 2) {
    findingHits.value = []
    return
  }
  const seq = ++searchSeq
  searching.value = true
  searchTimer = setTimeout(async () => {
    try {
      const res = await api<any>(
        `findings?q=${encodeURIComponent(q)}&limit=6&include_no_fix=true&include_baseline=true`,
      )
      if (seq === searchSeq) findingHits.value = res.groups ?? []
    } catch {
      if (seq === searchSeq) findingHits.value = []
    } finally {
      if (seq === searchSeq) searching.value = false
    }
  }, 180)
})

const items = computed<Item[]>(() => {
  const q = text.value.trim().toLowerCase()
  const match = (s: string) => !q || s.toLowerCase().includes(q)
  const out: Item[] = []
  for (const g of findingHits.value) {
    const first = g.instances?.[0]
    out.push({
      id: `f-${g.group_key}`, group: 'Findings',
      label: `${g.vulnerability_id}${g.summary ? ` — ${g.summary}` : ''}`,
      hint: `${g.instance_count} affected${g.malicious ? ' · malware' : g.kev ? ' · KEV' : ''}`,
      tone: g.malicious || g.kev ? 'bad' : undefined,
      run: go(first ? `/findings/${first.finding_id}` : '/findings'),
    })
  }
  if (q) {
    for (const a of assets.value.filter((a: any) => match(a.display_name)).slice(0, 6)) {
      out.push({
        id: `as-${a.id}`, group: 'Assets', label: a.display_name,
        hint: `${a.kind} · ${a.tier}`, run: go(`/assets/${a.id}`),
      })
    }
  }
  out.push(...PAGES.filter(p => match(p.label)))
  out.push(...ACTIONS.filter(a => match(a.label)))
  return out
})

const grouped = computed(() => {
  const groups: { name: string; items: (Item & { index: number })[] }[] = []
  items.value.forEach((item, index) => {
    let g = groups.find(x => x.name === item.group)
    if (!g) groups.push((g = { name: item.group, items: [] }))
    g.items.push({ ...item, index })
  })
  return groups
})

function close() {
  open.value = false
}

watch(items, (list, old) => {
  const id = old?.[active.value]?.id
  const at = id ? list.findIndex(i => i.id === id) : -1
  active.value = at >= 0 ? at : 0
})
watch(active, () => { armed.value = null })

async function choose(index: number) {
  const item = items.value[index]
  if (!item || busy.value) return
  if (item.confirm && armed.value !== item.id) {
    armed.value = item.id
    note.value = `Press ↵ again to ${item.confirm}.`
    return
  }
  armed.value = null
  busy.value = true
  note.value = null
  try {
    await item.run()
  } catch (e: any) {
    note.value = e?.data?.detail || e?.message || 'That did not work.'
  } finally {
    busy.value = false
  }
}

function onKey(e: KeyboardEvent) {
  const n = items.value.length
  if (e.key === 'ArrowDown') { e.preventDefault(); active.value = n ? (active.value + 1) % n : 0 }
  else if (e.key === 'ArrowUp') { e.preventDefault(); active.value = n ? (active.value - 1 + n) % n : 0 }
  else if (e.key === 'Enter') { e.preventDefault(); choose(active.value) }
  else if (e.key === 'Escape') { e.preventDefault(); close() }
  else if (e.key === 'Tab') { e.preventDefault() }
}

watch(active, async (i) => {
  await nextTick()
  document.getElementById(`cmd-${i}`)?.scrollIntoView({ block: 'nearest' })
})
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="scrim" @mousedown.self="close">
      <div class="palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <div class="inputrow">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
            <circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" />
          </svg>
          <input
            ref="input" v-model="text" type="text" spellcheck="false" autocomplete="off"
            placeholder="Search advisories and assets, or jump to a page"
            role="combobox" aria-expanded="true" aria-controls="cmd-list"
            :aria-activedescendant="items.length ? `cmd-${active}` : undefined"
            @keydown="onKey"
          >
          <kbd>esc</kbd>
        </div>

        <ul id="cmd-list" class="list" role="listbox">
          <template v-for="g in grouped" :key="g.name">
            <li class="grouplabel" role="presentation">{{ g.name }}</li>
            <li
              v-for="item in g.items" :id="`cmd-${item.index}`" :key="item.id"
              role="option" :aria-selected="item.index === active"
              class="opt" :class="{ on: item.index === active }"
              @mousemove="active = item.index" @click="choose(item.index)"
            >
              <span class="label" :class="item.tone"><UntrustedText :text="item.label" /></span>
              <span v-if="item.hint" class="hint">{{ item.hint }}</span>
            </li>
          </template>
          <li v-if="!items.length && searching" class="empty" role="presentation">
            Searching findings…
          </li>
          <li v-else-if="!items.length" class="empty" role="presentation">
            Nothing matches “{{ text }}”. Findings are searched by advisory id and summary.
          </li>
        </ul>

        <div class="foot">
          <span v-if="note" class="note">{{ note }}</span>
          <span v-else-if="busy" class="note">Working…</span>
          <span v-else class="keys"><kbd>↑</kbd><kbd>↓</kbd> move <kbd>↵</kbd> open <kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.scrim { position: fixed; inset: 0; background: rgba(10, 10, 10, .32); z-index: 50;
         display: flex; justify-content: center; align-items: flex-start; padding: 12vh 1rem 1rem; }
.palette { width: min(640px, 100%); background: var(--surface); border: 1px solid var(--rule);
           border-radius: 12px; box-shadow: 0 18px 50px rgba(0, 0, 0, .22); overflow: hidden;
           display: flex; flex-direction: column; max-height: 70vh; }
.inputrow { display: flex; align-items: center; gap: .6rem; padding: .7rem .9rem;
            border-bottom: 1px solid var(--rule); color: var(--ink-muted); }
.inputrow input { border: 0; background: transparent; padding: .2rem 0; font-size: .95rem;
                  outline: none; color: var(--ink); }
kbd { font: 600 .64rem ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--ink-muted);
      border: 1px solid var(--rule); border-radius: 4px; padding: .05rem .3rem; background: var(--plane); }
.list { list-style: none; margin: 0; padding: .35rem; overflow-y: auto; }
.grouplabel { font-size: .64rem; text-transform: uppercase; letter-spacing: .07em; font-weight: 600;
              color: var(--ink-muted); padding: .55rem .55rem .25rem; }
.opt { display: flex; align-items: center; justify-content: space-between; gap: .8rem;
       padding: .45rem .55rem; border-radius: 7px; cursor: pointer; font-size: .86rem; }
.opt.on { background: var(--plane); box-shadow: inset 3px 0 0 var(--ink); }
.label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.label.bad { color: var(--crit); }
.hint { font-size: .72rem; color: var(--ink-muted); white-space: nowrap; flex-shrink: 0; }
.empty { padding: .9rem .6rem; font-size: .82rem; color: var(--ink-muted); }
.foot { border-top: 1px solid var(--rule); padding: .45rem .9rem; font-size: .72rem; color: var(--ink-muted);
        display: flex; gap: .4rem; }
.keys { display: flex; align-items: center; gap: .25rem; }
.note { color: var(--ink-2); }
@media (prefers-reduced-motion: no-preference) {
  .palette { animation: rise .12s ease-out; }
  @keyframes rise { from { transform: translateY(6px); opacity: .6 } to { transform: none; opacity: 1 } }
}
</style>
