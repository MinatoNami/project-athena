<script setup lang="ts">
const props = defineProps<{ assetId?: string; compact?: boolean }>()

const route = useRoute()
const kind = ref<CodeFindingFilter>(codeFindingFilter(route.query.kind))
const showResolved = ref(route.query.resolved === '1')
watch([kind, showResolved], ([k, r]) => navigateTo({
  query: { ...route.query, kind: k === 'all' ? undefined : k, resolved: r ? '1' : undefined },
}, { replace: true }))
const open = ref<string | null>(null)

const query = computed(() => {
  const q = new URLSearchParams()
  if (props.assetId) q.set('asset_id', props.assetId)
  if (kind.value !== 'all') q.set('kind', kind.value)
  if (showResolved.value) q.set('include_resolved', 'true')
  return q.toString()
})

const { data, pending, error, refresh } = await useAsyncData(
  `code-findings-${props.assetId ?? 'all'}`,
  () => api<any>(`code-findings?${query.value}`),
  { watch: [query] },
)
useEvents(['assets'], refresh)

const cov = computed(() => data.value?.coverage)
const scannedAny = computed(() =>
  CODE_FINDING_KINDS.some(k => (cov.value?.[k]?.scanned ?? 0) > 0))
const notCheckedWhat = computed(() => kind.value === 'all'
  ? 'secrets, configuration or start-up hook'
  : CODE_KIND_LABELS[kind.value].scanned)
function openCount(k: CodeFindingKind) {
  return Object.values<number>(data.value?.open_counts?.[k] ?? {}).reduce((a, b) => a + b, 0)
}

function ago(at: string) {
  const days = Math.floor((Date.now() - new Date(at).getTime()) / 86400000)
  return days <= 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`
}
</script>

<template>
  <section class="codefind">
    <div class="head">
      <div class="cov">
        <template v-for="k in CODE_FINDING_KINDS" :key="k">
          <div class="covtile">
            <StatTile
              :label="CODE_KIND_LABELS[k].tile"
              :value="cov?.[k]?.scanned ? openCount(k) : null"
              of="open"
              hint="not checked yet"
              :target="!cov ? undefined : compact
                ? (cov[k].failing ? `last scan failed` : undefined)
                : `${cov[k].scanned} of ${plural(cov.repositories, 'repository', 'repositories')} checked${cov[k].failing ? ` · ${cov[k].failing} failing` : ''}`"
            />
            <span v-if="cov?.[k]?.oldest_success" class="checked">
              {{ cov[k].scanned > 1 ? 'oldest check' : 'checked' }}
              <FreshnessIndicator :at="cov[k].oldest_success" />
            </span>
          </div>
        </template>
      </div>
      <div class="ctrl">
        <div class="seg">
          <button :class="{ on: kind === 'all' }" :aria-pressed="kind === 'all'" @click="kind = 'all'">All</button>
          <button
            v-for="k in CODE_FINDING_KINDS" :key="k"
            :class="{ on: kind === k }" :aria-pressed="kind === k" @click="kind = k"
          >
            {{ CODE_KIND_LABELS[k].filter }}
          </button>
        </div>
        <label class="chk"><input v-model="showResolved" type="checkbox"> resolved</label>
      </div>
    </div>

    <RowSkeleton v-if="pending && !data" :rows="3" />
    <StateBlock v-else-if="error" kind="error" title="Cannot load code findings">
      The core service did not answer.
      <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
    </StateBlock>

    <StateBlock
      v-else-if="data && !data.findings.length && cov && cov.repositories &&
        (kind === 'all' ? !scannedAny : !cov[kind]?.scanned)"
      kind="never" title="Not checked yet"
    >
      No repository has completed a {{ notCheckedWhat }}
      scan, so this is <strong>unknown, not clean</strong>. Scans run with the next
      repository patrol.
    </StateBlock>

    <StateBlock
      v-else-if="data && !data.findings.length && cov && !cov.repositories"
      kind="never" title="No repositories"
    >
      Athena has no repository to search, so nothing has been checked — this is
      <strong>not a clean result</strong>. Register a repository and it is searched on
      the next patrol.
    </StateBlock>

    <StateBlock v-else-if="data && !data.findings.length" kind="clean" title="Nothing open">
      Every repository counted above was searched and nothing open was found. Secrets
      in git history are not searched — only the working tree.
    </StateBlock>

    <ul v-else-if="data" class="list">
      <li v-for="f in data.findings" :key="f.id" class="item" :class="{ resolved: f.resolved_at }">
        <button class="row" :aria-expanded="open === f.id" @click="open = open === f.id ? null : f.id">
          <span class="tag caps kind" :class="{ bad: f.kind === 'secret' || f.kind === 'startup-hook' }">
            {{ codeKindTag(f.kind) }}
          </span>
          <SeverityChip :severity="f.severity === 'info' ? 'informational' : f.severity" />
          <span class="meat">
            <span class="title"><UntrustedText :text="f.title" /></span>
            <code class="loc"><UntrustedText :text="`${f.path}${f.line ? `:${f.line}` : ''}`" /></code>
          </span>
          <span v-if="!assetId" class="on">{{ f.asset.display_name }}</span>
          <span class="when" :title="utcStamp(f.resolved_at || f.first_seen)">
            {{ f.resolved_at ? `resolved ${ago(f.resolved_at)}` : `since ${ago(f.first_seen)}` }}
          </span>
        </button>
        <div v-if="open === f.id" class="body">
          <p v-if="!assetId" class="inrepo">
            In <NuxtLink :to="`/assets/${f.asset.id}`">{{ f.asset.display_name }}</NuxtLink>
            · {{ f.asset.tier }}
          </p>
          <p v-if="f.kind === 'secret'" class="guide">{{ data.guidance.secret.summary }}</p>
          <ol v-if="f.kind === 'secret'" class="steps">
            <li v-for="(s, i) in data.guidance.secret.steps" :key="i">{{ s }}</li>
          </ol>
          <template v-else-if="f.kind === 'startup-hook'">
            <p class="guide">{{ data.guidance['startup-hook']?.summary }}</p>
            <p v-if="f.detail.line_text" class="fix">
              <span class="lbl">Line {{ f.line }}</span>
              <code class="hookline"><UntrustedText :text="f.detail.line_text" /></code>
              <span v-if="f.detail.line_truncated" class="fine"> (cut short)</span>
            </p>
            <ol v-if="data.guidance['startup-hook']?.steps?.length" class="steps">
              <li v-for="(s, i) in data.guidance['startup-hook'].steps" :key="i">{{ s }}</li>
            </ol>
          </template>
          <template v-else>
            <p v-if="f.detail.message" class="guide"><UntrustedText :text="f.detail.message" /></p>
            <p v-if="f.detail.resolution" class="fix">
              <span class="lbl">Resolution</span> <UntrustedText :text="f.detail.resolution" />
            </p>
            <p v-if="f.detail.reference" class="fine">
              Reference (not a link): <code><UntrustedText :text="f.detail.reference" /></code>
            </p>
          </template>
          <p class="fine">
            {{ f.tool }} {{ f.tool_version || '' }} · rule <code>{{ f.rule_id }}</code>
            · last seen {{ ago(f.last_seen) }}
            <template v-if="f.kind === 'secret'"> · value redacted inside the scanner sandbox</template>
          </p>
        </div>
      </li>
    </ul>
    <p v-if="data && data.total > data.findings.length" class="fine">
      Showing {{ data.findings.length }} of {{ data.total }}.
    </p>
  </section>
</template>

<style scoped>
.codefind { display: flex; flex-direction: column; gap: .7rem; }
.head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-end; flex-wrap: wrap; }
.cov { display: flex; gap: 1.6rem; flex-wrap: wrap; }
.covtile { display: flex; flex-direction: column; gap: .3rem; }
.checked { display: flex; align-items: center; gap: .3rem; font-size: var(--fs-xs); color: var(--ink-muted); }
.inrepo { margin: 0 0 .45rem; font-size: var(--fs-sm); color: var(--ink-2); }
@media (max-width: 640px) {
  .row { flex-wrap: wrap; }
  .meat { order: 3; flex-basis: 100%; }
  .title { white-space: normal; }
}
.ctrl { display: flex; align-items: center; gap: .6rem; }
.chk { display: flex; align-items: center; gap: .3rem; margin: 0; font-size: .74rem; }
.chk input { width: auto; }

.list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: .4rem; }
.item { border: 1px solid var(--rule); border-radius: 8px; background: var(--surface); }
.item.resolved { background: var(--plane); }
.item.resolved .title { color: var(--ink-2); text-decoration: line-through; text-decoration-color: var(--line-strong); }
.row { width: 100%; display: flex; align-items: center; gap: .6rem; padding: .55rem .75rem;
       background: none; border: 0; color: var(--ink); text-align: left; font-weight: 400;
       border-radius: 8px; cursor: pointer; }
.row:hover { background: var(--plane); }
.kind { min-width: 4.6rem; justify-content: center; }
.meat { flex-grow: 1; min-width: 0; display: flex; flex-direction: column; gap: .1rem; }
.title { font-size: .82rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.loc { font-size: .72rem; color: var(--ink-muted); }
.hookline { font-size: .74rem; overflow-wrap: anywhere; }
.on { font-size: .74rem; color: var(--ink-2); white-space: nowrap; }
.when { font-size: .7rem; color: var(--ink-muted); white-space: nowrap; }
.body { border-top: 1px solid var(--rule); padding: .6rem .8rem .7rem; background: var(--plane);
        border-radius: 0 0 8px 8px; }
.guide { margin: 0 0 .45rem; font-size: .82rem; line-height: 1.5; color: var(--ink-2); }
.steps { margin: 0 0 .5rem; padding-left: 1.1rem; font-size: .8rem; color: var(--ink-2); }
.fix { margin: 0 0 .4rem; font-size: .8rem; color: var(--ink-2); }
.fine { margin: .2rem 0 0; font-size: .7rem; color: var(--ink-muted); }
</style>
