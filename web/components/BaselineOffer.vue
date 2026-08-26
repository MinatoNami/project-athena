<script setup lang="ts">
/**
 * The offer to draw a line under an inherited backlog.
 *
 * Shown only while it would do something. The copy states what stays visible as
 * plainly as what goes, because an offer that reads as "make this all go away" is
 * one people take once and then distrust — and the escape clause means it is not
 * what happens anyway.
 */
const emit = defineEmits<{ done: [] }>()

const { data, refresh } = await useAsyncData('baseline', () =>
  api<any>('baseline').catch(() => null),
)

const busy = ref(false)
const failed = ref<string | null>(null)
const confirming = ref(false)

const accept = computed(() => data.value?.would_accept)
const worthOffering = computed(() => (accept.value?.would_leave_default_view ?? 0) > 0)

async function capture() {
  busy.value = true
  failed.value = null
  try {
    await api('baseline', { method: 'POST', body: {} })
    await refresh()
    confirming.value = false
    emit('done')
  } catch (e: any) {
    failed.value = e?.data?.detail ?? e?.message ?? 'The baseline was not saved.'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="worthOffering" class="offer">
    <div class="lbl">Start from here</div>
    <p>
      <strong>{{ accept.findings.toLocaleString() }} findings across
      {{ accept.assets_without_baseline.toLocaleString() }} assets pre-date your first
      look.</strong>
      They are the state you inherited, not something that happened this week.
    </p>

    <template v-if="!confirming">
      <button class="btn primary block" @click="confirming = true">
        Set a baseline
      </button>
      <p class="fine">
        Moves {{ accept.would_leave_default_view.toLocaleString() }} out of the default
        view. Nothing is hidden or deleted — one filter shows it all again.
      </p>
    </template>

    <template v-else>
      <!-- What stays is stated as plainly as what goes. -->
      <ul class="effects">
        <li>
          <span class="mono tnum">{{ accept.would_leave_default_view.toLocaleString() }}</span>
          move to <em>pre-existing</em>, still listed and still counted
        </li>
        <li v-if="accept.stays_visible">
          <span class="mono tnum">{{ accept.stays_visible.toLocaleString() }}</span>
          stay where they are — known-exploited or scored high and above are never
          set aside by a baseline
        </li>
        <li>Anything found from now on arrives as new</li>
      </ul>
      <p v-if="failed" class="failed">{{ failed }}</p>
      <div class="acts">
        <button class="btn" :disabled="busy" @click="confirming = false">Cancel</button>
        <button class="btn primary" :disabled="busy" @click="capture">
          {{ busy ? 'Setting…' : 'Set it' }}
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.offer { border: 1px solid var(--rule); border-radius: 9px;
         background: var(--surface); padding: .85rem .9rem; }
.offer p { margin: .5rem 0 .6rem; font-size: .8rem; line-height: 1.5; color: var(--ink-2); }
.offer p strong { color: var(--ink); font-weight: 600; }
.fine { margin: .5rem 0 0 !important; font-size: .71rem; color: var(--ink-muted); }
.block { display: block; width: 100%; }
.effects { margin: .1rem 0 .7rem; padding-left: 1rem;
           display: flex; flex-direction: column; gap: .35rem; }
.effects li { font-size: .78rem; line-height: 1.45; color: var(--ink-2); }
.effects .mono { font-weight: 600; color: var(--ink); }
.failed { margin: 0 0 .5rem !important; font-size: .76rem; color: var(--crit); }
.acts { display: flex; gap: .45rem; }
.acts .btn { flex: 1; }
</style>
