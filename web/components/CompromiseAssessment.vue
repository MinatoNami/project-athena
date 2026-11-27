<script setup lang="ts">
const props = defineProps<{ findingId: string, assessment: any }>()
const emit = defineEmits<{ done: [] }>()

const chosen = ref<Record<string, string>>({})
const busy = ref(false)
const failed = ref<string | null>(null)

const open = computed(() =>
  (props.assessment?.questions ?? []).filter((q: any) => q.answer == null))
const answered = computed(() =>
  (props.assessment?.questions ?? []).filter((q: any) => q.answer != null))
const ready = computed(() => Object.keys(chosen.value).length > 0)

function labelOf(q: any) {
  return q.options.find((o: any) => o.value === q.answer)?.label ?? q.answer
}

async function submit() {
  busy.value = true
  failed.value = null
  try {
    await api(`findings/${props.findingId}/compromise-assessment`, {
      method: 'POST',
      body: { answers: chosen.value },
    })
    chosen.value = {}
    emit('done')
  } catch (e: any) {
    failed.value = e?.data?.detail ?? e?.message ?? 'The answers were not saved.'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="assess">
    <div class="lbl">Compromise assessment</div>
    <p v-if="open.length">
      <strong>Did it run, and what could it reach?</strong>
      Removing the package does not undo code that ran at install or startup. Answers
      are kept as evidence; they do not lower the priority or close the finding.
    </p>
    <p v-else><strong>Answered.</strong> The answers are under Raw evidence.</p>

    <fieldset v-for="q in open" :key="q.key" class="field">
      <legend class="q">{{ q.prompt }}</legend>
      <div class="reasons">
        <button
          v-for="o in q.options" :key="o.value" type="button" class="reason"
          :class="{ on: chosen[q.key] === o.value }" :aria-pressed="chosen[q.key] === o.value"
          @click="chosen = { ...chosen, [q.key]: o.value }"
        >{{ o.label }}</button>
      </div>
    </fieldset>

    <ul v-if="answered.length" class="done">
      <li v-for="q in answered" :key="q.key">
        <span class="muted">{{ q.prompt }}</span> {{ labelOf(q) }}
      </li>
    </ul>

    <template v-if="open.length">
      <p v-if="failed" class="failed">{{ failed }}</p>
      <button class="btn primary" :disabled="busy || !ready" @click="submit">
        {{ busy ? 'Saving…' : 'Record answers' }}
      </button>
    </template>
  </div>
</template>

<style scoped>
.assess { border: 1px solid var(--rule); border-radius: 9px;
          background: var(--surface); padding: .85rem .9rem; margin-top: .75rem; }
.assess p { margin: .5rem 0 .6rem; font-size: .8rem; line-height: 1.5; color: var(--ink-2); }
.assess p strong { color: var(--ink); font-weight: 600; }
.field { border: 0; padding: 0; margin: 0 0 .7rem; }
.q { font-size: .8rem; color: var(--ink); margin-bottom: .35rem; }
.reasons { display: flex; flex-wrap: wrap; gap: .3rem; }
.reason {
  font: inherit; font-size: .76rem; padding: .3rem .6rem; border-radius: 6px;
  border: 1px solid var(--rule); background: transparent; color: var(--ink-2); cursor: pointer;
}
.reason:hover { background: var(--plane); color: var(--ink); }
.reason.on { background: var(--ink); color: var(--surface); border-color: var(--ink); font-weight: 600; }
.done { margin: 0 0 .6rem; padding-left: 1rem; font-size: .78rem; line-height: 1.5; }
.failed { color: var(--crit) !important; }
</style>
