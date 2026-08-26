<script setup lang="ts">
/**
 * Suppressing a finding.
 *
 * The form asks for the two things that make this a decision rather than a delete:
 * why, and how far it reaches. Both are shown back on the finding when it returns,
 * so the copy here is written for whoever reads it months from now rather than for
 * whoever is clicking today.
 */
const props = defineProps<{
  findingId: string
  vulnerabilityId: string
  asset: string
  instanceCount?: number
}>()
const emit = defineEmits<{ close: []; done: [] }>()

const REASONS = [
  { code: 'not_applicable', label: 'Cannot apply here',
    hint: 'The flaw needs something this asset does not have.' },
  { code: 'compensating_control', label: 'Something else prevents it',
    hint: 'A control already in place blocks exploitation.' },
  { code: 'false_positive', label: 'The match is wrong',
    hint: 'This is not really the affected package or version.' },
  { code: 'fix_scheduled', label: 'Fix already planned',
    hint: 'Work is scheduled; hide it until then.' },
  { code: 'accepted_risk', label: 'Accepted for now',
    hint: 'Understood and tolerated. Needs a review date.' },
]

const SCOPES = [
  { id: 'finding', label: 'This finding only' },
  { id: 'asset', label: 'This vulnerability on this asset' },
  { id: 'everywhere', label: 'This vulnerability everywhere' },
]

const reasonCode = ref('not_applicable')
const reason = ref('')
const scope = ref('finding')
const until = ref('')
const saving = ref(false)
const failed = ref<string | null>(null)

/** Accepted risk is an appetite, not a fact, so nothing else will prompt a review. */
const expiryRequired = computed(() => reasonCode.value === 'accepted_risk')
const hint = computed(() => REASONS.find(r => r.code === reasonCode.value)?.hint ?? '')
const tooShort = computed(() => reason.value.trim().length < 8)

async function submit() {
  saving.value = true
  failed.value = null
  try {
    await api(`findings/${props.findingId}/suppress`, {
      method: 'POST',
      body: {
        reason_code: reasonCode.value,
        reason: reason.value.trim(),
        scope: scope.value,
        expires_at: until.value ? new Date(`${until.value}T00:00:00`).toISOString() : null,
      },
    })
    emit('done')
  } catch (e: any) {
    // The API writes these for the operator, so they are shown as sent.
    failed.value = e?.data?.detail ?? e?.message ?? 'The suppression was not saved.'
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="backdrop" @click.self="emit('close')">
    <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="suppress-title">
      <h2 id="suppress-title">Stop showing this finding</h2>
      <p class="lead">
        <code>{{ vulnerabilityId }}</code> on <strong>{{ asset }}</strong>. It is not
        deleted — it stays counted, and comes back if what you are relying on changes.
      </p>

      <label class="field">
        <span class="lbl">Why</span>
        <div class="reasons">
          <button
            v-for="r in REASONS" :key="r.code" type="button" class="reason"
            :class="{ on: reasonCode === r.code }" @click="reasonCode = r.code"
          >{{ r.label }}</button>
        </div>
        <span class="hint">{{ hint }}</span>
      </label>

      <label class="field">
        <span class="lbl">In your words</span>
        <textarea
          v-model="reason" rows="3"
          placeholder="What makes this safe to set aside? Somebody reads this when it comes back."
        />
        <span class="hint" :class="{ warn: reason.length > 0 && tooShort }">
          {{ reason.length > 0 && tooShort
            ? 'A few more words — this is the whole explanation later.'
            : 'Shown on the finding, and in the audit trail.' }}
        </span>
      </label>

      <label class="field">
        <span class="lbl">How far it reaches</span>
        <select v-model="scope">
          <option v-for="s in SCOPES" :key="s.id" :value="s.id">{{ s.label }}</option>
        </select>
        <span v-if="scope === 'everywhere' && (instanceCount ?? 0) > 1" class="hint warn">
          Covers all {{ instanceCount }} affected assets, including ones added later.
        </span>
      </label>

      <label class="field">
        <span class="lbl">
          Review on
          <span v-if="!expiryRequired" class="optional">optional</span>
        </span>
        <input v-model="until" type="date">
        <span class="hint" :class="{ warn: expiryRequired && !until }">
          {{ expiryRequired
            ? 'Required: an accepted risk with no review date is one nobody revisits.'
            : 'Leave empty to keep it until the premise changes or you revoke it.' }}
        </span>
      </label>

      <p v-if="failed" class="failed">{{ failed }}</p>

      <div class="acts">
        <button class="btn" @click="emit('close')">Cancel</button>
        <button
          class="btn primary"
          :disabled="saving || tooShort || (expiryRequired && !until)"
          @click="submit"
        >{{ saving ? 'Saving…' : 'Stop showing it' }}</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.backdrop {
  position: fixed; inset: 0; background: rgba(0, 0, 0, .45);
  display: flex; align-items: center; justify-content: center; padding: 1.5rem; z-index: 50;
}
.dialog {
  background: var(--surface); border: 1px solid var(--rule); border-radius: 12px;
  padding: 1.25rem 1.4rem; width: min(30rem, 100%); max-height: 90vh; overflow: auto;
  display: flex; flex-direction: column; gap: .85rem;
}
h2 { margin: 0; font-size: 1.05rem; font-weight: 640; letter-spacing: -0.01em;
     text-transform: none; color: var(--ink); }
.lead { margin: 0; font-size: .82rem; line-height: 1.55; color: var(--ink-2); }
.field { display: flex; flex-direction: column; gap: .35rem; margin: 0; }
.reasons { display: flex; flex-wrap: wrap; gap: .3rem; }
.reason {
  font: inherit; font-size: .76rem; padding: .3rem .6rem; border-radius: 6px;
  border: 1px solid var(--rule); background: transparent; color: var(--ink-2); cursor: pointer;
}
.reason:hover { background: var(--plane); color: var(--ink); }
.reason.on { background: var(--ink); color: var(--surface); border-color: var(--ink); font-weight: 600; }
textarea, select, input[type="date"] {
  width: 100%; font: inherit; font-size: .82rem; padding: .45rem .6rem;
  border-radius: 7px; border: 1px solid var(--rule);
  background: var(--plane); color: var(--ink); resize: vertical;
}
.hint { font-size: .71rem; color: var(--ink-muted); line-height: 1.45; }
.hint.warn { color: var(--warn-ink); }
.optional { font-size: .62rem; opacity: .7; text-transform: none; letter-spacing: 0; }
.failed { margin: 0; font-size: .78rem; color: var(--crit); }
.acts { display: flex; justify-content: flex-end; gap: .5rem; margin-top: .2rem; }
</style>
