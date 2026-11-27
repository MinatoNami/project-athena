<script setup lang="ts">
const props = defineProps<{ canAdminister: boolean; mfaEnabled: boolean }>()

const route = useRoute()

const { data: control, refresh } = await useAsyncData('shell-control', async () =>
  parseHaltState(await api<unknown>('control').catch(() => null)),
)

watch(() => route.fullPath, () => refresh())

const editing = ref(false)
const reason = ref('')
const busy = ref(false)
const failed = ref<string | null>(null)
const confirmingIdentity = ref(false)
const password = ref('')
const totpCode = ref('')
const pendingAction = ref<{ label: string; run: () => Promise<void> } | null>(null)

const reasonValid = computed(() => isHaltReasonValid(reason.value))

async function perform(label: string, run: () => Promise<void>) {
  busy.value = true
  failed.value = null
  try {
    await run()
    pendingAction.value = null
    editing.value = false
    reason.value = ''
    await refresh()
  } catch (e: any) {
    if (isStepUpRequired(e)) {
      pendingAction.value = { label, run }
      confirmingIdentity.value = true
      return
    }
    failed.value = errorDetail(e, `${label} did not complete.`)
  } finally {
    busy.value = false
  }
}

async function confirmIdentity() {
  const action = pendingAction.value
  if (!action) return
  busy.value = true
  failed.value = null
  try {
    await stepUp(password.value, totpCode.value.trim())
  } catch (e: any) {
    failed.value = errorDetail(e, 'Re-authentication failed.')
    busy.value = false
    return
  } finally {
    password.value = ''
    totpCode.value = ''
  }
  confirmingIdentity.value = false
  busy.value = false
  await perform(action.label, action.run)
}

function cancelIdentity() {
  confirmingIdentity.value = false
  pendingAction.value = null
  password.value = ''
  totpCode.value = ''
}

function halt() {
  const text = reason.value.trim()
  if (!isHaltReasonValid(text)) return
  return perform('Halt', async () => {
    await api('control/halt', { method: 'POST', body: { reason: text } })
  })
}

function resume() {
  return perform('Resume', async () => {
    await api('control/resume', { method: 'POST' })
  })
}
</script>

<template>
  <div class="control">
    <section v-if="control?.halted" class="halted" role="alert" aria-labelledby="halt-title">
      <div class="body">
        <strong id="halt-title">Halted: the kill switch is on.</strong>
        <p class="reason">Reason: <UntrustedText :text="control.reason ?? 'none given'" /></p>
        <p class="meta">{{ haltAttribution(control) }}</p>
      </div>
      <button v-if="props.canAdminister" class="btn" :disabled="busy" @click="resume">Resume</button>
    </section>
    <section v-else-if="control === null" class="unknown" role="status">
      Kill switch state could not be read.
    </section>

    <div v-if="props.canAdminister && control && !control.halted" class="toggle">
      <button v-if="!editing" class="btn" @click="editing = true">Halt</button>
      <form v-else class="haltform" @submit.prevent="halt">
        <label>
          Reason for halting
          <input v-model="reason" required :minlength="HALT_REASON_MIN" :maxlength="HALT_REASON_MAX" />
        </label>
        <button class="btn primary" type="submit" :disabled="busy || !reasonValid">Halt</button>
        <button class="btn" type="button" :disabled="busy" @click="editing = false; reason = ''">Cancel</button>
      </form>
    </div>

    <section v-if="confirmingIdentity" class="card panel stepup" role="group" aria-labelledby="halt-stepup-title">
      <h2 id="halt-stepup-title">Confirm it is you</h2>
      <label>
        Password
        <input v-model="password" type="password" autocomplete="current-password" />
      </label>
      <label v-if="props.mfaEnabled">
        Authenticator code
        <input v-model="totpCode" class="mono" inputmode="numeric" autocomplete="one-time-code" maxlength="8" />
      </label>
      <div class="actions">
        <button class="btn primary" :disabled="busy || !password || (props.mfaEnabled && !totpCode)"
                @click="confirmIdentity">Confirm</button>
        <button class="btn" :disabled="busy" @click="cancelIdentity">Cancel</button>
      </div>
    </section>

    <p v-if="failed" class="failed" role="alert">{{ failed }}</p>
  </div>
</template>

<style scoped>
.control { display: flex; flex-direction: column; gap: .5rem; }
.control:empty { display: none; }
.halted {
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  padding: .75rem 1.25rem; background: var(--bad); color: var(--surface);
}
.halted .body { display: flex; flex-direction: column; gap: .2rem; min-width: 0; }
.halted p { margin: 0; font-size: .82rem; overflow-wrap: anywhere; }
.unknown { padding: .5rem 1.25rem; color: var(--warn-ink); font-size: .8rem; }
.toggle { display: flex; justify-content: flex-end; padding: .5rem 1.25rem 0; }
.haltform { display: flex; flex-wrap: wrap; align-items: flex-end; gap: .5rem; }
.haltform label { display: flex; flex-direction: column; gap: .2rem; font-size: .78rem; }
.haltform input { min-width: 18rem; }
.stepup { max-width: 34rem; margin: 0 1.25rem; display: flex; flex-direction: column; gap: .5rem; }
.stepup label { display: flex; flex-direction: column; gap: .2rem; font-size: .8rem; }
.actions { display: flex; gap: .5rem; }
.failed { margin: 0 1.25rem; color: var(--bad); font-size: .8rem; }
</style>
