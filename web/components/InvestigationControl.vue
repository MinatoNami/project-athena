<script setup lang="ts">
const props = defineProps<{ findingId: string; mfaEnabled: boolean; held: boolean }>()
const emit = defineEmits<{ changed: [] }>()

const busy = ref(false)
const failed = ref<string | null>(null)
const notice = ref<string | null>(null)
const confirmingIdentity = ref(false)
const password = ref('')
const totpCode = ref('')
const pendingAction = ref<{ label: string; run: () => Promise<void> } | null>(null)
const offered = computed(() => investigationActions(props.held))

async function perform(label: string, run: () => Promise<void>) {
  busy.value = true
  failed.value = null
  notice.value = null
  try {
    await run()
    pendingAction.value = null
    emit('changed')
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

function act(kind: 'pause' | 'unpause' | 'cancel', label: string) {
  return perform(label, async () => {
    const result = await api<{ paused?: boolean; removed_jobs?: number }>(
      `findings/${props.findingId}/investigation/${kind}`,
      { method: 'POST' },
    )
    if (kind === 'cancel') {
      notice.value = `Investigation cancelled. ${result?.removed_jobs ?? 0} queued job(s) removed; it stays paused.`
    } else {
      notice.value = result?.paused ? 'Investigation paused.' : 'Investigation unpaused.'
    }
  })
}
</script>

<template>
  <div class="invcontrol" role="group" aria-label="Investigation control">
    <p>{{ investigationHoldStatus(props.held) }}</p>
    <div class="buttons">
      <button v-if="offered.includes('pause')" class="btn" :disabled="busy" @click="act('pause', 'Pause')">Pause investigation</button>
      <button v-if="offered.includes('unpause')" class="btn" :disabled="busy" @click="act('unpause', 'Unpause')">Unpause</button>
      <button v-if="offered.includes('cancel')" class="btn" :disabled="busy" @click="act('cancel', 'Cancel')">Cancel investigation</button>
    </div>
    <div v-if="confirmingIdentity" class="stepup">
      <label>
        Password
        <input v-model="password" type="password" autocomplete="current-password" />
      </label>
      <label v-if="props.mfaEnabled">
        Authenticator code
        <input v-model="totpCode" class="mono" inputmode="numeric" autocomplete="one-time-code" maxlength="6" />
      </label>
      <div class="buttons">
        <button class="btn primary" :disabled="busy || !stepUpReady(password, totpCode, props.mfaEnabled)"
                @click="confirmIdentity">Confirm</button>
        <button class="btn" :disabled="busy" @click="cancelIdentity">Cancel</button>
      </div>
    </div>
    <p v-if="notice" role="status">{{ notice }}</p>
    <p v-if="failed" class="failed" role="alert">{{ failed }}</p>
  </div>
</template>

<style scoped>
.invcontrol { display: flex; flex-direction: column; gap: .5rem; margin: .5rem 0; }
.buttons { display: flex; flex-wrap: wrap; gap: .5rem; }
.stepup { display: flex; flex-direction: column; gap: .4rem; max-width: 24rem; }
.stepup label { display: flex; flex-direction: column; gap: .2rem; font-size: .8rem; }
.invcontrol p { margin: 0; font-size: .8rem; }
.failed { color: var(--bad); }
</style>
