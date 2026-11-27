<script setup lang="ts">
useHead({ title: 'Account security' })

const { data: me, refresh: refreshMe } = await useMe()
if (!me.value) await navigateTo('/login')

const provisioningUri = ref<string | null>(null)
const code = ref('')
const password = ref('')
const confirmingIdentity = ref(false)
const busy = ref(false)
const failed = ref<string | null>(null)
const copied = ref(false)

const secret = computed(() => (provisioningUri.value ? totpSecretFromUri(provisioningUri.value) : null))
const codeValid = computed(() => /^\d{6,8}$/.test(code.value.trim()))

async function startEnrolment() {
  busy.value = true
  failed.value = null
  try {
    if (confirmingIdentity.value) {
      await stepUp(password.value)
      password.value = ''
      confirmingIdentity.value = false
    }
    const res = await api<{ provisioning_uri: string }>('auth/mfa/enrol', { method: 'POST' })
    provisioningUri.value = res.provisioning_uri
    copied.value = false
  } catch (e: any) {
    if (isStepUpRequired(e)) {
      confirmingIdentity.value = true
      failed.value = 'Confirm your password to start enrolment.'
      return
    }
    failed.value = errorDetail(e, 'Enrolment did not start.')
  } finally {
    busy.value = false
  }
}

async function confirmEnrolment() {
  busy.value = true
  failed.value = null
  try {
    await api('auth/mfa/confirm', { method: 'POST', body: { code: code.value.trim() } })
    provisioningUri.value = null
    code.value = ''
    await refreshMe()
  } catch (e: any) {
    failed.value = errorDetail(e, 'The code was not accepted.')
  } finally {
    busy.value = false
  }
}

async function copyUri() {
  if (!provisioningUri.value) return
  try {
    await navigator.clipboard.writeText(provisioningUri.value)
    copied.value = true
  } catch {
    copied.value = false
    failed.value = 'Copy failed. Select the text and copy it by hand.'
  }
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Account security</h1>
        <p>Your sign-in and second factor.</p>
      </div>
    </div>

    <section v-if="me" class="card panel">
      <dl class="facts">
        <dt>Email</dt>
        <dd>{{ me.email }}</dd>
        <dt>Role</dt>
        <dd>{{ roleLabel(me.role) }}</dd>
        <dt>Authenticator app</dt>
        <dd>
          <span class="status" :class="me.mfa_enabled ? 'on' : 'off'">
            <span class="dot" :class="me.mfa_enabled ? 'live' : 'down'" />
            {{ me.mfa_enabled ? 'Enabled' : 'Not enabled' }}
          </span>
        </dd>
      </dl>
    </section>

    <section v-if="me && !me.mfa_enabled" class="card panel">
      <h2>Set up an authenticator app</h2>

      <template v-if="!provisioningUri">
        <p class="lead">
          After this, signing in and confirming consequential actions also need a six-digit code
          from your authenticator app.
        </p>
        <template v-if="confirmingIdentity">
          <label class="field">
            <span class="lbl">Password</span>
            <input v-model="password" type="password" autocomplete="current-password" />
          </label>
        </template>
        <p v-if="failed" class="failed" role="alert">{{ failed }}</p>
        <div class="acts">
          <button class="btn primary" :disabled="busy || (confirmingIdentity && !password)"
                  @click="startEnrolment">
            {{ busy ? 'Starting…' : 'Start enrolment' }}
          </button>
        </div>
      </template>

      <template v-else>
        <p class="lead">
          Add this to your authenticator app. It is shown once: if you leave this page before
          confirming, start again.
        </p>
        <label class="field">
          <span class="lbl">Provisioning URI</span>
          <textarea class="mono uri" rows="3" readonly :value="provisioningUri"
                    @focus="($event.target as HTMLTextAreaElement).select()" />
        </label>
        <p v-if="secret" class="hint">
          To type it in by hand, the key is <code class="mono">{{ secret }}</code>.
        </p>
        <div class="acts left">
          <button class="btn" type="button" @click="copyUri">{{ copied ? 'Copied' : 'Copy' }}</button>
        </div>

        <label class="field">
          <span class="lbl">Code from the app</span>
          <input v-model="code" class="mono" inputmode="numeric" autocomplete="one-time-code"
                 maxlength="8" @keydown.enter="codeValid && !busy && confirmEnrolment()" />
        </label>
        <p v-if="failed" class="failed" role="alert">{{ failed }}</p>
        <div class="acts">
          <button class="btn primary" :disabled="busy || !codeValid" @click="confirmEnrolment">
            {{ busy ? 'Checking…' : 'Confirm' }}
          </button>
        </div>
      </template>
    </section>

    <section v-else-if="me" class="card panel">
      <p class="lead">
        Your authenticator app is enabled. To move it to a new device, ask an admin to reset it,
        then enrol again here.
      </p>
    </section>
  </div>
</template>

<style scoped>
.panel { display: flex; flex-direction: column; gap: .8rem; padding: 1.1rem 1.25rem;
         margin-bottom: 1rem; max-width: 44rem; }
h2 { margin: 0; font-size: 1rem; font-weight: 640; text-transform: none; color: var(--ink); }
.facts { display: grid; grid-template-columns: max-content 1fr; gap: .45rem 1.2rem; margin: 0;
         font-size: .85rem; }
.facts dt { color: var(--ink-muted); }
.facts dd { margin: 0; color: var(--ink); overflow-wrap: anywhere; }
.status { display: inline-flex; align-items: center; gap: .4rem; }
.status.off { color: var(--warn-ink); font-weight: 500; }
.lead { margin: 0; font-size: .84rem; line-height: 1.55; color: var(--ink-2); }
.field { display: flex; flex-direction: column; gap: .35rem; }
.lbl { font-size: .74rem; color: var(--ink-muted); }
input, textarea {
  width: 100%; font: inherit; font-size: .84rem; padding: .45rem .6rem;
  border-radius: 7px; border: 1px solid var(--rule); background: var(--plane); color: var(--ink);
}
.uri { resize: none; overflow-wrap: anywhere; font-size: .78rem; }
.hint { margin: 0; font-size: .74rem; color: var(--ink-muted); }
.failed { margin: 0; font-size: .8rem; color: var(--crit); }
.acts { display: flex; justify-content: flex-end; gap: .5rem; }
.acts.left { justify-content: flex-start; }
</style>
