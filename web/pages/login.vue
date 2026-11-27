<script setup lang="ts">
definePageMeta({ layout: false })

useHead({ title: 'Sign in' })
const email = ref('')
const password = ref('')
const totpCode = ref('')
const newPassword = ref('')
const needsNewPassword = ref(false)
const error = ref('')
const busy = ref(false)

const { data: bootstrap } = await useAsyncData('bootstrap-required', () =>
  api<{ required: boolean }>('auth/bootstrap-required'),
)
if (bootstrap.value?.required) await navigateTo('/bootstrap')

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const body: Record<string, string> = { email: email.value, password: password.value }
    if (totpCode.value.trim()) body.totp_code = totpCode.value.trim()
    if (needsNewPassword.value) body.new_password = newPassword.value
    await api('auth/login', { method: 'POST', body })
    await navigateTo('/')
  } catch (e: any) {
    const detail = e?.data?.detail
    if (detail === 'Password change required') needsNewPassword.value = true
    error.value = typeof detail === 'string' ? detail : 'Invalid credentials'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="wrap" style="max-width:24rem;padding-top:6rem">
    <h1>{{ $config.public.appName }}</h1>
    <p class="sub">Sign in to continue.</p>
    <form class="card" @submit.prevent="submit">
      <label for="email">Email</label>
      <input id="email" v-model="email" type="email" autocomplete="username" required>
      <label for="password">Password</label>
      <input id="password" v-model="password" type="password" autocomplete="current-password" required>
      <label for="totp">Authenticator code (if enabled)</label>
      <input id="totp" v-model="totpCode" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" maxlength="8">
      <template v-if="needsNewPassword">
        <label for="new-password">New password (at least 12 characters)</label>
        <input id="new-password" v-model="newPassword" type="password" autocomplete="new-password" minlength="12" required>
      </template>
      <div style="margin-top:1.25rem">
        <button type="submit" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>
      </div>
      <p v-if="error" class="err">{{ error }}</p>
    </form>
  </div>
</template>
