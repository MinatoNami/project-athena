<script setup lang="ts">
const email = ref('')
const password = ref('')
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
    await api('auth/login', { method: 'POST', body: { email: email.value, password: password.value } })
    await navigateTo('/')
  } catch (e: any) {
    error.value = e?.data?.detail || 'Invalid credentials'
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
      <div style="margin-top:1.25rem">
        <button type="submit" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>
      </div>
      <p v-if="error" class="err">{{ error }}</p>
    </form>
  </div>
</template>
