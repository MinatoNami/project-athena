<script setup lang="ts">
/** First-run admin creation. The token is printed once to the API log by
 *  `athena bootstrap` — the deployment ships no credentials of any kind. */
useHead({ title: 'First run' })

const token = ref('')
const email = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  if (password.value.length < 12) {
    error.value = 'Password must be at least 12 characters.'
    return
  }
  busy.value = true
  try {
    await api('auth/bootstrap', {
      method: 'POST',
      body: { token: token.value.trim(), email: email.value, password: password.value },
    })
    await navigateTo('/')
  } catch (e: any) {
    error.value = e?.data?.detail || 'Bootstrap failed'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="wrap" style="max-width:28rem;padding-top:5rem">
    <h1>Create the first account</h1>
    <p class="sub">
      Athena ships with no default credentials. Retrieve the single-use bootstrap
      token from the API log.
    </p>
    <p class="sub cmds">
      running locally:
      <br><code>docker compose exec api athena bootstrap</code>
      <br><br>on a deployment host:
      <br><code>./deploy/deploy.sh bootstrap</code>
    </p>
    <form class="card" @submit.prevent="submit">
      <label for="token">Bootstrap token</label>
      <input id="token" v-model="token" required autocomplete="off">
      <label for="email">Email</label>
      <input id="email" v-model="email" type="email" autocomplete="username" required>
      <label for="password">Password (12+ characters)</label>
      <input id="password" v-model="password" type="password" autocomplete="new-password" required>
      <div style="margin-top:1.25rem">
        <button type="submit" :disabled="busy">{{ busy ? 'Creating…' : 'Create admin account' }}</button>
      </div>
      <p v-if="error" class="err">{{ error }}</p>
    </form>
  </div>
</template>

<style scoped>
.cmds { font-size: .85rem; }
</style>
