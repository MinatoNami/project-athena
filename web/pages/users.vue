<script setup lang="ts">
useHead({ title: 'Users' })

interface UserRow {
  id: string
  email: string
  role: string
  mfa_enabled: boolean
  disabled: boolean
  password_change_required: boolean
}

const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')
else if (!showsAdminNav(me.value)) await navigateTo('/')

const { data: users, pending, error, refresh } = await useAsyncData('users', () =>
  api<UserRow[]>('users'),
)

const inviteEmail = ref('')
const inviteRole = ref<string>('viewer')
const issued = ref<{ email: string; credential: string } | null>(null)
const copied = ref(false)

const busy = ref(false)
const failed = ref<string | null>(null)
const notice = ref<string | null>(null)
const confirmingIdentity = ref(false)
const password = ref('')
const totpCode = ref('')
const pendingAction = ref<{ label: string; run: () => Promise<void> } | null>(null)
const confirmTarget = ref<{ kind: 'disable' | 'mfa'; user: UserRow } | null>(null)
const roleDraft = reactive<Record<string, string>>({})

const inviteValid = computed(() => /^[^\s@]+@[^\s@]+$/.test(inviteEmail.value.trim()))

watchEffect(() => {
  for (const u of users.value ?? []) if (!(u.id in roleDraft)) roleDraft[u.id] = u.role
})

async function perform(label: string, run: () => Promise<void>) {
  busy.value = true
  failed.value = null
  notice.value = null
  try {
    await run()
    pendingAction.value = null
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

function invite() {
  const email = inviteEmail.value.trim()
  const role = inviteRole.value
  return perform('Invite', async () => {
    const res = await api<UserRow & { invite_credential: string }>('users/invite', {
      method: 'POST',
      body: { email, role },
    })
    issued.value = { email: res.email, credential: res.invite_credential }
    copied.value = false
    inviteEmail.value = ''
  })
}

function setRole(user: UserRow) {
  const role = roleDraft[user.id]
  if (!isRole(role) || role === user.role) return
  return perform('Role change', async () => {
    await api(`users/${user.id}/role`, { method: 'POST', body: { role } })
    notice.value = `${user.email} is now ${roleLabel(role)}.`
  })
}

function runConfirmed() {
  const target = confirmTarget.value
  if (!target) return
  confirmTarget.value = null
  if (target.kind === 'disable') {
    return perform('Disable', async () => {
      await api(`users/${target.user.id}/disable`, { method: 'POST' })
      notice.value = `${target.user.email} is disabled and signed out everywhere.`
    })
  }
  return perform('MFA reset', async () => {
    await api(`users/${target.user.id}/mfa/reset`, { method: 'POST' })
    notice.value = `${target.user.email} must enrol an authenticator app again.`
  })
}

async function copyCredential() {
  if (!issued.value) return
  try {
    await navigator.clipboard.writeText(issued.value.credential)
    copied.value = true
  } catch {
    failed.value = 'Copy failed. Select the text and copy it by hand.'
  }
}

function isSelf(user: UserRow) {
  return user.id === me.value?.id
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Users</h1>
        <p>Who can sign in, and what each person may do. Every change is recorded in the audit trail.</p>
      </div>
      <div class="actions">
        <button class="btn" :disabled="pending" @click="refresh()">Refresh</button>
      </div>
    </div>

    <section class="card panel">
      <h2>Invite someone</h2>
      <div class="invite">
        <label class="field grow">
          <span class="lbl">Email</span>
          <input v-model="inviteEmail" type="email" autocomplete="off" />
        </label>
        <label class="field">
          <span class="lbl">Role</span>
          <select v-model="inviteRole">
            <option v-for="r in ROLES" :key="r" :value="r">{{ roleLabel(r) }}</option>
          </select>
        </label>
        <button class="btn primary" :disabled="busy || !inviteValid" @click="invite">Invite</button>
      </div>
      <span class="hint">{{ roleHint(inviteRole) }}</span>

      <div v-if="issued" class="issued" role="status">
        <p class="lead">
          Single-use credential for <strong>{{ issued.email }}</strong>. It is shown once. Pass it on
          privately; they choose their own password at first sign-in.
        </p>
        <div class="credential">
          <input class="mono" readonly :value="issued.credential"
                 @focus="($event.target as HTMLInputElement).select()" />
          <button class="btn" type="button" @click="copyCredential">{{ copied ? 'Copied' : 'Copy' }}</button>
          <button class="btn" type="button" @click="issued = null">Done</button>
        </div>
      </div>
    </section>

    <section v-if="confirmingIdentity" class="card panel stepup" role="group" aria-labelledby="stepup-title">
      <h2 id="stepup-title">Confirm it is you</h2>
      <p class="lead">{{ pendingAction?.label }} needs a fresh sign-in confirmation.</p>
      <label class="field">
        <span class="lbl">Password</span>
        <input v-model="password" type="password" autocomplete="current-password" />
      </label>
      <label v-if="me?.mfa_enabled" class="field">
        <span class="lbl">Authenticator code</span>
        <input v-model="totpCode" class="mono" inputmode="numeric" autocomplete="one-time-code" maxlength="6" />
      </label>
      <div class="acts">
        <button class="btn" @click="cancelIdentity">Cancel</button>
        <button class="btn primary" :disabled="busy || !stepUpReady(password, totpCode, !!me?.mfa_enabled)"
                @click="confirmIdentity">Confirm and continue</button>
      </div>
    </section>

    <section v-if="confirmTarget" class="card panel stepup" role="group" aria-labelledby="confirm-title">
      <h2 id="confirm-title">
        {{ confirmTarget.kind === 'disable' ? 'Disable this account?' : 'Reset this authenticator?' }}
      </h2>
      <p class="lead">
        <strong>{{ confirmTarget.user.email }}</strong>
        {{ confirmTarget.kind === 'disable'
          ? 'can no longer sign in, and every open session ends now.'
          : 'is signed out everywhere and must enrol an authenticator app again.' }}
      </p>
      <div class="acts">
        <button class="btn" @click="confirmTarget = null">Cancel</button>
        <button class="btn primary" :disabled="busy" @click="runConfirmed">
          {{ confirmTarget.kind === 'disable' ? 'Disable' : 'Reset' }}
        </button>
      </div>
    </section>

    <p v-if="failed" class="failed" role="alert">{{ failed }}</p>
    <p v-if="notice" class="notice" role="status">{{ notice }}</p>

    <StateBlock v-if="error" kind="error" title="Cannot read the users">
      {{ errorDetail(error, 'The list did not load.') }}
      <template #actions><button class="btn primary" @click="refresh()">Retry</button></template>
    </StateBlock>

    <section v-else-if="users" class="card">
      <table class="users">
        <thead>
          <tr>
            <th scope="col">Email</th>
            <th scope="col">Role</th>
            <th scope="col">Authenticator</th>
            <th scope="col">Status</th>
            <th scope="col"><span class="sr">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id" :class="{ off: u.disabled }">
            <td class="email">{{ u.email }}<span v-if="isSelf(u)" class="you">you</span></td>
            <td>
              <div class="role">
                <select v-model="roleDraft[u.id]" :disabled="busy || isSelf(u) || u.disabled"
                        :aria-label="`Role for ${u.email}`">
                  <option v-if="!isRole(u.role)" :value="u.role">{{ roleLabel(u.role) }}</option>
                  <option v-for="r in ROLES" :key="r" :value="r">{{ roleLabel(r) }}</option>
                </select>
                <button v-if="roleDraft[u.id] !== u.role" class="btn" :disabled="busy"
                        @click="setRole(u)">Save</button>
              </div>
            </td>
            <td>{{ u.mfa_enabled ? 'Enabled' : 'Not enabled' }}</td>
            <td>
              {{ u.disabled ? 'Disabled' : u.password_change_required ? 'Invited, not signed in' : 'Active' }}
            </td>
            <td class="rowacts">
              <template v-if="!isSelf(u)">
                <button v-if="u.mfa_enabled" class="btn" :disabled="busy"
                        @click="confirmTarget = { kind: 'mfa', user: u }">Reset authenticator</button>
                <button v-if="!u.disabled" class="btn" :disabled="busy"
                        @click="confirmTarget = { kind: 'disable', user: u }">Disable</button>
              </template>
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>

<style scoped>
.panel { display: flex; flex-direction: column; gap: .7rem; padding: 1.1rem 1.25rem; margin-bottom: 1rem; }
.stepup { max-width: 34rem; border-color: var(--ink-muted); }
h2 { margin: 0; font-size: 1rem; font-weight: 640; text-transform: none; color: var(--ink); }
.invite { display: flex; align-items: flex-end; gap: .6rem; flex-wrap: wrap; }
.field { display: flex; flex-direction: column; gap: .35rem; }
.grow { flex: 1 1 16rem; }
.lbl { font-size: .74rem; color: var(--ink-muted); }
input, select {
  font: inherit; font-size: .84rem; padding: .42rem .6rem; border-radius: 7px;
  border: 1px solid var(--rule); background: var(--plane); color: var(--ink);
}
.hint { font-size: .74rem; color: var(--ink-muted); }
.lead { margin: 0; font-size: .84rem; line-height: 1.55; color: var(--ink-2); overflow-wrap: anywhere; }
.issued { display: flex; flex-direction: column; gap: .5rem; border-top: 1px solid var(--rule); padding-top: .8rem; }
.credential { display: flex; gap: .5rem; flex-wrap: wrap; }
.credential input { flex: 1 1 18rem; }
.acts { display: flex; justify-content: flex-end; gap: .5rem; }
.failed { margin: 0 0 1rem; font-size: .82rem; color: var(--crit); }
.notice { margin: 0 0 1rem; font-size: .82rem; color: var(--ink-2); }
.users { width: 100%; border-collapse: collapse; font-size: .84rem; }
.users th { text-align: left; font-size: .72rem; font-weight: 600; color: var(--ink-muted);
            padding: .6rem .9rem; border-bottom: 1px solid var(--rule); }
.users td { padding: .55rem .9rem; border-bottom: 1px solid var(--rule); vertical-align: middle; }
.users tr:last-child td { border-bottom: 0; }
.users tr.off td { color: var(--ink-muted); }
.email { overflow-wrap: anywhere; }
.you { margin-left: .4rem; font-size: .68rem; color: var(--ink-muted); border: 1px solid var(--rule);
       border-radius: 4px; padding: 0 .3rem; }
.role { display: flex; gap: .4rem; align-items: center; }
.rowacts { display: flex; gap: .4rem; justify-content: flex-end; flex-wrap: wrap; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
</style>
