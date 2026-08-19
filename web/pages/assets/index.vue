<script setup lang="ts">
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data, refresh, pending } = await useAsyncData('assets', () =>
  api<{ assets: any[]; coverage: any }>('assets'),
)

const url = ref('')
const tier = ref('unknown')
const busy = ref(false)
const error = ref('')

async function addRepository() {
  error.value = ''
  busy.value = true
  try {
    await api('assets/repositories', { method: 'POST', body: { url: url.value, tier: tier.value } })
    url.value = ''
    await refresh()
  } catch (e: any) {
    error.value = e?.data?.detail || 'Could not register that repository'
  } finally {
    busy.value = false
  }
}

useEvents(['assets'], refresh)
</script>

<template>
  <div class="wrap">
    <h1>Assets</h1>
    <p class="sub">What Athena knows about, and how recently it looked.</p>

    <CoveragePanel v-if="data?.coverage" :coverage="data.coverage" />

    <div class="card">
      <h2>Connect a repository</h2>
      <form class="row" @submit.prevent="addRepository">
        <input v-model="url" placeholder="https://github.com/org/repo.git" required>
        <select v-model="tier">
          <option value="unknown">tier: unset</option>
          <option value="production">production</option>
          <option value="staging">staging</option>
          <option value="development">development</option>
          <option value="personal">personal</option>
        </select>
        <button type="submit" :disabled="busy">{{ busy ? 'Adding…' : 'Add' }}</button>
      </form>
      <p v-if="error" class="err">{{ error }}</p>
    </div>

    <div class="card">
      <h2>Inventory</h2>
      <table>
        <thead>
          <tr><th>asset</th><th>kind</th><th>tier</th><th>components</th><th>last inventoried</th></tr>
        </thead>
        <tbody>
          <tr v-for="a in data?.assets ?? []" :key="a.id">
            <td><NuxtLink :to="`/assets/${a.id}`">{{ a.display_name }}</NuxtLink></td>
            <td class="muted">{{ a.kind }}</td>
            <td>
              <span v-if="a.tier === 'unknown'" class="muted" title="Unset tier deflates risk scoring">tier unset</span>
              <span v-else>{{ a.tier }}</span>
            </td>
            <td>
              <!-- Never show 0 for an asset we have not inventoried: that reads as
                   "no dependencies" when it means "we have not looked". -->
              <span v-if="a.never_inventoried" class="muted">unknown</span>
              <span v-else>{{ a.component_count }}</span>
            </td>
            <td>
              <FreshnessIndicator
                :at="a.last_inventoried_at"
                :never-inventoried="a.never_inventoried"
                :stale="a.stale"
              />
            </td>
          </tr>
          <tr v-if="!pending && !(data?.assets ?? []).length">
            <td colspan="5" class="muted">No assets yet. Connect a repository above.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.row { display: flex; gap: .6rem; align-items: center; }
.row input { flex: 1; }
select { padding: .6rem .5rem; font: inherit; background: var(--plane); color: var(--ink);
         border: 1px solid var(--rule); border-radius: 7px; }
</style>
