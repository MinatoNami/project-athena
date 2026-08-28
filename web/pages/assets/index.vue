<script setup lang="ts">
useHead({ title: 'Assets' })
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')

const { data, refresh, pending } = await useAsyncData('assets', () =>
  api<{ assets: any[]; coverage: any }>('assets'),
)

const url = ref('')
const tier = ref('unknown')
const builds = ref('')
const busy = ref(false)
const error = ref('')
const linked = ref<number | null>(null)

// Offered rather than typed. Matching is exact on the name the runtime reports, so
// the one thing that must not happen is somebody entering a plausible spelling that
// links nothing — and the names are already on this page.
const imageNames = computed(() => {
  const names = new Set<string>()
  for (const a of data.value?.assets ?? []) {
    if (a.kind !== 'image') continue
    let n = String(a.display_name)
    for (const sep of ['@', ':']) if (n.includes(sep)) n = n.slice(0, n.lastIndexOf(sep))
    if (n) names.add(n)
  }
  return [...names].sort()
})

async function addRepository() {
  error.value = ''
  linked.value = null
  busy.value = true
  try {
    const res = await api<{ images_linked: number }>('assets/repositories', {
      method: 'POST',
      body: {
        url: url.value,
        tier: tier.value,
        builds: builds.value.split(',').map(n => n.trim()).filter(Boolean),
      },
    })
    linked.value = builds.value.trim() ? res.images_linked : null
    url.value = ''
    builds.value = ''
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
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Assets</h1>
        <p>What Athena knows about, and how recently it looked.</p>
      </div>
      <div class="actions">
        <NuxtLink to="/assets/classify" class="btn primary">Classify</NuxtLink>
      </div>
    </div>

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

      <!-- Nothing in an image records the source that built it. Saying so here is the
           only way a finding on an image ever leads to the file that has to change. -->
      <div class="buildsrow">
        <input
          v-model="builds" list="known-images" class="grow"
          placeholder="images this repository builds, comma separated — optional"
        >
        <datalist id="known-images">
          <option v-for="n in imageNames" :key="n" :value="n" />
        </datalist>
      </div>
      <p class="hint">
        Name them the way Docker does. Findings on those images will then point at the
        manifest in this repository instead of stopping at the image.
      </p>

      <p v-if="error" class="err">{{ error }}</p>
      <p v-else-if="linked === 0" class="err">
        Registered, but none of those names match an image Athena has seen. Findings on
        them will still say the source is unknown until the names match.
      </p>
      <p v-else-if="linked" class="ok">
        Registered, and linked to {{ linked }} image{{ linked === 1 ? '' : 's' }}.
      </p>
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
.buildsrow { display: flex; gap: .5rem; margin-top: .5rem; }
.buildsrow .grow { flex-grow: 1; }
.hint { margin: .35rem 0 0; font-size: .74rem; line-height: 1.5; color: var(--ink-muted); }
.ok { margin: .5rem 0 0; font-size: .78rem; color: var(--ink-2); }
</style>
