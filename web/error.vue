<script setup lang="ts">
/**
 * Application error page.
 *
 * Nuxt's default is an unbranded white page with a giant "404" and no way back into
 * the product. For a security tool that is worse than ugly: someone who lands here
 * cannot tell whether the page is missing or the whole service is down, and those
 * call for different reactions.
 */
import type { NuxtError } from '#app'

const props = defineProps<{ error: NuxtError }>()
const missing = computed(() => props.error?.statusCode === 404)
useHead({ title: () => (missing.value ? 'Not found' : 'Something went wrong') })
</script>

<template>
  <div class="errpage">
    <StateBlock
      :kind="missing ? 'empty' : 'error'"
      :title="missing ? 'That page does not exist' : 'Something went wrong'"
    >
      <template v-if="missing">
        The address <code>{{ $route.fullPath }}</code> is not part of Athena. Nothing is
        wrong with your data — this link simply goes nowhere.
      </template>
      <template v-else>
        Athena hit an error rendering this page. Your findings and audit trail are
        unaffected; this view could not be built.
        <span v-if="error?.statusCode" class="code">Status {{ error.statusCode }}</span>
      </template>
      <template #actions>
        <button class="btn primary" @click="clearError({ redirect: '/' })">
          Back to Today
        </button>
        <button v-if="!missing" class="btn" @click="clearError({ redirect: $route.fullPath })">
          Try again
        </button>
      </template>
    </StateBlock>
  </div>
</template>

<style scoped>
.errpage {
  min-height: 100vh; background: var(--plane); color: var(--ink);
  display: flex; align-items: center; justify-content: center; padding: 2rem;
}
.code { display: block; margin-top: .5rem; font-size: .74rem; color: var(--ink-muted); }
</style>
