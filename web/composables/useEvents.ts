/**
 * SSE subscription.
 *
 * Events carry identity only, so the handler refetches through the normal API and
 * authorisation is re-checked on the read path.
 */
export function useEvents(topics: string[], onEvent: () => void) {
  if (import.meta.server) return

  // Resolved in setup scope: useRuntimeConfig(), which apiUrl() reads, wants the
  // Nuxt context and onMounted's callback does not reliably carry it.
  const url = apiUrl(`events?topics=${topics.join(',')}`)

  onMounted(() => {
    const source = new EventSource(url)
    for (const topic of topics) source.addEventListener(topic, () => onEvent())
    onBeforeUnmount(() => source.close())
  })
}
