/**
 * SSE subscription.
 *
 * Events carry identity only, so the handler refetches through the normal API and
 * authorisation is re-checked on the read path.
 */
export function useEvents(topics: string[], onEvent: () => void) {
  if (import.meta.server) return

  onMounted(() => {
    const source = new EventSource(`/api/events?topics=${topics.join(',')}`)
    for (const topic of topics) source.addEventListener(topic, () => onEvent())
    onBeforeUnmount(() => source.close())
  })
}
