/**
 * SSE subscription — one connection per tab, shared by everything that listens.
 *
 * Events carry identity only, so the handler refetches through the normal API and
 * authorisation is re-checked on the read path.
 *
 * Each caller used to open its own EventSource. The asset page alone held four (the
 * shell's status dot, the page, the code-findings panel, the notification bell),
 * and browsers allow six HTTP/1.1 connections per host — so two open tabs exhausted
 * the pool and every further request, page loads included, hung behind a stream
 * that never ends. One connection subscribed to every topic, with listeners
 * reference-counted on top, costs the server a little more filtering and the
 * browser one socket.
 */

// Every topic any page listens for. Filtering happens in each listener, so a new
// topic is added here once rather than reopening the connection per caller.
const TOPICS = ['findings', 'jobs', 'assets']

let source: EventSource | null = null
let users = 0
const connected = ref(true)

function acquire(url: string): EventSource {
  if (!source) {
    source = new EventSource(url)
    source.onopen = () => (connected.value = true)
    // EventSource reconnects on its own; the flag says so in the meantime (§4:
    // a dashboard that looks live while being stale is dangerous).
    source.onerror = () => (connected.value = false)
  }
  users += 1
  return source
}

function release() {
  users -= 1
  if (users <= 0 && source) {
    source.close()
    source = null
    users = 0
  }
}

export function useEvents(topics: string[], onEvent: () => void) {
  if (import.meta.server) return

  // Resolved in setup scope: useRuntimeConfig(), which apiUrl() reads, wants the
  // Nuxt context and onMounted's callback does not reliably carry it.
  const url = apiUrl(`events?topics=${TOPICS.join(',')}`)

  onMounted(() => {
    const es = acquire(url)
    const handler = () => onEvent()
    for (const topic of topics) es.addEventListener(topic, handler)
    onBeforeUnmount(() => {
      for (const topic of topics) es.removeEventListener(topic, handler)
      release()
    })
  })
}

/** Whether the shared stream is currently connected, for the shell's status line. */
export function useEventStatus() {
  if (import.meta.server) return readonly(connected)
  const url = apiUrl(`events?topics=${TOPICS.join(',')}`)
  onMounted(() => {
    acquire(url)
    onBeforeUnmount(release)
  })
  return readonly(connected)
}
