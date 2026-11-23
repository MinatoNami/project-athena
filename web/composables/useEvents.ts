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
 *
 * Sharing it has a cost the per-page streams did not: the shell holds it for the
 * life of the tab, so it is never reopened by navigating. EventSource retries a
 * dropped connection by itself, but gives up for good when an answer is not a 200
 * event stream — which is exactly what the proxy returns while core restarts. So a
 * closed stream is rebuilt here, with backoff, and every listener is re-attached
 * from the registry rather than from the dead source.
 */

// Every topic any page listens for. Filtering happens in each listener, so a new
// topic is added here once rather than reopening the connection per caller.
const TOPICS = ['findings', 'jobs', 'assets']

let source: EventSource | null = null
let users = 0
let streamUrl = ''
let retryTimer: ReturnType<typeof setTimeout> | null = null
let retryDelay = 1000
const listeners = new Map<string, Set<() => void>>()
const connected = ref(true)

function dispatch(topic: string) {
  return () => {
    for (const handler of listeners.get(topic) ?? []) handler()
  }
}

function open() {
  const es = new EventSource(streamUrl)
  es.onopen = () => {
    connected.value = true
    retryDelay = 1000
  }
  // While the browser retries by itself the flag says so (§4: a dashboard that
  // looks live while being stale is dangerous). Once it has given up, nothing will
  // reconnect unless this does.
  es.onerror = () => {
    connected.value = false
    if (es.readyState === EventSource.CLOSED && source === es) {
      source = null
      if (users > 0 && !retryTimer) {
        retryTimer = setTimeout(() => {
          retryTimer = null
          if (users > 0 && !source) open()
        }, retryDelay)
        retryDelay = Math.min(retryDelay * 2, 30_000)
      }
    }
  }
  for (const topic of TOPICS) es.addEventListener(topic, dispatch(topic))
  source = es
}

function acquire(url: string) {
  streamUrl = url
  users += 1
  if (!source && !retryTimer) open()
}

function release() {
  users -= 1
  if (users > 0) return
  users = 0
  if (retryTimer) {
    clearTimeout(retryTimer)
    retryTimer = null
  }
  source?.close()
  source = null
}

export function useEvents(topics: string[], onEvent: () => void) {
  if (import.meta.server) return

  // Resolved in setup scope: useRuntimeConfig(), which apiUrl() reads, wants the
  // Nuxt context and onMounted's callback does not reliably carry it.
  const url = apiUrl(`events?topics=${TOPICS.join(',')}`)

  onMounted(() => {
    // A wrapper per caller, so the same function registered twice is still two
    // registrations and removing one leaves the other.
    const handler = () => onEvent()
    for (const topic of topics) {
      if (!listeners.has(topic)) listeners.set(topic, new Set())
      listeners.get(topic)!.add(handler)
    }
    acquire(url)
    onBeforeUnmount(() => {
      for (const topic of topics) listeners.get(topic)?.delete(handler)
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
