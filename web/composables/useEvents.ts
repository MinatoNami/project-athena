const TOPICS = ['findings', 'jobs', 'assets']

let source: EventSource | null = null
let users = 0
let streamUrl = ''
let retryTimer: ReturnType<typeof setTimeout> | null = null
let retryDelay = 1000
let interrupted = false
const listeners = new Map<string, Set<() => void>>()
const connected = ref(true)

function dispatch(topic: string) {
  return () => {
    for (const handler of listeners.get(topic) ?? []) handler()
  }
}

function refreshAll() {
  const handlers = new Set<() => void>()
  for (const set of listeners.values()) for (const handler of set) handlers.add(handler)
  for (const handler of handlers) handler()
}

function open() {
  const es = new EventSource(streamUrl)
  es.onopen = () => {
    connected.value = true
    retryDelay = 1000
    if (interrupted) {
      interrupted = false
      refreshAll()
    }
  }
  es.onerror = () => {
    connected.value = false
    interrupted = true
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
  interrupted = false
  if (retryTimer) {
    clearTimeout(retryTimer)
    retryTimer = null
  }
  source?.close()
  source = null
}

export function useEvents(topics: string[], onEvent: () => void) {
  if (import.meta.server) return

  const url = apiUrl(`events?topics=${TOPICS.join(',')}`)

  onMounted(() => {
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

export function useEventStatus() {
  if (import.meta.server) return readonly(connected)
  const url = apiUrl(`events?topics=${TOPICS.join(',')}`)
  onMounted(() => {
    acquire(url)
    onBeforeUnmount(release)
  })
  return readonly(connected)
}
