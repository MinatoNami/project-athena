export interface Me {
  id: string
  email: string
  role: string
  mfa_enabled: boolean
  step_up_fresh: boolean
}

export function apiUrl(path: string): string {
  const base = useRuntimeConfig().app.baseURL || '/'
  return `${base.endsWith('/') ? base : base + '/'}api/${path}`
}

export function api<T>(path: string, opts: Record<string, any> = {}) {
  const headers: Record<string, string> = { ...(opts.headers || {}) }

  if (import.meta.server) {
    const incoming = useRequestHeaders(['cookie'])
    if (incoming.cookie) headers.cookie = incoming.cookie
  }

  return $fetch<T>(apiUrl(path), {
    ...opts,
    headers,
    credentials: 'same-origin',
  })
}

export function useMe() {
  return useAsyncData<Me | null>('me', async () => {
    try {
      return await api<Me>('auth/me')
    } catch {
      return null
    }
  })
}
