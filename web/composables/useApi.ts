export interface Me {
  id: string
  email: string
  role: string
  mfa_enabled: boolean
  step_up_fresh: boolean
}

/**
 * All calls go to the local BFF, never to core.
 *
 * On the server, the incoming request's cookie must be forwarded explicitly: a
 * server-side $fetch carries no browser cookie jar, so without this every
 * server-rendered page load looks unauthenticated and redirects to /login — even
 * for a signed-in user refreshing the page.
 */
export function api<T>(path: string, opts: Record<string, any> = {}) {
  const headers: Record<string, string> = { ...(opts.headers || {}) }

  if (import.meta.server) {
    const incoming = useRequestHeaders(['cookie'])
    if (incoming.cookie) headers.cookie = incoming.cookie
  }

  return $fetch<T>(`/api/${path}`, {
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
