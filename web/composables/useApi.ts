export interface Me {
  id: string
  email: string
  role: string
  mfa_enabled: boolean
  step_up_fresh: boolean
}

/**
 * Absolute path to a BFF route, honouring the app's base path.
 *
 * Athena is served under a prefix by the gateway on alena-server (/athena/),
 * and at the root in local development. Nuxt rewrites the router and the asset
 * URLs from NUXT_APP_BASE_URL on its own, but a hand-written path like
 * `/api/...` is invisible to it — so every caller goes through here instead.
 */
export function apiUrl(path: string): string {
  const base = useRuntimeConfig().app.baseURL || '/'
  return `${base.endsWith('/') ? base : base + '/'}api/${path}`
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
