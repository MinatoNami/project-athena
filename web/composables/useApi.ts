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
  const headers: Record<string, string> = { ...(opts.headers || {}), 'x-requested-by': 'athena-web' }

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

export const STEP_UP_REQUIRED = 'step_up_required'

export function needsStepUp(e: any): boolean {
  return e?.statusCode === 403 && e?.data?.detail === STEP_UP_REQUIRED
}

export async function stepUp(password: string, totpCode?: string): Promise<void> {
  const me = useNuxtData<Me | null>('me').data.value
  await api('auth/step-up', {
    method: 'POST',
    body: { email: me?.email ?? '', password, totp_code: totpCode || null },
  })
}
