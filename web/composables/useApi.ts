export interface Me {
  id: string
  email: string
  role: string
  mfa_enabled: boolean
  step_up_fresh: boolean
}

/** All calls go to the local BFF, never to core. */
export function api<T>(path: string, opts: Parameters<typeof $fetch>[1] = {}) {
  return $fetch<T>(`/api/${path}`, { ...opts, credentials: 'same-origin' })
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
