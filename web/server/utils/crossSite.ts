export const REQUESTED_BY_HEADER = 'x-requested-by'
export const REQUESTED_BY_VALUE = 'athena-web'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export interface CrossSiteCheck {
  method: string
  origin?: string
  referer?: string
  requestedBy?: string
  expectedOrigin: string
}

export type CrossSiteRefusal = 'csrf_source_missing' | 'csrf_origin_mismatch' | 'csrf_header_missing'

function originOf(value: string): string | null {
  try {
    const origin = new URL(value).origin
    return origin === 'null' ? null : origin
  } catch {
    return null
  }
}

export function expectedOrigin(configured: string, requestOrigin: string): string {
  return configured.trim() || requestOrigin
}

export function crossSiteRefusal(check: CrossSiteCheck): CrossSiteRefusal | null {
  if (SAFE_METHODS.has(check.method.toUpperCase())) return null

  const source = check.origin || check.referer
  if (!source) return 'csrf_source_missing'

  const expected = originOf(check.expectedOrigin)
  if (!expected || originOf(source) !== expected) return 'csrf_origin_mismatch'

  if (check.requestedBy !== REQUESTED_BY_VALUE) return 'csrf_header_missing'
  return null
}
