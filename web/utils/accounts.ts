export const ROLES = ['viewer', 'operator', 'approver', 'auditor', 'admin'] as const

export type Role = (typeof ROLES)[number]

const ROLE_LABELS: Record<Role, string> = {
  viewer: 'Viewer',
  operator: 'Operator',
  approver: 'Approver',
  auditor: 'Auditor',
  admin: 'Admin',
}

const ROLE_HINTS: Record<Role, string> = {
  viewer: 'Reads everything, changes nothing.',
  operator: 'Runs scans and handles findings.',
  approver: 'Approves remediation.',
  auditor: 'Reads the audit trail.',
  admin: 'Manages users and settings.',
}

export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value)
}

export function roleLabel(role: unknown): string {
  return isRole(role) ? ROLE_LABELS[role] : `Unknown (${String(role ?? '')})`
}

export function roleHint(role: unknown): string {
  return isRole(role) ? ROLE_HINTS[role] : 'Not a role this console knows.'
}

export function showsAdminNav(me: { role?: unknown } | null | undefined): boolean {
  return me?.role === 'admin'
}

const STEP_UP_DETAILS = new Set(['step_up_required', 'Fresh step-up required'])

export function isStepUpRequired(e: any): boolean {
  return e?.statusCode === 403 && STEP_UP_DETAILS.has(e?.data?.detail)
}

export function errorDetail(e: any, fallback: string): string {
  const detail = e?.data?.detail
  return typeof detail === 'string' && detail ? detail : fallback
}

export function totpSecretFromUri(uri: string): string | null {
  try {
    const secret = new URL(uri).searchParams.get('secret')
    return secret || null
  } catch {
    return null
  }
}
