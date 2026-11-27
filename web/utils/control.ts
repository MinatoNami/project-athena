export interface HaltState {
  halted: boolean
  reason: string | null
  setBy: string | null
  setAt: string | null
}

export const HALT_REASON_MIN = 4
export const HALT_REASON_MAX = 2000

function optionalText(value: unknown): string | null {
  return typeof value === 'string' && value ? value : null
}

export function parseHaltState(raw: unknown): HaltState | null {
  if (!raw || typeof raw !== 'object') return null
  const record = raw as Record<string, unknown>
  if (typeof record.halted !== 'boolean') return null
  return {
    halted: record.halted,
    reason: optionalText(record.reason),
    setBy: optionalText(record.set_by),
    setAt: optionalText(record.set_at),
  }
}

export function canOperateInvestigations(me: { role?: unknown } | null | undefined): boolean {
  return me?.role === 'operator' || me?.role === 'admin'
}

export function isHaltReasonValid(reason: string): boolean {
  const length = reason.trim().length
  return length >= HALT_REASON_MIN && length <= HALT_REASON_MAX
}

export function haltAttribution(state: HaltState): string {
  const who = state.setBy ?? 'an unknown actor'
  if (!state.setAt) return `Set by ${who}`
  const when = new Date(state.setAt)
  const stamp = Number.isNaN(when.getTime())
    ? state.setAt
    : `${when.toISOString().replace('T', ' ').slice(0, 16)} UTC`
  return `Set by ${who} at ${stamp}`
}
