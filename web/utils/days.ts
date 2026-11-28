export function daysUntil(isoDate: string): number {
  const today = Date.parse(new Date().toISOString().slice(0, 10))
  return Math.round((Date.parse(String(isoDate).slice(0, 10)) - today) / 86400000)
}

export function dueText(isoDate: string | null | undefined): string | null {
  if (!isoDate) return null
  const days = daysUntil(isoDate)
  if (days < 0) return `overdue ${-days}d`
  if (days === 0) return 'due today'
  return `due in ${days}d`
}

export function utcStamp(at: string | Date): string {
  return `${new Date(at).toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

export function ordinal(n: number): string {
  const tens = n % 100
  const suffix = tens >= 11 && tens <= 13 ? 'th'
    : n % 10 === 1 ? 'st' : n % 10 === 2 ? 'nd' : n % 10 === 3 ? 'rd' : 'th'
  return `${n}${suffix}`
}

export function plural(n: number | null | undefined, one: string, many = `${one}s`): string {
  const v = n ?? 0
  return `${v.toLocaleString()} ${v === 1 ? one : many}`
}
