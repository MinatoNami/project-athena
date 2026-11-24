/**
 * Whole calendar days from today (UTC) to an ISO date.
 *
 * Deadlines are dates, not instants. Subtracting `Date.now()` from a date's UTC
 * midnight made a deadline due today read as one day overdue for most of the day;
 * comparing date to date, in the same zone the server computes them in, does not.
 */
export function daysUntil(isoDate: string): number {
  const today = Date.parse(new Date().toISOString().slice(0, 10))
  return Math.round((Date.parse(String(isoDate).slice(0, 10)) - today) / 86400000)
}

/**
 * A deadline in one wording everywhere: "overdue 17d", "due today", "due in 5d".
 *
 * The same date used to read four ways across Today, the list, the case-file header
 * and the deadline card — and a reader comparing them could not tell whether they
 * were one deadline or several.
 */
export function dueText(isoDate: string | null | undefined): string | null {
  if (!isoDate) return null
  const days = daysUntil(isoDate)
  if (days < 0) return `overdue ${-days}d`
  if (days === 0) return 'due today'
  return `due in ${days}d`
}

/**
 * "2026-11-21 14:05 UTC". The same on the server and in the browser, so a title
 * rendered during SSR is not the server's local time passed off as the reader's.
 */
export function utcStamp(at: string | Date): string {
  return `${new Date(at).toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

/** 1st, 2nd, 3rd, 11th, 22nd, 93rd. */
export function ordinal(n: number): string {
  const tens = n % 100
  const suffix = tens >= 11 && tens <= 13 ? 'th'
    : n % 10 === 1 ? 'st' : n % 10 === 2 ? 'nd' : n % 10 === 3 ? 'rd' : 'th'
  return `${n}${suffix}`
}

/** "1 asset", "3 assets" — a count and the right form of its noun. */
export function plural(n: number | null | undefined, one: string, many = `${one}s`): string {
  const v = n ?? 0
  return `${v.toLocaleString()} ${v === 1 ? one : many}`
}
