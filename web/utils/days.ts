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
