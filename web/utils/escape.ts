/** Text made safe to place inside HTML that something else will parse. */
export function escapeHtml(text: unknown): string {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/**
 * One CSV cell. Quoted when it must be, and a cell a spreadsheet would read as a
 * formula (`=`, `+`, `-`, `@`, tab, carriage return) is prefixed with `'` — asset
 * and package names reach these files and are not Athena's to vouch for.
 */
export function csvCell(value: string | number): string {
  let s = String(value)
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/**
 * Release an object URL after the download it started has been handed off.
 * Revoking it in the same tick cancels the download in Safari.
 */
export function revokeLater(url: string) {
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
