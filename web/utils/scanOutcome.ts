/**
 * A scan run, in words a person can act on.
 *
 * The stored `error` is built for an engineer reading a database: a diagnosis
 * wrapped around 300 characters of the scanner's stderr. Showing it raw was the
 * worst of both — too much for a reader who wants to know whether the asset is
 * covered, too little for one who wants to debug the scanner. So the outcome is
 * translated, and the original is kept verbatim behind a disclosure rather than
 * thrown away.
 */

export interface ScanOutcome {
  /** One of: covered · partial · unknown — what this run established, not how it exited. */
  state: 'covered' | 'partial' | 'unknown'
  headline: string
  /** The scanner's own words, for the person who does want them. */
  detail: string | null
}

const CAUSES: [RegExp, string][] = [
  [/timeout|timed out/i, 'The scanner ran out of time and was stopped.'],
  [/out of memory|exit 137/i, 'The scanner ran out of memory inside its sandbox.'],
  [/exceeded the size limit/i, 'The scanner produced more output than the sandbox allows.'],
  [/no repository reference|neither a usable tag/i,
    'Athena cannot work out where to fetch this image from.'],
  [/no clone url/i, 'No clone URL is configured for this repository.'],
  [/valid json/i, 'The scanner returned something Athena could not read.'],
  [/sandbox/i, 'The scanner sandbox was not available.'],
  [/clone|checkout|authentication|permission denied/i, 'Athena could not check the source out.'],
]

/** Scan kinds that look at a repository's tree rather than inventory its packages. */
export const CODE_SCAN_KINDS = ['secret', 'misconfiguration']

export function scanOutcome(run: {
  status: string
  kind?: string
  error?: string | null
  stats?: { components?: number; warnings?: number; findings?: number; files_checked?: number } | null
}): ScanOutcome {
  const components = run.stats?.components

  // A secrets or misconfiguration scan says nothing about packages, so it is never
  // described as having "read" any.
  if (run.kind && CODE_SCAN_KINDS.includes(run.kind) && run.status === 'succeeded') {
    const n = run.stats?.findings ?? 0
    const what = run.kind === 'secret' ? 'secret' : 'misconfiguration'
    const scope = run.kind === 'secret'
      ? ' (working tree; history not searched)'
      : run.stats?.files_checked != null ? ` across ${run.stats.files_checked} config files` : ''
    return {
      state: 'covered',
      headline: `Checked for ${what}s${scope}: ${n ? `${n} open` : 'none found'}.`,
      detail: null,
    }
  }

  if (run.status === 'succeeded') {
    return {
      state: 'covered',
      headline: components != null
        ? `Read ${components.toLocaleString()} packages.`
        : 'Completed.',
      detail: null,
    }
  }

  if (run.status === 'partial') {
    const unresolved = run.stats?.warnings
    return {
      state: 'partial',
      headline: unresolved
        ? `Read ${(components ?? 0).toLocaleString()} packages; ${unresolved.toLocaleString()} could not be resolved.`
        : 'Read some of this asset, but not all of it.',
      detail: run.error || null,
    }
  }

  if (run.status === 'running') {
    return { state: 'partial', headline: 'Running now.', detail: null }
  }

  const cause = CAUSES.find(([pattern]) => pattern.test(run.error || ''))
  return {
    state: 'unknown',
    headline: cause ? cause[1] : 'The scan did not finish, so this asset is still unread.',
    detail: run.error || null,
  }
}
