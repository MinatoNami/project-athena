export interface ScanOutcome {
  state: 'covered' | 'partial' | 'unknown'
  headline: string
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

export const CODE_SCAN_KINDS = ['secret', 'misconfiguration']

export function scanOutcome(run: {
  status: string
  kind?: string
  error?: string | null
  stats?: { components?: number; warnings?: number; findings?: number; files_checked?: number } | null
}): ScanOutcome {
  const components = run.stats?.components

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
