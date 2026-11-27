export const CODE_FINDING_KINDS = ['secret', 'misconfiguration', 'startup-hook'] as const
export type CodeFindingKind = (typeof CODE_FINDING_KINDS)[number]
export type CodeFindingFilter = 'all' | CodeFindingKind

interface CodeKindLabels {
  tag: string
  filter: string
  tile: string
  scanned: string
}

export const CODE_KIND_LABELS: Record<CodeFindingKind, CodeKindLabels> = {
  'secret': { tag: 'secret', filter: 'Secrets', tile: 'Secrets', scanned: 'secrets' },
  'misconfiguration': {
    tag: 'config', filter: 'Config', tile: 'Misconfigurations', scanned: 'configuration',
  },
  'startup-hook': {
    tag: 'start-up hook', filter: 'Start-up hooks', tile: 'Start-up hooks', scanned: 'start-up hook',
  },
}

export function isCodeFindingKind(value: unknown): value is CodeFindingKind {
  return CODE_FINDING_KINDS.includes(value as CodeFindingKind)
}

export function codeFindingFilter(value: unknown): CodeFindingFilter {
  return isCodeFindingKind(value) ? value : 'all'
}

export function codeKindTag(kind: string): string {
  return isCodeFindingKind(kind) ? CODE_KIND_LABELS[kind].tag : kind
}
