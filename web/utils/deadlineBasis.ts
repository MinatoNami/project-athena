export interface DeadlineBasisInput {
  due?: string | null
  due_rule?: string | null
  computed_due?: string | null
  kev_due_date?: string | null
  days?: number | null
}

export interface DeadlineBasis {
  setByKev: boolean
  label: string
  overridden: string | null
}

export function deadlineBasis(d: DeadlineBasisInput | null | undefined): DeadlineBasis | null {
  if (!d || !d.due_rule) return null
  if (d.due_rule === 'kev_due_date') {
    return {
      setByKev: true,
      label: 'Due date set by CISA KEV',
      overridden: d.computed_due
        ? `The BOD 26-04 table alone would give ${d.computed_due}${d.days != null ? ` (${d.days} days)` : ''}; CISA's KEV date is earlier, so it applies.`
        : 'The BOD 26-04 table alone gives no calendar deadline (fix in the next upgrade); CISA\'s KEV date applies instead.',
    }
  }
  return {
    setByKev: false,
    label: 'Due date set by the BOD 26-04 table',
    overridden: null,
  }
}
