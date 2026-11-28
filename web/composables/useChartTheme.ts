const TOKENS = {
  ink: '--ink',
  ink2: '--ink-2',
  muted: '--ink-muted',
  rule: '--rule',
  surface: '--surface',
  plane: '--plane',
  good: '--good',
  warn: '--warn',
  warnInk: '--warn-ink',
  crit: '--crit',
  critical: '--sev-critical',
  high: '--sev-high',
  medium: '--sev-medium',
  low: '--sev-low',
  informational: '--sev-informational',
} as const

export type ChartTheme = Record<keyof typeof TOKENS, string>

const FALLBACK: ChartTheme = {
  ink: '#0b0b0b', ink2: '#52514e', muted: '#6f6d68', rule: '#e1e0d9',
  surface: '#fcfcfb', plane: '#f9f9f7', good: '#0ca30c', warn: '#fab219',
  warnInk: '#8a5a00', crit: '#66201f', critical: '#66201f', high: '#8e2f2c',
  medium: '#b54840', low: '#d1685f', informational: '#e5948c',
}

function read(): ChartTheme {
  if (!import.meta.client) return FALLBACK
  const style = getComputedStyle(document.documentElement)
  const out = {} as ChartTheme
  for (const [key, prop] of Object.entries(TOKENS)) {
    out[key as keyof ChartTheme] = style.getPropertyValue(prop).trim() || FALLBACK[key as keyof ChartTheme]
  }
  return out
}

export function useChartTheme() {
  const theme = ref<ChartTheme>(FALLBACK)
  const reducedMotion = ref(false)

  onMounted(() => {
    theme.value = read()
    const dark = window.matchMedia('(prefers-color-scheme: dark)')
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)')
    reducedMotion.value = motion.matches

    const onTheme = () => { theme.value = read() }
    const onMotion = () => { reducedMotion.value = motion.matches }
    dark.addEventListener('change', onTheme)
    motion.addEventListener('change', onMotion)
    onScopeDispose(() => {
      dark.removeEventListener('change', onTheme)
      motion.removeEventListener('change', onMotion)
    })
  })

  const chrome = computed(() => ({
    animation: !reducedMotion.value,
    textStyle: { fontFamily: 'system-ui, -apple-system, sans-serif' },
    tooltip: {
      backgroundColor: theme.value.surface,
      borderColor: theme.value.rule,
      borderWidth: 1,
      padding: [6, 9],
      textStyle: { color: theme.value.ink, fontSize: 12 },
      extraCssText: 'box-shadow: 0 2px 10px rgba(0,0,0,.09); border-radius: 7px;',
    },
  }))

  const severity = computed((): Record<string, string> => ({
    critical: theme.value.critical,
    high: theme.value.high,
    medium: theme.value.medium,
    low: theme.value.low,
    informational: theme.value.informational,
  }))

  return { theme, chrome, severity, reducedMotion }
}
