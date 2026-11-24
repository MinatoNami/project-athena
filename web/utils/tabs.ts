/**
 * Arrow keys across a tablist — the WAI-ARIA tabs pattern, with automatic
 * activation. Only the selected tab sits in the Tab order (`tabindex` 0, the rest
 * -1), so the arrows are how the others are reached; without this handler a
 * keyboard user could select only the first tab.
 */
export function tabKeydown(
  e: KeyboardEvent,
  ids: readonly string[],
  current: string,
  select: (id: string) => void,
) {
  const i = ids.indexOf(current)
  const next = e.key === 'ArrowRight' ? (i + 1) % ids.length
    : e.key === 'ArrowLeft' ? (i - 1 + ids.length) % ids.length
      : e.key === 'Home' ? 0
        : e.key === 'End' ? ids.length - 1
          : -1
  if (next < 0) return
  e.preventDefault()
  select(ids[next]!)
  const list = (e.currentTarget as HTMLElement | null)?.closest('[role="tablist"]')
  list?.querySelectorAll<HTMLElement>('[role="tab"]')[next]?.focus()
}
