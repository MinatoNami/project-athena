export function cookieMount(baseURL: string): string {
  return (baseURL || '/').replace(/\/+$/, '') || '/'
}

export function scopeCookie(header: string, mount: string): string {
  if (mount === '/') return header

  let seen = false
  const rewritten = header.split(';').map(part => {
    const eq = part.indexOf('=')
    const name = (eq === -1 ? part : part.slice(0, eq)).trim().toLowerCase()
    if (name !== 'path') return part
    seen = true
    const original = (eq === -1 ? '' : part.slice(eq + 1)).trim() || '/'
    return ` Path=${original === '/' ? mount : mount + original}`
  })
  return seen ? rewritten.join(';') : `${header}; Path=${mount}`
}
