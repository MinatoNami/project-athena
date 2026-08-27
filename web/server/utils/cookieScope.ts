/**
 * Re-scoping cookies to the path this app is mounted at.
 *
 * Core sets `Path=/` because it has no idea it is behind a path prefix. Left alone
 * on a host where several apps share one origin, the browser sends Athena's session
 * token to every neighbour on that origin, and theirs to Athena. The cookie is
 * httpOnly so no script reads it, but each app's server receives it, and a session
 * token is not something to hand to software that has no use for it.
 *
 * Separate ports were never protection here: cookies are scoped by host, not port.
 */

/**
 * The path to scope cookies to, derived from the mount point.
 *
 * The trailing slash is dropped deliberately. Per RFC 6265 §5.1.4 a cookie-path of
 * `/athena/` does not match a request for exactly `/athena`, while `/athena` matches
 * both that and everything beneath it.
 */
export function cookieMount(baseURL: string): string {
  return (baseURL || '/').replace(/\/+$/, '') || '/'
}

/**
 * Re-scope one Set-Cookie header to the mount point.
 *
 * The existing path is prefixed rather than replaced, so a cookie scoped narrowly on
 * purpose stays narrow instead of being widened to the whole app. A cookie with no
 * Path at all gets one: the browser would otherwise default to the requesting
 * directory, which for a login at /athena/api/auth/login is `/athena/api` — narrow
 * enough that the session would not be sent to the pages that need it.
 */
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
