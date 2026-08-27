/**
 * BFF proxy.
 *
 * Every browser call to the API goes through here. Athena Core is never reachable
 * from the browser, which is the whole reason this application is server-rendered
 * rather than a static SPA (docs/WEB_UI.md §1).
 */
export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig()
  const path = getRouterParam(event, 'path') || ''
  const target = `${config.athenaApiUrl}/api/v1/${path}${getRequestURL(event).search}`
  const method = event.method

  const cookie = getHeader(event, 'cookie')
  const body =
    method === 'GET' || method === 'HEAD'
      ? undefined
      : await readRawBody(event).catch(() => undefined)

  const response = await fetch(target, {
    method,
    headers: {
      'content-type': getHeader(event, 'content-type') || 'application/json',
      ...(cookie ? { cookie } : {}),
    },
    body,
    redirect: 'manual',
  })

  // Forward Set-Cookie, re-scoped to wherever this app is mounted. See
  // server/utils/cookieScope.ts for why this is not left to core.
  const mount = cookieMount(config.app.baseURL)
  for (const c of response.headers.getSetCookie?.() ?? []) {
    appendHeader(event, 'set-cookie', scopeCookie(c, mount))
  }

  setResponseStatus(event, response.status)
  const contentType = response.headers.get('content-type') || 'application/json'
  setHeader(event, 'content-type', contentType)

  if (contentType.includes('text/event-stream')) {
    return sendStream(event, response.body as unknown as ReadableStream)
  }
  return response.text()
})
