export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig()
  const method = event.method

  const refusal = crossSiteRefusal({
    method,
    origin: getHeader(event, 'origin'),
    referer: getHeader(event, 'referer'),
    requestedBy: getHeader(event, REQUESTED_BY_HEADER),
    expectedOrigin: expectedOrigin(config.dashboardOrigin, getRequestURL(event).origin),
  })
  if (refusal) {
    setResponseStatus(event, 403)
    return { detail: refusal }
  }

  const path = getRouterParam(event, 'path') || ''
  const target = `${config.athenaApiUrl}/api/v1/${path}${getRequestURL(event).search}`

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
