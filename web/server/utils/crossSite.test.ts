import assert from 'node:assert/strict'
import { test } from 'node:test'
import { REQUESTED_BY_VALUE, crossSiteRefusal, expectedOrigin } from './crossSite.ts'

const DASHBOARD = 'https://athena.example.com'

const mutation = (overrides: Record<string, string | undefined> = {}) => ({
  method: 'POST',
  origin: DASHBOARD,
  requestedBy: REQUESTED_BY_VALUE,
  expectedOrigin: DASHBOARD,
  ...overrides,
})

test('a same-origin mutation is allowed', () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    assert.equal(crossSiteRefusal(mutation({ method })), null, method)
  }
})

test('a cross-origin mutation is refused', () => {
  assert.equal(crossSiteRefusal(mutation({ origin: 'https://evil.example.net' })), 'csrf_origin_mismatch')
})

test('a missing Origin falls back to a matching Referer', () => {
  const check = mutation({ origin: undefined, referer: `${DASHBOARD}/athena/findings?x=1` })
  assert.equal(crossSiteRefusal(check), null)
})

test('a missing Origin with a foreign Referer is refused', () => {
  const check = mutation({ origin: undefined, referer: 'https://evil.example.net/athena.example.com' })
  assert.equal(crossSiteRefusal(check), 'csrf_origin_mismatch')
})

test('a mismatched Origin is not rescued by a matching Referer', () => {
  const check = mutation({ origin: 'https://evil.example.net', referer: `${DASHBOARD}/` })
  assert.equal(crossSiteRefusal(check), 'csrf_origin_mismatch')
})

test('a mutation with neither Origin nor Referer is refused', () => {
  assert.equal(crossSiteRefusal(mutation({ origin: undefined, referer: undefined })), 'csrf_source_missing')
  assert.equal(crossSiteRefusal(mutation({ origin: '', referer: '' })), 'csrf_source_missing')
})

test('an opaque null Origin is refused', () => {
  assert.equal(crossSiteRefusal(mutation({ origin: 'null' })), 'csrf_origin_mismatch')
})

test('a same-origin mutation without the custom header is refused', () => {
  assert.equal(crossSiteRefusal(mutation({ requestedBy: undefined })), 'csrf_header_missing')
  assert.equal(crossSiteRefusal(mutation({ requestedBy: 'someone-else' })), 'csrf_header_missing')
})

test('safe methods pass with no Origin, Referer or custom header', () => {
  for (const method of ['GET', 'HEAD', 'OPTIONS', 'get']) {
    const check = { method, expectedOrigin: DASHBOARD }
    assert.equal(crossSiteRefusal(check), null, method)
    assert.equal(crossSiteRefusal({ ...check, origin: 'https://evil.example.net' }), null, method)
  }
})

test('the event stream is a safe request and is never checked', () => {
  assert.equal(crossSiteRefusal({ method: 'GET', expectedOrigin: DASHBOARD }), null)
})

test('lookalike origins are refused', () => {
  for (const origin of [
    'http://athena.example.com',
    'https://athena.example.com:8443',
    'https://athena.example.com.evil.example.net',
    'https://evil-athena.example.com',
    'https://sub.athena.example.com',
  ]) {
    assert.equal(crossSiteRefusal(mutation({ origin })), 'csrf_origin_mismatch', origin)
  }
})

test('an explicit default port still matches', () => {
  assert.equal(crossSiteRefusal(mutation({ origin: 'https://athena.example.com:443' })), null)
})

test('a non-default port must match exactly', () => {
  const check = mutation({ origin: 'http://127.0.0.1:8080', expectedOrigin: 'http://127.0.0.1:8080' })
  assert.equal(crossSiteRefusal(check), null)
  assert.equal(crossSiteRefusal({ ...check, origin: 'http://127.0.0.1:3000' }), 'csrf_origin_mismatch')
})

test('a configured origin wins over the request host', () => {
  assert.equal(expectedOrigin(DASHBOARD, 'http://web:3000'), DASHBOARD)
  assert.equal(expectedOrigin('', 'http://web:3000'), 'http://web:3000')
})

test('an unparseable configured origin refuses every mutation', () => {
  const check = mutation({ expectedOrigin: expectedOrigin('not a url', DASHBOARD) })
  assert.equal(crossSiteRefusal(check), 'csrf_origin_mismatch')
})
