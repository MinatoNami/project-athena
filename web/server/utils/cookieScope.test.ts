/**
 * Cookie re-scoping.
 *
 * Run with: node --test server/utils/
 *
 * The property under test is that a session token stops being sent to whatever else
 * shares the origin, and that nothing about logging in or out breaks on the way —
 * a scoping fix that quietly broke logout would be worse than the leak.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { cookieMount, scopeCookie } from './cookieScope.ts'

const SESSION = 'athena_session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200'

test('the mount loses its trailing slash', () => {
  // RFC 6265: cookie-path `/athena/` does not match a request for exactly `/athena`.
  assert.equal(cookieMount('/athena/'), '/athena')
  assert.equal(cookieMount('/athena'), '/athena')
  assert.equal(cookieMount('/'), '/')
  assert.equal(cookieMount(''), '/')
})

test('a root-scoped cookie is confined to the mount', () => {
  const out = scopeCookie(SESSION, '/athena')
  assert.match(out, /Path=\/athena(;|$)/)
  assert.doesNotMatch(out, /Path=\/(;|$)/)
})

test('everything else about the cookie survives', () => {
  const out = scopeCookie(SESSION, '/athena')
  for (const attr of ['athena_session=abc123', 'HttpOnly', 'Secure', 'SameSite=Lax', 'Max-Age=43200']) {
    assert.ok(out.includes(attr), `${attr} was lost`)
  }
})

test('mounting at the root changes nothing', () => {
  assert.equal(scopeCookie(SESSION, '/'), SESSION)
})

test('a deletion still clears the cookie it set', () => {
  // Logout sends Max-Age=0 with the same path. If the paths disagree the browser
  // keeps the original and the user stays signed in after clicking sign out.
  const set = scopeCookie(SESSION, '/athena')
  const clear = scopeCookie('athena_session=; Path=/; Max-Age=0', '/athena')
  const pathOf = (c: string) => c.split(';').map(s => s.trim()).find(s => s.toLowerCase().startsWith('path='))
  assert.equal(pathOf(set), pathOf(clear))
})

test('a deliberately narrow path is not widened', () => {
  // Core does not do this today, but prefixing rather than replacing means a
  // narrower scope stays narrower instead of being handed the whole app.
  assert.match(scopeCookie('x=1; Path=/auth', '/athena'), /Path=\/athena\/auth/)
})

test('a cookie with no path gets the mount, not the request directory', () => {
  // Without this the browser defaults to the directory of /athena/api/auth/login,
  // scoping the session to /athena/api — too narrow for the pages that need it.
  assert.match(scopeCookie('x=1; HttpOnly', '/athena'), /Path=\/athena$/)
})

test('the path attribute is matched however it is cased or spaced', () => {
  assert.match(scopeCookie('x=1; path=/', '/athena'), /Path=\/athena/)
  assert.match(scopeCookie('x=1;PATH=/', '/athena'), /Path=\/athena/)
})
