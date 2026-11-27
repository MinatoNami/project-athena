import assert from 'node:assert/strict'
import { test } from 'node:test'
import { CODE_FINDING_KINDS, CODE_KIND_LABELS, codeFindingFilter, codeKindTag } from '../../utils/codeKinds.ts'
import { CODE_SCAN_KINDS, scanOutcome } from '../../utils/scanOutcome.ts'

test('every code finding kind the API serves has a filter', () => {
  assert.deepEqual([...CODE_FINDING_KINDS], ['secret', 'misconfiguration', 'startup-hook'])
  for (const k of CODE_FINDING_KINDS) assert.ok(CODE_KIND_LABELS[k].filter)
})

test('a start-up hook is tagged as one, not as config', () => {
  assert.equal(codeKindTag('startup-hook'), 'start-up hook')
  assert.equal(codeKindTag('misconfiguration'), 'config')
  assert.equal(codeKindTag('secret'), 'secret')
  assert.equal(codeKindTag('something-new'), 'something-new')
})

test('the kind filter accepts only known kinds from the query string', () => {
  assert.equal(codeFindingFilter('startup-hook'), 'startup-hook')
  assert.equal(codeFindingFilter('secret'), 'secret')
  assert.equal(codeFindingFilter('all'), 'all')
  assert.equal(codeFindingFilter(undefined), 'all')
  assert.equal(codeFindingFilter(['secret']), 'all')
  assert.equal(codeFindingFilter('<script>'), 'all')
})

test('a start-up hook scan run is reported as a code scan, not a package read', () => {
  assert.deepEqual(CODE_SCAN_KINDS, [...CODE_FINDING_KINDS])
  const clean = scanOutcome({ status: 'succeeded', kind: 'startup-hook', stats: { findings: 0, pth_files: 3 } })
  assert.equal(clean.state, 'covered')
  assert.equal(clean.headline, 'Checked for start-up hooks across 3 .pth files: none found.')
  const hit = scanOutcome({ status: 'succeeded', kind: 'startup-hook', stats: { findings: 2 } })
  assert.equal(hit.headline, 'Checked for start-up hooks: 2 open.')
})

test('a partial start-up hook scan stays partial', () => {
  const out = scanOutcome({ status: 'partial', kind: 'startup-hook', error: '1 .pth file(s) not read', stats: {} })
  assert.equal(out.state, 'partial')
})
