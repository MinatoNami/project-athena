import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  canOperateInvestigations,
  haltAttribution,
  investigationActions,
  investigationHoldStatus,
  isHaltReasonValid,
  parseHaltState,
} from '../../utils/control.ts'

test('only operators and admins may pause, unpause or cancel an investigation', () => {
  assert.equal(canOperateInvestigations({ role: 'operator' }), true)
  assert.equal(canOperateInvestigations({ role: 'admin' }), true)
  for (const role of ['viewer', 'approver', 'auditor', 'owner', undefined]) {
    assert.equal(canOperateInvestigations({ role }), false)
  }
  assert.equal(canOperateInvestigations(null), false)
})

test('a halted state is read with its reason, actor and time', () => {
  assert.deepEqual(
    parseHaltState({ halted: true, reason: 'bad scan', set_by: 'user:a@b', set_at: '2026-11-27T16:40:00+00:00' }),
    { halted: true, reason: 'bad scan', setBy: 'user:a@b', setAt: '2026-11-27T16:40:00+00:00' },
  )
})

test('a running state carries no reason', () => {
  assert.deepEqual(
    parseHaltState({ halted: false, reason: null, set_by: 'user:a@b', set_at: null }),
    { halted: false, reason: null, setBy: 'user:a@b', setAt: null },
  )
})

test('a response without a boolean halted flag is unknown, never running', () => {
  assert.equal(parseHaltState(null), null)
  assert.equal(parseHaltState('halted'), null)
  assert.equal(parseHaltState({ halted: 'false' }), null)
  assert.equal(parseHaltState({}), null)
})

test('a halt reason must have four to two thousand characters after trimming', () => {
  assert.equal(isHaltReasonValid('   '), false)
  assert.equal(isHaltReasonValid(' abc '), false)
  assert.equal(isHaltReasonValid('abcd'), true)
  assert.equal(isHaltReasonValid('x'.repeat(2000)), true)
  assert.equal(isHaltReasonValid('x'.repeat(2001)), false)
})

test('the attribution names the actor and the UTC minute', () => {
  const state = { halted: true, reason: 'r', setBy: 'user:a@b', setAt: '2026-11-27T16:40:59+00:00' }
  assert.equal(haltAttribution(state), 'Set by user:a@b at 2026-11-27 16:40 UTC')
})

test('the attribution survives a missing actor or an unreadable time', () => {
  assert.equal(haltAttribution({ halted: true, reason: null, setBy: null, setAt: null }), 'Set by an unknown actor')
  assert.equal(
    haltAttribution({ halted: true, reason: null, setBy: 'x', setAt: 'yesterday' }),
    'Set by x at yesterday',
  )
})

test('a held investigation offers unpause and cancel, never pause', () => {
  assert.deepEqual(investigationActions(true), ['unpause', 'cancel'])
  assert.equal(investigationHoldStatus(true), 'Investigation is paused.')
})

test('an investigation that is not held offers pause and cancel, never unpause', () => {
  assert.deepEqual(investigationActions(false), ['pause', 'cancel'])
  assert.equal(investigationHoldStatus(false), 'Investigation is not paused.')
})
