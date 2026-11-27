import assert from 'node:assert/strict'
import { test } from 'node:test'
import { deadlineBasis } from '../../utils/deadlineBasis.ts'

test('a KEV feed date that sets the deadline says so and shows what it overrode', () => {
  const basis = deadlineBasis({
    due: '2026-12-01', due_rule: 'kev_due_date', computed_due: '2026-12-20',
    kev_due_date: '2026-12-01', days: 14,
  })
  assert.ok(basis)
  assert.equal(basis.setByKev, true)
  assert.equal(basis.label, 'Due date set by CISA KEV')
  assert.match(basis.overridden ?? '', /2026-12-20/)
  assert.match(basis.overridden ?? '', /14 days/)
})

test('a KEV date that replaces a fix-on-upgrade deadline says the table gave none', () => {
  const basis = deadlineBasis({
    due: '2026-12-01', due_rule: 'kev_due_date', computed_due: null,
    kev_due_date: '2026-12-01', days: null,
  })
  assert.equal(basis?.setByKev, true)
  assert.match(basis?.overridden ?? '', /no calendar deadline/)
})

test('the table rule names the table and overrides nothing', () => {
  const basis = deadlineBasis({ due: '2026-12-20', due_rule: 'bod_table', computed_due: '2026-12-20' })
  assert.equal(basis?.setByKev, false)
  assert.equal(basis?.label, 'Due date set by the BOD 26-04 table')
  assert.equal(basis?.overridden, null)
})

test('no rule, as for a malicious package, gives no basis', () => {
  assert.equal(deadlineBasis(null), null)
  assert.equal(deadlineBasis({ due: null, due_rule: null }), null)
})
