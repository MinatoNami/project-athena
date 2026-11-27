import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  ROLES,
  errorDetail,
  isRole,
  isStepUpRequired,
  roleHint,
  roleLabel,
  showsAdminNav,
  stepUpReady,
  totpSecretFromUri,
} from '../../utils/accounts.ts'

test('the roles match the backend vocabulary', () => {
  assert.deepEqual([...ROLES], ['viewer', 'operator', 'approver', 'auditor', 'admin'])
})

test('every role has a label and a hint', () => {
  for (const role of ROLES) {
    assert.ok(isRole(role))
    assert.doesNotMatch(roleLabel(role), /Unknown/)
    assert.notEqual(roleHint(role), 'Not a role this console knows.')
  }
})

test('an unknown role is named as unknown, never as a known one', () => {
  assert.equal(isRole('owner'), false)
  assert.equal(isRole(undefined), false)
  assert.equal(roleLabel('owner'), 'Unknown (owner)')
  assert.equal(roleLabel(null), 'Unknown ()')
})

test('only admins see the admin navigation', () => {
  assert.equal(showsAdminNav({ role: 'admin' }), true)
  for (const role of ['viewer', 'operator', 'approver', 'auditor', 'Admin', '']) {
    assert.equal(showsAdminNav({ role }), false)
  }
  assert.equal(showsAdminNav(null), false)
  assert.equal(showsAdminNav(undefined), false)
  assert.equal(showsAdminNav({}), false)
})

test('step-up is recognised under both backend wordings', () => {
  assert.equal(isStepUpRequired({ statusCode: 403, data: { detail: 'step_up_required' } }), true)
  assert.equal(isStepUpRequired({ statusCode: 403, data: { detail: 'Fresh step-up required' } }), true)
})

test('other failures are not mistaken for step-up', () => {
  assert.equal(isStepUpRequired({ statusCode: 401, data: { detail: 'step_up_required' } }), false)
  assert.equal(isStepUpRequired({ statusCode: 403, data: { detail: 'Insufficient role' } }), false)
  assert.equal(isStepUpRequired({ statusCode: 403 }), false)
  assert.equal(isStepUpRequired(null), false)
})

test('the error detail is used only when it is a non-empty string', () => {
  assert.equal(errorDetail({ data: { detail: 'No such user' } }, 'x'), 'No such user')
  assert.equal(errorDetail({ data: { detail: [{ msg: 'bad' }] } }, 'fallback'), 'fallback')
  assert.equal(errorDetail({ data: { detail: '' } }, 'fallback'), 'fallback')
  assert.equal(errorDetail(undefined, 'fallback'), 'fallback')
})

test('the secret is read from a provisioning URI', () => {
  const uri = 'otpauth://totp/Athena:a%40b.test?secret=JBSWY3DPEHPK3PXP&issuer=Athena'
  assert.equal(totpSecretFromUri(uri), 'JBSWY3DPEHPK3PXP')
  assert.equal(totpSecretFromUri('otpauth://totp/Athena:a?issuer=Athena'), null)
  assert.equal(totpSecretFromUri('not a uri'), null)
})

test('step-up needs a password, and a six-digit code only when MFA is on', () => {
  assert.equal(stepUpReady('', '', false), false)
  assert.equal(stepUpReady('pw', '', false), true)
  assert.equal(stepUpReady('pw', '', true), false)
  assert.equal(stepUpReady('pw', '12345', true), false)
  assert.equal(stepUpReady('pw', '12a456', true), false)
  assert.equal(stepUpReady('pw', ' 123456 ', true), true)
  assert.equal(stepUpReady('', '123456', true), false)
})
