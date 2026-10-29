import { describe, expect, it } from 'vitest'
import { isValidChallenge, isValidVerifier, s256Challenge, verifyPkce } from '../src/services/pkce'
import { CHALLENGE, VERIFIER } from './helpers'

describe('PKCE S256', () => {
  it('matches the RFC 7636 Appendix B example', async () => {
    expect(await s256Challenge(VERIFIER)).toBe(CHALLENGE)
    expect(await verifyPkce(VERIFIER, CHALLENGE)).toBe(true)
  })

  it('rejects a different verifier', async () => {
    const other = 'eBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    expect(await verifyPkce(other, CHALLENGE)).toBe(false)
  })

  it('rejects the plain method (verifier sent as its own challenge)', async () => {
    expect(await verifyPkce(VERIFIER, VERIFIER)).toBe(false)
  })

  it('validates verifier length and characters', () => {
    expect(isValidVerifier('a'.repeat(43))).toBe(true)
    expect(isValidVerifier('a'.repeat(128))).toBe(true)
    expect(isValidVerifier('Az09-._~'.repeat(6))).toBe(true)
    expect(isValidVerifier('a'.repeat(42))).toBe(false)
    expect(isValidVerifier('a'.repeat(129))).toBe(false)
    expect(isValidVerifier(`${'a'.repeat(42)}+`)).toBe(false)
    expect(isValidVerifier(`${'a'.repeat(42)}=`)).toBe(false)
    expect(isValidVerifier(undefined)).toBe(false)
  })

  it('validates the challenge format', () => {
    expect(isValidChallenge(CHALLENGE)).toBe(true)
    expect(isValidChallenge(`${CHALLENGE}=`)).toBe(false)
    expect(isValidChallenge(CHALLENGE.slice(1))).toBe(false)
    expect(isValidChallenge(CHALLENGE.replace('-', '+'))).toBe(false)
    expect(isValidChallenge(undefined)).toBe(false)
  })

  it('never matches a malformed challenge', async () => {
    expect(await verifyPkce(VERIFIER, `${CHALLENGE}=`)).toBe(false)
  })
})
