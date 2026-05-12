import { describe, expect, it } from 'vitest'

import { redactApiKey } from './redactApiKey.js'

describe('redactApiKey', () => {
  it('returns "EMPTY" for falsy inputs', () => {
    expect(redactApiKey('')).toBe('EMPTY')
    expect(redactApiKey(undefined)).toBe('EMPTY')
    expect(redactApiKey(null)).toBe('EMPTY')
  })

  it('keeps only the rv_live_ brand prefix plus an ellipsis', () => {
    const key = 'rv_live_' + 'a'.repeat(64)
    const got = redactApiKey(key)
    expect(got).toBe('rv_live_\u2026')
    expect(got).not.toContain('a')
  })

  it('does not leak any byte of the random suffix', () => {
    // 72-char real-world key shape: first 8 chars are public, the rest is
    // 256 bits of randomness encoded as 64 hex chars. The redacted form
    // must not contain ANY character from the random tail.
    const suffix = 'b'.repeat(64)
    const key = 'rv_live_' + suffix
    const got = redactApiKey(key)
    for (const ch of suffix) {
      expect(got).not.toContain(ch)
    }
  })

  it('handles short keys (defensive)', () => {
    // Pathological inputs the helper might see during dev / tests.
    expect(redactApiKey('rv_li')).toBe('rv_li\u2026')
    expect(redactApiKey('x')).toBe('x\u2026')
  })
})
