import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { __testing } from './discovery.js'

const { isTrustedDiscoveryFile, resetCache } = __testing

const SAMPLE_BODY = JSON.stringify({
  schema_version: 1,
  http_port: 47318,
  socket_path: '/tmp/rivault.sock',
  hmac_key_hex: '00'.repeat(32),
})

describe('isTrustedDiscoveryFile', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'rivault-discovery-'))
    resetCache()
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('accepts a regular file at mode 0600 owned by the current user', () => {
    const p = join(dir, 'daemon.json')
    writeFileSync(p, SAMPLE_BODY)
    chmodSync(p, 0o600)
    expect(isTrustedDiscoveryFile(p)).toBe(true)
  })

  it('rejects a missing file', () => {
    expect(isTrustedDiscoveryFile(join(dir, 'does-not-exist'))).toBe(false)
  })

  it('rejects a world-readable file', () => {
    const p = join(dir, 'daemon.json')
    writeFileSync(p, SAMPLE_BODY)
    chmodSync(p, 0o644)
    expect(isTrustedDiscoveryFile(p)).toBe(false)
  })

  it('rejects a group-readable file', () => {
    const p = join(dir, 'daemon.json')
    writeFileSync(p, SAMPLE_BODY)
    chmodSync(p, 0o640)
    expect(isTrustedDiscoveryFile(p)).toBe(false)
  })

  it('rejects an executable file (covers the 0o700 mistake)', () => {
    const p = join(dir, 'daemon.json')
    writeFileSync(p, SAMPLE_BODY)
    chmodSync(p, 0o700)
    expect(isTrustedDiscoveryFile(p)).toBe(false)
  })

  it('rejects a symlink, even when the target is a valid 0600 file', () => {
    const real = join(dir, 'real.json')
    writeFileSync(real, SAMPLE_BODY)
    chmodSync(real, 0o600)
    const link = join(dir, 'daemon.json')
    symlinkSync(real, link)
    expect(isTrustedDiscoveryFile(link)).toBe(false)
  })

  it('rejects a directory at the discovery path', () => {
    const p = join(dir, 'daemon.json')
    mkdirSync(p)
    chmodSync(p, 0o700)
    expect(isTrustedDiscoveryFile(p)).toBe(false)
  })
})
