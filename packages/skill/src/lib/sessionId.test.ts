import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { __testing, getCurrentSessionId } from './sessionId.js'

const SAMPLE: Record<string, { updatedAt: number; sessionId?: string }> = {
  agent_key_a: { updatedAt: 1_000, sessionId: 'sess-old' },
  agent_key_b: { updatedAt: 2_000, sessionId: 'sess-newest' },
  agent_key_c: { updatedAt: 1_500 },
}

const FOREIGN: Record<string, { updatedAt: number; sessionId?: string }> = {
  agent_key_x: { updatedAt: 9_999, sessionId: 'sess-attacker-owned' },
}

let prevHome: string | undefined

function writeSessionsAt(file: string, body: unknown): void {
  mkdirSync(join(file, '..'), { recursive: true })
  writeFileSync(file, JSON.stringify(body))
}

function seedHome(): { home: string; sessions: string; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), 'rivault-skill-'))
  const sessions = join(home, '.openclaw', 'agents', 'main', 'sessions', 'sessions.json')
  prevHome = process.env.HOME
  process.env.HOME = home
  __testing.resetCache()
  return {
    home,
    sessions,
    cleanup() {
      if (prevHome === undefined) delete process.env.HOME
      else process.env.HOME = prevHome
      rmSync(home, { recursive: true, force: true })
      __testing.resetCache()
    },
  }
}

describe('getCurrentSessionId', () => {
  let h: ReturnType<typeof seedHome>

  beforeEach(() => {
    h = seedHome()
  })

  afterEach(() => {
    h.cleanup()
  })

  it('returns the most recently updated session id from a legit file', () => {
    writeSessionsAt(h.sessions, SAMPLE)
    expect(getCurrentSessionId()).toBe('sess-newest')
  })

  it('falls back to the agent key when sessionId field is absent', () => {
    writeSessionsAt(h.sessions, {
      agent_key_b: { updatedAt: 2_000 },
    })
    expect(getCurrentSessionId()).toBe('agent_key_b')
  })

  it('returns "" when sessions.json is missing', () => {
    expect(getCurrentSessionId()).toBe('')
  })

  it('follows a symlink that stays inside ~/.openclaw', () => {
    // iCloud-Drive-style: sessions.json points to a real file elsewhere
    // under the openclaw root.
    const real = join(h.home, '.openclaw', 'real-sessions.json')
    mkdirSync(join(real, '..'), { recursive: true })
    writeFileSync(real, JSON.stringify(SAMPLE))
    mkdirSync(join(h.sessions, '..'), { recursive: true })
    symlinkSync(real, h.sessions)
    chmodSync(real, 0o600)
    expect(getCurrentSessionId()).toBe('sess-newest')
  })

  it('refuses a symlink whose target escapes ~/.openclaw', () => {
    // Attacker drops a symlink pointing to foreign JSON outside the
    // user's OpenClaw tree.
    const foreign = join(h.home, 'attacker-controlled.json')
    writeFileSync(foreign, JSON.stringify(FOREIGN))
    mkdirSync(join(h.sessions, '..'), { recursive: true })
    symlinkSync(foreign, h.sessions)
    expect(getCurrentSessionId()).toBe('')
  })

  it('refuses a symlink in a parent directory that escapes', () => {
    // Replace the `agents` directory itself with a symlink to a foreign
    // tree containing attacker JSON.
    const attackerTree = join(h.home, 'attacker-agents')
    const attackerSessions = join(attackerTree, 'main', 'sessions', 'sessions.json')
    writeSessionsAt(attackerSessions, FOREIGN)
    const agentsDir = join(h.home, '.openclaw', 'agents')
    mkdirSync(join(h.home, '.openclaw'), { recursive: true })
    symlinkSync(attackerTree, agentsDir)
    expect(getCurrentSessionId()).toBe('')
  })

  it('caches the result for 5s so repeated calls hit memory', () => {
    writeSessionsAt(h.sessions, SAMPLE)
    expect(getCurrentSessionId()).toBe('sess-newest')
    // Delete the file; cached value persists until TTL.
    rmSync(h.sessions)
    expect(getCurrentSessionId()).toBe('sess-newest')
  })
})
