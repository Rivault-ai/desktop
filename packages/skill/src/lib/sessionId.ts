import { lstatSync, readFileSync, realpathSync, type Stats } from 'node:fs'
import { homedir, platform } from 'node:os'
import { join, sep } from 'node:path'

/**
 * Resolve the OpenClaw session id the agent is currently inside.
 *
 * Reads `~/.openclaw/agents/main/sessions/sessions.json` (the most
 * recently-touched session wins) and returns the embedded `sessionId`,
 * falling back to the agent key, or `''` when the file is unavailable.
 *
 * Hardened against same-UID symlink attacks: an attacker who can write
 * inside `~` could replace the file (or any path component) with a
 * symlink pointing at attacker-controlled JSON to inject a `sessionId`
 * the poller would then "resume" — delivering `[RIVAULT_APPROVED]`
 * messages and plaintext into the attacker's session.
 *
 * Defence:
 *
 *  - Resolve via `realpath` so symlinks are followed.
 *  - Confirm the resolved path stays under a canonicalized
 *    `~/.openclaw/` root. Legitimate symlinks (iCloud Drive, custom
 *    dotfile setups) keep working as long as both ends live in the
 *    user's OpenClaw tree.
 *  - Confirm the resolved file's owner UID matches the current process,
 *    so a path that escaped onto a shared mount can't surface foreign
 *    JSON.
 *
 * Cached for 5s — agents fan out many tool calls per task and the
 * filesystem walk shouldn't dominate latency.
 */

const CACHE_TTL_MS = 5_000

let cache: { value: string; expiresAt: number } | null = null

interface OpenclawSession {
  updatedAt: number
  sessionId?: string
}

export function getCurrentSessionId(): string {
  const now = Date.now()
  if (cache && now < cache.expiresAt) return cache.value
  const value = resolveSessionId()
  cache = { value, expiresAt: now + CACHE_TTL_MS }
  return value
}

function resolveSessionId(): string {
  try {
    const path = trustedSessionsPath()
    if (path === null) return ''
    const sessions = JSON.parse(readFileSync(path, 'utf-8')) as Record<
      string,
      OpenclawSession
    >
    const entries = Object.entries(sessions)
    entries.sort(([, a], [, b]) => b.updatedAt - a.updatedAt)
    return entries[0]?.[1]?.sessionId ?? entries[0]?.[0] ?? ''
  } catch {
    return ''
  }
}

function trustedSessionsPath(): string | null {
  const root = openclawRoot()
  const sessionsPath = join(root, 'agents', 'main', 'sessions', 'sessions.json')

  let resolvedRoot: string
  let resolvedFile: string
  try {
    resolvedRoot = realpathSync(root)
    resolvedFile = realpathSync(sessionsPath)
  } catch {
    return null
  }

  if (!isInsideDir(resolvedFile, resolvedRoot)) {
    warn(
      `[rivault] ignoring sessions.json: resolved target ${resolvedFile} ` +
        `escapes openclaw root ${resolvedRoot}`,
    )
    return null
  }

  // POSIX-only ownership check; on Windows process.getuid is undefined.
  if (platform() !== 'win32' && typeof process.getuid === 'function') {
    let stat: Stats
    try {
      stat = lstatSync(resolvedFile)
    } catch {
      return null
    }
    const uid = process.getuid()
    if (stat.uid !== uid) {
      warn(
        `[rivault] ignoring sessions.json: owner uid ${stat.uid} != process uid ${uid}`,
      )
      return null
    }
  }

  return resolvedFile
}

function openclawRoot(): string {
  return join(homedir(), '.openclaw')
}

function isInsideDir(file: string, dir: string): boolean {
  const prefix = dir.endsWith(sep) ? dir : dir + sep
  return file === dir || file.startsWith(prefix)
}

function warn(msg: string): void {
  try {
    process.stderr.write(`${msg}\n`)
  } catch {
    /* swallow */
  }
}

// Test-only entry points.
export const __testing = {
  trustedSessionsPath,
  resetCache(): void {
    cache = null
  },
}
