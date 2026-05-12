import { lstatSync, readFileSync, type Stats } from 'node:fs'
import { homedir, platform } from 'node:os'
import { join } from 'node:path'

interface DiscoveryFile {
  schema_version: number
  http_port: number | null
  socket_path: string
  hmac_key_hex: string
}

const DISCOVERY_TTL_MS = 30_000

let cached: DiscoveryFile | null = null
let cachedAt = 0

/**
 * The Rivault desktop daemon writes a discovery file (mode 0600) when
 * it binds its localhost HTTP listener. The skill reads it on each
 * tool invocation to decide whether to route through the daemon
 * (`http://127.0.0.1:<port>`) or fall back to `api.rivault.ai`.
 *
 * Auto-discovery removes the need for users to set `RIVAULT_API_URL`
 * by hand or to mutate `openclaw.json` (whose schema rejects unknown
 * keys). When the daemon isn't running, this returns null and callers
 * use the public API directly.
 *
 * Cached for 30s to avoid hammering the filesystem on agents that fan
 * out many tool calls per task.
 */
export function discoverDaemonUrl(): string | null {
  const file = loadDiscoveryFile()
  if (!file || file.http_port == null) return null
  return `http://127.0.0.1:${file.http_port}`
}

function loadDiscoveryFile(): DiscoveryFile | null {
  const now = Date.now()
  if (cached !== null && now - cachedAt < DISCOVERY_TTL_MS) return cached
  cached = null
  cachedAt = now
  try {
    const p = discoveryPath()
    if (!isTrustedDiscoveryFile(p)) return null
    const parsed = JSON.parse(readFileSync(p, 'utf8')) as DiscoveryFile
    cached = parsed
    return parsed
  } catch {
    return null
  }
}

/**
 * Refuse a daemon.json that any other local process could have written.
 *
 * The daemon writes the file at mode 0600 under the current user's
 * data directory; any same-UID local process can still clobber it
 * (that's a macOS reality, not an ACL bug), but a tampered file should
 * at least announce itself by failing one of these structural checks.
 *
 *  - **Symlink rejected.** A symlink at the discovery path is never
 *    something the daemon wrote — it was placed by another process to
 *    redirect the read.
 *  - **Owner UID must match.** Catches the case where the file was
 *    written by a different account on a shared Mac (rare today,
 *    important for future enterprise deployments).
 *  - **Mode must be exactly 0600.** A widened mode (`0640`, `0644`,
 *    …) is the signal a previous installer or another process
 *    weakened the file.
 *
 * On Windows the POSIX `uid`/`mode` fields are meaningless, so the
 * check is a no-op there — the daemon doesn't ship to Windows today
 * and adding a separate ACL check is out of scope.
 */
function isTrustedDiscoveryFile(p: string): boolean {
  if (platform() === 'win32') return true
  let stat: Stats
  try {
    stat = lstatSync(p)
  } catch {
    return false
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    warn(`[rivault] ignoring daemon.json: not a regular file (path=${p})`)
    return false
  }
  const myUid = typeof process.getuid === 'function' ? process.getuid() : null
  if (myUid !== null && stat.uid !== myUid) {
    warn(
      `[rivault] ignoring daemon.json: owner uid ${stat.uid} != process uid ${myUid}`,
    )
    return false
  }
  const mode = stat.mode & 0o777
  if (mode !== 0o600) {
    warn(
      `[rivault] ignoring daemon.json: mode ${mode.toString(8)} != 600; ` +
        'expected an exclusive-to-owner file written by the desktop daemon',
    )
    return false
  }
  return true
}

function warn(msg: string): void {
  // Best-effort: don't crash if stderr is closed.
  try {
    process.stderr.write(`${msg}\n`)
  } catch {
    /* swallow */
  }
}

function discoveryPath(): string {
  if (platform() === 'darwin') {
    return join(homedir(), 'Library', 'Application Support', 'Rivault', 'daemon.json')
  }
  const xdg = process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share')
  return join(xdg, 'Rivault', 'daemon.json')
}

// Test-only entry points. Not exported from the package barrel; used by
// vitest fixtures to bypass the cache + path resolver.
export const __testing = {
  isTrustedDiscoveryFile,
  resetCache(): void {
    cached = null
    cachedAt = 0
  },
}
