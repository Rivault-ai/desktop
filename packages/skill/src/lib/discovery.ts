import { readFileSync } from 'node:fs'
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
  try {
    const raw = readFileSync(discoveryPath(), 'utf8')
    const parsed = JSON.parse(raw) as DiscoveryFile
    cached = parsed
    cachedAt = now
    return parsed
  } catch {
    cached = null
    cachedAt = now
    return null
  }
}

function discoveryPath(): string {
  if (platform() === 'darwin') {
    return join(homedir(), 'Library', 'Application Support', 'Rivault', 'daemon.json')
  }
  const xdg = process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share')
  return join(xdg, 'Rivault', 'daemon.json')
}
