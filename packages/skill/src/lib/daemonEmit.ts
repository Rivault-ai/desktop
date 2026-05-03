import { createHash, createHmac, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { homedir, platform } from 'node:os'
import { join } from 'node:path'

interface DiscoveryFile {
  schema_version: number
  http_port: number | null
  socket_path: string
  hmac_key_hex: string
}

export type Tier = 'L1' | 'L2'
export type Runtime = 'claude_code' | 'codex' | 'openclaw' | 'claude_desktop'

/**
 * Public input shape — what skill tools pass in. We translate this into
 * the daemon's wire format inside emitRelease().
 */
export interface ReleaseEventInput {
  userId: string
  apiKeyId: string
  itemId: string
  tier: Tier
  plaintext: string | null
  agentSessionId?: string | null
}

/**
 * Wire shape consumed by `packages/desktop/src-tauri/src/daemon/release.rs`.
 *
 * Field names + casing are deliberately set to match Rust's serde derive
 * (lowercase tier, kebab-case runtime, value_plaintext / value_hash /
 * released_at). When this drifts from Rust the daemon returns 400 and
 * release events disappear silently — keep them in lockstep.
 */
interface DaemonReleaseEvent {
  release_id: string
  session_id: string
  tier: 'l1' | 'l2'
  agent_runtime: 'claude-code' | 'openclaw' | 'claude-desktop' | 'codex' | 'custom'
  mcp_mode: 'envelope-verbatim' | 'server-decrypt' | null
  value_plaintext: string | null
  value_hash: string
  encoded_variants: string[]
  transcript_paths: string[]
  released_at: string
  rotation_supported: boolean
}

let cachedDiscovery: DiscoveryFile | null = null
let cachedDiscoveryAt = 0
const DISCOVERY_TTL_MS = 30_000
const DEBUG = !!process.env.RIVAULT_SKILL_DEBUG

function debug(...args: unknown[]) {
  if (DEBUG) console.error('[rivault-skill]', ...args)
}

function discoveryPath(): string {
  if (platform() === 'darwin') {
    return join(homedir(), 'Library', 'Application Support', 'Rivault', 'daemon.json')
  }
  const xdg = process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share')
  return join(xdg, 'Rivault', 'daemon.json')
}

async function loadDiscovery(): Promise<DiscoveryFile | null> {
  const now = Date.now()
  if (cachedDiscovery && now - cachedDiscoveryAt < DISCOVERY_TTL_MS) {
    return cachedDiscovery
  }
  try {
    const raw = await readFile(discoveryPath(), 'utf8')
    const parsed = JSON.parse(raw) as DiscoveryFile
    cachedDiscovery = parsed
    cachedDiscoveryAt = now
    return parsed
  } catch (err) {
    debug('discovery file unreadable:', err)
    cachedDiscovery = null
    return null
  }
}

function detectRuntime(): DaemonReleaseEvent['agent_runtime'] {
  if (process.env.OPENCLAW_SKILL || process.env.OPENCLAW_RUNTIME) return 'openclaw'
  if (process.env.CLAUDE_CODE_SESSION || process.env.CLAUDECODE) return 'claude-code'
  if (process.env.CODEX_HOME || process.env.CODEX_SESSION) return 'codex'
  return 'openclaw'
}

function transcriptPaths(): string[] {
  const out: string[] = []
  for (const k of ['CLAUDE_TRANSCRIPT_PATH', 'CODEX_TRANSCRIPT_PATH', 'OPENCLAW_TRANSCRIPT_PATH']) {
    const v = process.env[k]
    if (v) out.push(v)
  }
  return out
}

export async function emitRelease(input: ReleaseEventInput): Promise<void> {
  const discovery = await loadDiscovery()
  if (!discovery || !discovery.http_port) {
    debug('no daemon discovery — skipping emit')
    return
  }

  // Daemon's session_id groups releases for the same agent task. Prefer the
  // explicit agent session id, fall back to apiKeyId so the dashboard can at
  // least cluster by API key, ultimately to a synthetic UUID.
  const sessionId =
    input.agentSessionId ??
    process.env.RIVAULT_AGENT_SESSION_ID ??
    input.apiKeyId ??
    randomUUID()

  const event: DaemonReleaseEvent = {
    release_id: randomUUID(),
    session_id: sessionId,
    tier: input.tier === 'L1' ? 'l1' : 'l2',
    agent_runtime: detectRuntime(),
    // mcp_mode null = not running through MCP; only the API-server-side
    // MCP tool path sets envelope-verbatim / server-decrypt.
    mcp_mode: null,
    value_plaintext: input.plaintext,
    value_hash: createHash('sha256').update(input.plaintext ?? '').digest('hex'),
    encoded_variants: [],
    transcript_paths: transcriptPaths(),
    released_at: new Date().toISOString(),
    rotation_supported: false,
  }

  const body = JSON.stringify(event)
  const key = Buffer.from(discovery.hmac_key_hex, 'hex')
  const signature = createHmac('sha256', key).update(body).digest('hex')

  const url = `http://127.0.0.1:${discovery.http_port}/release`
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Rivault-Signature': signature,
      },
      body,
      signal: AbortSignal.timeout(2_000),
    })
    if (!res.ok) {
      // Schema drift between skill and daemon used to fail silently and
      // hide release events for hours of debugging. Surfacing the body
      // here makes the next mismatch immediately diagnosable.
      const detail = await res.text().catch(() => '')
      debug(`daemon rejected release (${res.status}):`, detail)
    } else {
      debug('release accepted', event.release_id)
    }
  } catch (err) {
    // Daemon offline or network error — never block the agent.
    debug('emit failed:', err)
  }
}
