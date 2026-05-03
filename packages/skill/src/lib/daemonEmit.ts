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
export type McpMode = 'remote' | 'local' | 'none'

export interface ReleaseEventInput {
  userId: string
  apiKeyId: string
  itemId: string
  tier: Tier
  plaintext: string | null
  agentSessionId?: string | null
}

interface ReleaseEvent {
  release_id: string
  user_id: string
  api_key_id: string
  item_id: string
  tier: Tier
  runtime: Runtime
  runtime_pid: number | null
  mcp_mode: McpMode
  agent_session_id: string | null
  cwd: string
  transcript_paths: string[]
  plaintext: string | null
  plaintext_hash: string
  retrieved_at: string
}

let cachedDiscovery: DiscoveryFile | null = null
let cachedDiscoveryAt = 0
const DISCOVERY_TTL_MS = 30_000

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
  } catch {
    cachedDiscovery = null
    return null
  }
}

function detectRuntime(): Runtime {
  if (process.env.OPENCLAW_SKILL || process.env.OPENCLAW_RUNTIME) return 'openclaw'
  if (process.env.CLAUDE_CODE_SESSION || process.env.CLAUDECODE) return 'claude_code'
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
  if (!discovery || !discovery.http_port) return

  const event: ReleaseEvent = {
    release_id: randomUUID(),
    user_id: input.userId,
    api_key_id: input.apiKeyId,
    item_id: input.itemId,
    tier: input.tier,
    runtime: detectRuntime(),
    runtime_pid: process.pid,
    mcp_mode: 'none',
    agent_session_id: input.agentSessionId ?? process.env.RIVAULT_AGENT_SESSION_ID ?? null,
    cwd: process.cwd(),
    transcript_paths: transcriptPaths(),
    plaintext: input.plaintext,
    plaintext_hash: createHash('sha256').update(input.plaintext ?? '').digest('hex'),
    retrieved_at: new Date().toISOString(),
  }

  const body = JSON.stringify(event)
  const key = Buffer.from(discovery.hmac_key_hex, 'hex')
  const signature = createHmac('sha256', key).update(body).digest('hex')

  const url = `http://127.0.0.1:${discovery.http_port}/release`
  try {
    await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Rivault-Signature': signature,
      },
      body,
      signal: AbortSignal.timeout(2_000),
    })
  } catch {
    // Daemon offline or rejected — never block the agent.
  }
}
