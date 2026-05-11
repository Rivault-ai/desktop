import { spawn } from 'child_process'
import { readFileSync, openSync, appendFileSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'
import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

// Cache for getCurrentSessionId — TTL of 5 seconds to avoid repeated disk reads
let _sessionIdCache: { value: string; expiresAt: number } | null = null

function getCurrentSessionId(): string {
  const now = Date.now()
  if (_sessionIdCache && now < _sessionIdCache.expiresAt) {
    return _sessionIdCache.value
  }
  try {
    const sessionsPath = join(homedir(), '.openclaw/agents/main/sessions/sessions.json')
    const sessions = JSON.parse(readFileSync(sessionsPath, 'utf-8')) as Record<
      string,
      { updatedAt: number; sessionId?: string }
    >
    const entries = Object.entries(sessions)
    entries.sort(([, a], [, b]) => b.updatedAt - a.updatedAt)
    // Return the actual session UUID from the value, not the agent key
    const value = entries[0]?.[1]?.sessionId ?? entries[0]?.[0] ?? ''
    _sessionIdCache = { value, expiresAt: now + 5_000 }
    return value
  } catch {
    _sessionIdCache = { value: '', expiresAt: now + 5_000 }
    return ''
  }
}

function spawnBackgroundPoller(
  apiKey: string,
  apiBaseUrl: string,
  authRequestId: string,
  urlToken: string,
  sessionId: string,
  itemLabel: string,
): void {
  const pollerScript = join(__dirname, '../lib/poller.js')
  const logFile = join(homedir(), '.openclaw/rivault-poller.log')
  const logStream = openSync(logFile, 'a')
  const child = spawn(process.execPath, [pollerScript, apiKey, apiBaseUrl, authRequestId, urlToken, sessionId, itemLabel], {
    detached: true,
    stdio: ['ignore', logStream, logStream],
  })
  child.on('error', (err) => {
    appendFileSync(logFile, `[rivault] spawn error: ${err.message}\n`)
  })
  child.unref()
  appendFileSync(logFile, `[rivault] spawned poller PID=${child.pid} authRequestId=${authRequestId} sessionId=${sessionId}\n`)
}

export function createRequestAuthTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_request_auth',
    description:
      '[USE THIS TOOL — DO NOT FALL BACK TO BASH CURL] Request user authorization to access an L1 or L2 vault item. Creates a unique authorization link for the user to approve via Face ID. After calling this, send the agentMessage from the response to the user word-for-word and END your response — a detached background poller will auto-resume your session when the user approves. ' +
      'PLUGIN IS HEALTHY (v0.2.6+). Bash curl bypasses the daemon: no ledger row, no transcript redaction, no auto-resume.',
    parameters: {
      type: 'object',
      properties: {
        item_id: {
          type: 'string',
          description: 'The vault item ID from rivault_search results',
        },
        reason: {
          type: 'string',
          description:
            'Brief explanation of why you need this item (shown to user on the authorization page). E.g. "needed to complete your shoe purchase on Nike.com"',
        },
      },
      required: ['item_id'],
    },
    async execute(params): Promise<ToolResult> {
      const itemId = params.item_id as string
      const reason = params.reason as string | undefined

      // Diagnostic: log unconditionally so we can see if this function runs
      const logFile = join(homedir(), '.openclaw/rivault-poller.log')
      appendFileSync(logFile, `[rivault] execute called at ${new Date().toISOString()} itemId=${itemId}\n`)

      // Get the current OpenClaw session ID so the background poller can resume it
      const sessionId = getCurrentSessionId()
      appendFileSync(logFile, `[rivault] sessionId="${sessionId}"\n`)

      try {
        const result = await client.requestAuth(itemId, reason, sessionId || undefined)

        const apiKey = client.getApiKey()
        const apiBaseUrl = client.getBaseUrl()
        appendFileSync(logFile, `[rivault] apiKey="${apiKey ? apiKey.substring(0, 10) + '...' : 'EMPTY'}" authRequestId=${result.authRequestId}\n`)

        // Extract the URL token from the auth URL (e.g. https://rivault.ai/a/<token>)
        const urlToken = result.authUrl?.split('/a/')[1] ?? ''

        // Spawn detached background poller — it will call `openclaw agent` when the user approves
        if (sessionId && apiKey) {
          spawnBackgroundPoller(apiKey, apiBaseUrl, result.authRequestId, urlToken, sessionId, itemId)
        } else {
          appendFileSync(logFile, `[rivault] SKIPPED spawn: sessionId=${!!sessionId} apiKey=${!!apiKey}\n`)
        }

        return textResult(
          `Authorization request created.\n\n` +
            `Auth Request ID: ${result.authRequestId}\n` +
            `Item ID: ${itemId}\n\n` +
            `Send this EXACT message to the user (do not paraphrase):\n${result.agentMessage}\n\n` +
            `End your response now. A background process is polling for approval. ` +
            `When the user approves, you will automatically receive a [RIVAULT_APPROVED] message. ` +
            `Do NOT poll manually. Do NOT call any more tools. End your response immediately after sending the auth message.`,
        )
      } catch (err) {
        return textResult(
          `Failed to create authorization request: ${err instanceof Error ? err.message : 'Unknown error'}`,
        )
      }
    },
  }
}
