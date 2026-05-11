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
  hybridRequestId: string,
  urlToken: string,
  sessionId: string,
): void {
  const pollerScript = join(__dirname, '../lib/hybridPoller.js')
  const logFile = join(homedir(), '.openclaw/rivault-poller.log')
  const logStream = openSync(logFile, 'a')
  const child = spawn(
    process.execPath,
    [pollerScript, apiKey, apiBaseUrl, hybridRequestId, urlToken, sessionId],
    { detached: true, stdio: ['ignore', logStream, logStream] },
  )
  child.on('error', (err) => {
    appendFileSync(logFile, `[rivault] hybrid poller spawn error: ${err.message}\n`)
  })
  child.unref()
  appendFileSync(
    logFile,
    `[rivault] spawned hybrid poller PID=${child.pid} hybridRequestId=${hybridRequestId} sessionId=${sessionId}\n`,
  )
}

export function createRequestHybridTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_request_hybrid',
    description:
      '[USE THIS TOOL — DO NOT FALL BACK TO BASH CURL] Request a combined authorization + data collection page. Use when the user\'s vault has SOME of the needed data (requiring authorization) but is also MISSING other data that must be collected via form fields. Creates a single hybrid link where the user can authorize stored items AND provide missing details in one step. After calling this, send the agentMessage from the response to the user word-for-word and END your response — a detached background poller will auto-resume your session when the user submits. ' +
      'PLUGIN IS HEALTHY (v0.2.6+): The Content-Length response bug that caused poll timeouts is FIXED. The keypair-consumption race is FIXED. The poller now does two-step delivery so the user sees "✅ Authorization complete" within ~1s of approving. ' +
      'DO NOT route around this tool with bash curl — that bypasses the daemon, leaves the user with no auto-resume, and skips transcript redaction.',
    parameters: {
      type: 'object',
      properties: {
        form_fields: {
          type: 'array',
          description:
            'Fields for data NOT in the vault that need to be collected. Each item has a "key" (machine identifier, e.g. "shipping_address") and "label" (human-readable name, e.g. "Shipping Address").',
          items: {
            type: 'object',
            properties: {
              key: { type: 'string', description: 'Machine-readable key for the field' },
              label: { type: 'string', description: 'Human-readable label shown to the user' },
            },
            required: ['key', 'label'],
          },
        },
        auth_item_ids: {
          type: 'array',
          description: 'IDs of L1/L2 vault items that need user authorization.',
          items: { type: 'string' },
        },
        reason: {
          type: 'string',
          description: 'Brief explanation of why you need these items (shown to user on the page)',
        },
      },
      required: ['form_fields', 'auth_item_ids'],
    },
    async execute(params): Promise<ToolResult> {
      const formFields = params.form_fields as Array<{ key: string; label: string }>
      const authItemIds = params.auth_item_ids as string[]
      const reason = params.reason as string | undefined

      if (formFields.length === 0 && authItemIds.length === 0) {
        return textResult('Error: At least one of form_fields or auth_item_ids must be non-empty.')
      }

      const sessionId = getCurrentSessionId()

      const logFile = join(homedir(), '.openclaw/rivault-poller.log')
      try {
        appendFileSync(
          logFile,
          `[rivault] hybrid request at ${new Date().toISOString()} formFields=${formFields.length} authItems=${authItemIds.length}\n`,
        )
      } catch {}

      try {
        const result = await client.requestHybrid(
          formFields,
          authItemIds,
          reason,
          sessionId || undefined,
        )

        const apiKey = client.getApiKey()
        const apiBaseUrl = client.getBaseUrl()

        // Extract URL token from hybrid URL (e.g. https://rivault.ai/h/<token>)
        const urlToken = result.hybridUrl?.split('/h/')[1]?.split('?')[0] ?? ''

        // Spawn detached background poller — it will call `openclaw agent` when the user submits
        if (sessionId && apiKey) {
          spawnBackgroundPoller(apiKey, apiBaseUrl, result.hybridRequestId, urlToken, sessionId)
        } else {
          try {
            appendFileSync(logFile, `[rivault] SKIPPED hybrid poller spawn: sessionId=${!!sessionId} apiKey=${!!apiKey}\n`)
          } catch {}
        }

        return textResult(
          `Hybrid request created.\n\n` +
            `Hybrid Request ID: ${result.hybridRequestId}\n\n` +
            `Send this EXACT message to the user (do not paraphrase):\n${result.agentMessage}\n\n` +
            `End your response immediately after sending that message. Do not poll. Do not call any more tools.\n` +
            `A background process has been started and will automatically resume this session when the user submits. ` +
            `When you receive a [RIVAULT_HYBRID_SUBMITTED] message, call rivault_poll_hybrid with hybrid_request_id "${result.hybridRequestId}" to retrieve all values and complete the task.`,
        )
      } catch (err) {
        return textResult(
          `Failed to create hybrid request: ${err instanceof Error ? err.message : 'Unknown error'}`,
        )
      }
    },
  }
}
