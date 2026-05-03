/**
 * Background polling script — spawned as a detached child process by requestHybrid.
 * Polls Rivault until the hybrid request is submitted, then calls `openclaw agent`
 * to resume the agent session automatically.
 *
 * Args: apiKey apiBaseUrl hybridRequestId urlToken sessionId
 */

import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

const [, , apiKey, apiBaseUrl, hybridRequestId, urlToken, sessionId] = process.argv

if (!apiKey || !hybridRequestId || !sessionId) {
  process.exit(1)
}

const POLL_INTERVAL_INITIAL_MS = 3_000
const POLL_INTERVAL_MAX_MS = 8_000
const BACKOFF_AFTER_POLLS = 10
const MAX_ATTEMPTS = 250 // ~30 minutes at mixed intervals

async function resumeAgent(message: string): Promise<void> {
  try {
    await execFileAsync('openclaw', [
      'agent',
      '--session-id', sessionId,
      '--message', message,
      '--deliver',
    ])
  } catch {
    try {
      await execFileAsync('openclaw', [
        'agent',
        '--channel', 'last',
        '--message', message,
        '--deliver',
      ])
    } catch {
      // Nothing more we can do
    }
  }
}

async function poll(): Promise<void> {
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    if (i > 0) {
      const intervalMs = i >= BACKOFF_AFTER_POLLS ? POLL_INTERVAL_MAX_MS : POLL_INTERVAL_INITIAL_MS
      await new Promise<void>(resolve => setTimeout(resolve, intervalMs))
    }

    try {
      // Use the public endpoint to check status without consuming Redis values
      if (urlToken) {
        const res = await fetch(`${apiBaseUrl}/hybrid-request/${urlToken}`, {
          headers: { 'Content-Type': 'application/json' },
        })
        if (!res.ok) continue
        const data = (await res.json()) as { status: string }

        if (data.status === 'submitted') {
          await resumeAgent(
            `[RIVAULT_HYBRID_SUBMITTED] hybridRequestId=${hybridRequestId}\n\n` +
            `The user submitted form data and authorized access to stored items. ` +
            `Call rivault_poll_hybrid with hybrid_request_id="${hybridRequestId}" to retrieve all values and complete the original task.`,
          )
          process.exit(0)
        }

        if (data.status === 'expired') {
          process.exit(0)
        }
      } else {
        // Fallback to authenticated agent endpoint
        const res = await fetch(`${apiBaseUrl}/agent/hybrid-request/${hybridRequestId}/status`, {
          headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        })
        if (!res.ok) continue
        const data = (await res.json()) as { status: string }

        if (data.status === 'submitted') {
          await resumeAgent(
            `[RIVAULT_HYBRID_SUBMITTED] hybridRequestId=${hybridRequestId}\n\n` +
            `The user submitted form data and authorized access to stored items. ` +
            `Call rivault_poll_hybrid with hybrid_request_id="${hybridRequestId}" to retrieve all values and complete the original task.`,
          )
          process.exit(0)
        }

        if (data.status === 'expired') {
          process.exit(0)
        }
      }
    } catch {
      // Network error — keep polling
    }
  }

  process.exit(0)
}

poll()
