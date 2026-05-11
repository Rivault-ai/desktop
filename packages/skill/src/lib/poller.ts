/**
 * Background polling script — spawned as a detached child process by requestAuth.
 * Polls Rivault until the auth request is resolved, then calls `openclaw agent`
 * to resume the agent session automatically.
 *
 * Args: apiKey apiBaseUrl authRequestId sessionId itemLabel
 */

import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

const [, , apiKey, apiBaseUrl, authRequestId, urlToken, sessionId, itemLabel] = process.argv

if (!apiKey || !authRequestId || !sessionId) {
  process.exit(1)
}

// Exponential backoff: start at 3s, increase to 8s after 10 polls
const POLL_INTERVAL_INITIAL_MS = 3_000
const POLL_INTERVAL_MAX_MS = 8_000
const BACKOFF_AFTER_POLLS = 10
const MAX_ATTEMPTS = 200 // ~22 minutes at mixed intervals

async function resumeAgent(message: string): Promise<boolean> {
  // 3 attempts × 2 transports (session-id, channel=last) × 2s backoff.
  // `openclaw agent --deliver` is sometimes flaky after gateway restarts;
  // retrying handles transient IPC failures gracefully.
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await execFileAsync('/opt/homebrew/bin/openclaw', [
        'agent', '--session-id', sessionId, '--message', message, '--deliver',
      ])
      return true
    } catch {
      try {
        await execFileAsync('/opt/homebrew/bin/openclaw', [
          'agent', '--channel', 'last', '--message', message, '--deliver',
        ])
        return true
      } catch {
        if (attempt < 3) {
          await new Promise(resolve => setTimeout(resolve, 2_000))
        }
      }
    }
  }
  return false
}

async function poll(): Promise<void> {
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    if (i > 0) {
      const intervalMs = i >= BACKOFF_AFTER_POLLS ? POLL_INTERVAL_MAX_MS : POLL_INTERVAL_INITIAL_MS
      await new Promise<void>(resolve => setTimeout(resolve, intervalMs))
    }

    try {
      // Use the PUBLIC endpoint (no API key, no Redis touch) to detect approval.
      // This preserves the Redis value for rivault_poll_auth to retrieve.
      // Fall back to the authenticated endpoint if no URL token is available.
      let status: string | undefined
      if (urlToken) {
        const res = await fetch(`${apiBaseUrl}/auth-request/${urlToken}`, {
          headers: { 'Content-Type': 'application/json' },
        })
        if (!res.ok) continue
        const data = (await res.json()) as { status: string }
        status = data.status
      } else {
        const res = await fetch(`${apiBaseUrl}/agent/auth-request/${authRequestId}/status`, {
          headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        })
        if (!res.ok) continue
        const data = (await res.json()) as { status: string }
        status = data.status
      }

      if (status === 'approved') {
        // Step 1: Send a lightweight notify so the agent immediately sends
        // "✅ Authorization approved." as its own standalone message.
        await resumeAgent(`[RIVAULT_APPROVED_NOTIFY]`)

        // Brief pause to let the agent finish sending the notification message
        // before we deliver the actual work message.
        await new Promise<void>(resolve => setTimeout(resolve, 4000))

        // Step 2: Now trigger the actual work.
        // Include item_id in the message so the agent can pass it to rivault_poll_auth
        // as a fallback if the value isn't available in Redis.
        await resumeAgent(
          `[RIVAULT_APPROVED] authRequestId=${authRequestId} itemId=${itemLabel}\n\n` +
          `The user approved access to vault item (item_id="${itemLabel}"). ` +
          `Call rivault_poll_auth with auth_request_id="${authRequestId}" and item_id="${itemLabel}" to retrieve the value and complete the original task. ` +
          `When done, tell the user: "✅ Task completed. [one sentence summary of what was done]"`,
        )
        process.exit(0)
      }

      if (status === 'denied') {
        await resumeAgent(
          `[RIVAULT_DENIED] authRequestId=${authRequestId}\n\n` +
          `The user denied access to "${itemLabel}". ` +
          `Inform the user you cannot complete the task without this item.`,
        )
        process.exit(0)
      }

      if (status === 'expired') {
        process.exit(0)
      }
    } catch {
      // Network error — keep polling
    }
  }

  process.exit(0)
}

poll()
