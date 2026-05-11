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

/**
 * Two-step delivery so the user gets "Authorization complete!" as a
 * standalone WhatsApp message the moment we detect approval, BEFORE
 * the agent spends time retrieving values + filling the form. Mirrors
 * the auth-request poller's pattern.
 */
async function deliverWithRetry(message: string): Promise<boolean> {
  // Try up to 3 times: --session-id first, --channel last as fallback,
  // with a 2s backoff between attempts. `openclaw agent --deliver` is
  // sometimes flaky across gateway restarts; retrying buys reliability.
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
      // Use the public endpoint to check status without consuming Redis values
      let status: string | undefined
      if (urlToken) {
        const res = await fetch(`${apiBaseUrl}/hybrid-request/${urlToken}`, {
          headers: { 'Content-Type': 'application/json' },
        })
        if (!res.ok) continue
        const data = (await res.json()) as { status: string }
        status = data.status
      } else {
        const res = await fetch(`${apiBaseUrl}/agent/hybrid-request/${hybridRequestId}/status`, {
          headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        })
        if (!res.ok) continue
        const data = (await res.json()) as { status: string }
        status = data.status
      }

      if (status === 'submitted') {
        // Step 1 — quick notify so the user immediately sees a single
        // WhatsApp message: "✅ Authorization complete, filling the
        // form now." This lands BEFORE the agent does any tool calls.
        await deliverWithRetry(
          `[RIVAULT_HYBRID_NOTIFY] Approval detected. Send the user EXACTLY ` +
          `this message and end your response immediately (do not call any ` +
          `other tools yet): "✅ Authorization complete — filling the form now."`,
        )

        // Brief pause so OpenClaw flushes turn 1 to WhatsApp before we
        // queue turn 2. Without this the two messages bundle together
        // and the "approval complete" notification arrives at the same
        // time as the final result, defeating the whole point.
        await new Promise<void>(resolve => setTimeout(resolve, 4_000))

        // Step 2 — actually deliver the work message.
        await deliverWithRetry(
          `[RIVAULT_HYBRID_SUBMITTED] hybridRequestId=${hybridRequestId}\n\n` +
          `The user submitted form data and authorized access to stored items. ` +
          `Call rivault_poll_hybrid with hybrid_request_id="${hybridRequestId}" ` +
          `to retrieve all values and complete the original task. After ` +
          `success tell the user: "Done — [one-sentence summary]."`,
        )
        process.exit(0)
      }

      if (status === 'expired') {
        await deliverWithRetry(
          `[RIVAULT_HYBRID_EXPIRED] hybridRequestId=${hybridRequestId}\n\n` +
          `The authorization link expired before the user submitted. ` +
          `Tell the user it expired and offer to send a fresh link with ` +
          `rivault_request_hybrid using the same item ids.`,
        )
        process.exit(0)
      }
    } catch {
      // Network error — keep polling
    }
  }

  process.exit(0)
}

poll()
