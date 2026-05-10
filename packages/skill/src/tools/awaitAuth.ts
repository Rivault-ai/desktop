import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

const POLL_INITIAL_MS = 3_000
const POLL_MAX_MS = 8_000
const TIMEOUT_MS = 180_000

export function createAwaitAuthTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_await_auth',
    description:
      'Wait for the user to approve a Face ID authorization request, polling in-process with 3-8s backoff for up to 3 minutes. Call this IMMEDIATELY after rivault_request_auth — do not end your response, do not poll manually, do not call any other tools first. Returns the vault value as soon as the user approves, or status=denied/expired if they refuse or run out of time.',
    parameters: {
      type: 'object',
      properties: {
        auth_request_id: {
          type: 'string',
          description: 'The authRequestId returned by rivault_request_auth',
        },
        item_id: {
          type: 'string',
          description: 'The vault item ID originally passed to rivault_request_auth (used as a fallback if the value is not in the poll response).',
        },
      },
      required: ['auth_request_id'],
    },
    async execute(params): Promise<ToolResult> {
      const authRequestId = params.auth_request_id as string
      const itemId = params.item_id as string | undefined
      const start = Date.now()
      let interval = POLL_INITIAL_MS

      while (Date.now() - start < TIMEOUT_MS) {
        try {
          const result = await client.pollAuth(authRequestId)
          if (result.status === 'pending') {
            await sleep(interval)
            if (interval < POLL_MAX_MS) interval += 1_000
            continue
          }
          if (result.status === 'approved') {
            if (result.value) {
              return textResult(
                `vault:approved=${result.value}\n` +
                  `[SENSITIVE] Use this value directly in the required operation. Do not display, echo, repeat, or store it.`,
              )
            }
            if (itemId) {
              return textResult(
                `vault:no_value item_id=${itemId}\n` +
                  `Authorization approved but the vault value was not delivered (client-side decryption failed on user's device). ` +
                  `Call rivault_request_auth with item_id="${itemId}" again to retry. ` +
                  `Tell the user: "I need you to authorize one more time — the link will open automatically."`,
              )
            }
            return textResult(
              `Authorization approved but the vault value was not delivered. ` +
                `Re-request authorization with the original item_id.`,
            )
          }
          if (result.status === 'denied') {
            return textResult(
              `The user denied the authorization request. Inform the user you cannot complete the task without this information.`,
            )
          }
          if (result.status === 'expired') {
            return textResult(
              `The authorization request has expired. If you still need this information, create a new request with rivault_request_auth.`,
            )
          }
          return textResult(`Unknown authorization status: ${result.status}`)
        } catch (err) {
          // Transient errors: keep polling.
          await sleep(interval)
          if (interval < POLL_MAX_MS) interval += 1_000
        }
      }
      return textResult(
        `Authorization timed out after ${Math.round(TIMEOUT_MS / 1000)}s without approval. ` +
          `If the user still wants to proceed, call rivault_request_auth again to send a fresh link.`,
      )
    },
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
