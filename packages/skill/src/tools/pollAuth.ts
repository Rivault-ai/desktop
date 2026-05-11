import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

export function createPollAuthTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_poll_auth',
    description: '[USE THIS TOOL — DO NOT FALL BACK TO BASH CURL] Retrieve the decrypted value for an approved auth request. Call this after receiving a [RIVAULT_APPROVED] callback. PLUGIN IS HEALTHY (v0.2.6+): retries on timeout 3x. Bash fallback bypasses the daemon — no ledger row, no transcript redaction.',
    parameters: {
      type: 'object',
      properties: {
        auth_request_id: {
          type: 'string',
          description: 'The authRequestId returned by rivault_request_auth',
        },
        item_id: {
          type: 'string',
          description: 'The vault item ID originally passed to rivault_request_auth. Required to fetch the value after approval.',
        },
      },
      required: ['auth_request_id'],
    },
    async execute(params): Promise<ToolResult> {
      const authRequestId = params.auth_request_id as string
      const itemId = params.item_id as string | undefined

      try {
        const result = await client.pollAuth(authRequestId)

        switch (result.status) {
          case 'pending':
            return textResult(`Authorization request is pending. The user has not yet approved. Continue polling every 5-10 seconds.`)

          case 'approved': {
            // If the poll response includes the value inline, use it directly.
            if (result.value) {
              return textResult(
                `vault:approved=${result.value}\n` +
                `[SENSITIVE] Use this value directly in the required operation. Do not display, echo, repeat, or store it.`
              )
            }
            // Value not in Redis — client-side decryption failed during authorization.
            // rivault_get_secret does NOT work for L1/L2 items — do not call it.
            // Re-request authorization so the user can retry (the new link will auto-trigger).
            if (itemId) {
              return textResult(
                `vault:no_value item_id=${itemId}\n` +
                `Authorization approved but the vault value was not delivered (client-side decryption failed on user's device). ` +
                `Call rivault_request_auth with item_id="${itemId}" to send a new authorization link. ` +
                `Tell the user: "I need you to authorize one more time — the link will open automatically."`
              )
            }
            return textResult(
              `Authorization approved but the vault value was not delivered (client-side decryption failed). ` +
              `You need the original item_id to retry. Check the [RIVAULT_APPROVED] message for item_id and call rivault_request_auth again.`
            )
          }

          case 'denied':
            return textResult(`The user denied the authorization request. You cannot access this vault item. Inform the user that you cannot complete the task without this information.`)

          case 'expired':
            return textResult(`The authorization request has expired. If you still need this information, create a new authorization request using rivault_request_auth.`)

          default:
            return textResult(`Unknown authorization status: ${result.status}`)
        }
      } catch (err) {
        return textResult(`Failed to check authorization status: ${err instanceof Error ? err.message : 'Unknown error'}`)
      }
    },
  }
}
