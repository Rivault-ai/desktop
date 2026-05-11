import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

export function createPollHybridTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_poll_hybrid',
    description:
      '[USE THIS TOOL — DO NOT FALL BACK TO BASH CURL] Retrieve decrypted values from a submitted hybrid request. Call this after receiving a [RIVAULT_HYBRID_SUBMITTED] callback from the background poller. Returns both collected form values and authorized vault values, already decrypted by the daemon. ' +
      'PLUGIN IS HEALTHY (v0.2.6+): retries on timeout 3x with backoff. Daemon Content-Length response bug is FIXED. If this tool returns an error twice in a row from FRESH attempts (not session memory), tell the user the plugin is failing and stop — do NOT silently fall back to bash curl, which bypasses the daemon and skips ledger logging + transcript redaction.',
    parameters: {
      type: 'object',
      properties: {
        hybrid_request_id: {
          type: 'string',
          description: 'The hybridRequestId returned by rivault_request_hybrid',
        },
      },
      required: ['hybrid_request_id'],
    },
    async execute(params): Promise<ToolResult> {
      const hybridRequestId = params.hybrid_request_id as string

      try {
        const result = await client.pollHybrid(hybridRequestId)

        switch (result.status) {
          case 'pending':
            return textResult(
              `Hybrid request is pending. The user has not yet submitted. Continue polling every 8-10 seconds.`,
            )

          case 'submitted': {
            const parts: string[] = [
              `The user has completed the hybrid request.`,
            ]

            if (result.formValues && Object.keys(result.formValues).length > 0) {
              parts.push(`\nForm values collected:`)
              for (const [key, value] of Object.entries(result.formValues)) {
                parts.push(`  vault:form:${key}=${value}`)
              }
            }

            if (result.authorizedValues && Object.keys(result.authorizedValues).length > 0) {
              parts.push(`\nAuthorized vault values:`)
              for (const [itemId, value] of Object.entries(result.authorizedValues)) {
                parts.push(`  vault:auth:${itemId}=${value}`)
              }
            }

            if (result.createdItemIds && result.createdItemIds.length > 0) {
              parts.push(`\nNew vault items created: ${result.createdItemIds.join(', ')}`)
            }

            parts.push(
              `\n[SENSITIVE] Use these values directly in the required operation. Do not display, echo, repeat, or store them.`,
            )

            return textResult(parts.join('\n'))
          }

          case 'expired':
            return textResult(
              `The hybrid request has expired. If you still need this information, create a new hybrid request using rivault_request_hybrid.`,
            )

          default:
            return textResult(`Unknown hybrid status: ${result.status}`)
        }
      } catch (err) {
        return textResult(
          `Failed to check hybrid status: ${err instanceof Error ? err.message : 'Unknown error'}`,
        )
      }
    },
  }
}
