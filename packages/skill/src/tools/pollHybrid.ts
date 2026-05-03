import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'
import { emitRelease } from '../lib/daemonEmit.js'

export function createPollHybridTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_poll_hybrid',
    description:
      'Check the status of a pending hybrid request (combined authorization + form). Poll every 8-10 seconds after sending the hybrid URL. When submitted, returns both collected form values and authorized vault values.',
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
              const identity = await client.identityCached()
              for (const [itemId, value] of Object.entries(result.authorizedValues)) {
                parts.push(`  vault:auth:${itemId}=${value}`)
                if (identity) {
                  await emitRelease({
                    userId: identity.userId,
                    apiKeyId: identity.apiKeyId ?? '',
                    itemId,
                    tier: 'L2',
                    plaintext: value,
                  })
                }
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
