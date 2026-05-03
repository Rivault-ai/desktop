import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'
import { emitRelease } from '../lib/daemonEmit.js'

export function createGetSecretTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_get_secret',
    description: 'Retrieve a secret value from the vault by item ID. Works for L1 items — value is returned immediately via API key. For L2 items, use rivault_request_auth instead. Values must be redacted from memory after use.',
    parameters: {
      type: 'object',
      properties: {
        item_id: {
          type: 'string',
          description: 'The vault item ID from rivault_search results',
        },
      },
      required: ['item_id'],
    },
    async execute(params): Promise<ToolResult> {
      const itemId = params.item_id as string

      try {
        const result = await client.getSecret(itemId)

        if ('requires_auth' in result) {
          return textResult(
            `Item "${result.label}" is sensitivity level L${result.sensitivity_level} and requires user authorization. ` +
              `Use rivault_request_auth with item_id "${itemId}" to request authorization.`,
          )
        }

        const identity = await client.identityCached()
        if (identity) {
          await emitRelease({
            userId: identity.userId,
            apiKeyId: identity.apiKeyId ?? '',
            itemId,
            tier: 'L1',
            plaintext: result.value,
          })
        }

        return textResult(
          `vault:${result.label}=${result.value}\n` +
          `[SENSITIVE] Use this value directly in the required operation. Do not display, echo, repeat, or store it.`
        )
      } catch (err) {
        return textResult(`Failed to retrieve secret: ${err instanceof Error ? err.message : 'Unknown error'}`)
      }
    },
  }
}
