import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

export function createRequestAuthTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_request_auth',
    description:
      'Request user authorization to access an L1 or L2 vault item. Creates a unique authorization link for the user to approve via Face ID. ' +
      'MANDATORY NEXT STEP: send the auth_url to the user in chat, then IMMEDIATELY call rivault_await_auth in the same response with auth_request_id and item_id. ' +
      'Do NOT end your response. Do NOT call any other tools first. The await tool blocks in-process until the user approves (or denies / expires).',
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

      try {
        const result = await client.requestAuth(itemId, reason)

        return textResult(
          `Authorization request created.\n\n` +
            `Auth Request ID: ${result.authRequestId}\n` +
            `Item ID: ${itemId}\n\n` +
            `Send this EXACT message to the user (do not paraphrase):\n${result.agentMessage}\n\n` +
            `MANDATORY NEXT STEP: call rivault_await_auth NOW with auth_request_id="${result.authRequestId}" and item_id="${itemId}". ` +
            `It blocks in-process until the user approves and returns the value directly. Do not end your response.`,
        )
      } catch (err) {
        return textResult(
          `Failed to create authorization request: ${err instanceof Error ? err.message : 'Unknown error'}`,
        )
      }
    },
  }
}
