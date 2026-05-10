import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

export function createRequestHybridTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_request_hybrid',
    description:
      'Request a combined authorization + data collection page. Use when the user\'s vault has SOME of the needed data (requiring authorization) but is also MISSING other data that must be collected via form fields. Creates a single hybrid link where the user can authorize stored items AND provide missing details in one step. ' +
      'MANDATORY NEXT STEP: send the hybrid_url to the user in chat, then IMMEDIATELY call rivault_await_hybrid in the same response with hybrid_request_id. ' +
      'Do NOT end your response. Do NOT call any other tools first. The await tool blocks in-process until the user submits.',
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

      try {
        const result = await client.requestHybrid(formFields, authItemIds, reason)

        return textResult(
          `Hybrid request created.\n\n` +
            `Hybrid Request ID: ${result.hybridRequestId}\n\n` +
            `Send this EXACT message to the user (do not paraphrase):\n${result.agentMessage}\n\n` +
            `MANDATORY NEXT STEP: call rivault_await_hybrid NOW with hybrid_request_id="${result.hybridRequestId}". ` +
            `It blocks in-process until the user submits and returns the values directly. Do not end your response.`,
        )
      } catch (err) {
        return textResult(
          `Failed to create hybrid request: ${err instanceof Error ? err.message : 'Unknown error'}`,
        )
      }
    },
  }
}
