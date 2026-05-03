import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

export function createPollFormTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_poll_form',
    description: 'Check if the user has submitted the form with the requested information. Poll every 5-10 seconds after sending the form URL. When submitted, use the returned item_id with rivault_get_secret or rivault_request_auth.',
    parameters: {
      type: 'object',
      properties: {
        form_request_id: {
          type: 'string',
          description: 'The formRequestId returned by rivault_request_form',
        },
      },
      required: ['form_request_id'],
    },
    async execute(params): Promise<ToolResult> {
      const formRequestId = params.form_request_id as string

      try {
        const result = await client.pollForm(formRequestId)

        switch (result.status) {
          case 'pending':
            return textResult(`Form request is pending. The user has not yet submitted the form. Continue polling every 5-10 seconds.`)

          case 'submitted':
            if (result.itemId) {
              return textResult(
                `The user has submitted the form and saved the item to their vault.\n` +
                  `New vault item ID: ${result.itemId}\n\n` +
                  `Use this item ID with rivault_get_secret (if L1) or rivault_request_auth (if L2) to retrieve the value.`,
              )
            }
            return textResult(`The user submitted the form but chose not to save to vault. The item is not available for retrieval.`)

          case 'expired':
            return textResult(`The form request has expired. If you still need this information, create a new form request using rivault_request_form.`)

          default:
            return textResult(`Unknown form status: ${result.status}`)
        }
      } catch (err) {
        return textResult(`Failed to check form status: ${err instanceof Error ? err.message : 'Unknown error'}`)
      }
    },
  }
}
