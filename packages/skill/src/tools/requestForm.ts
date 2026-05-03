import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

export function createRequestFormTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_request_form',
    description: 'Request the user to provide a new secret via a secure form link. Use when rivault_search finds no matching items. The form allows the user to save the item to their vault for future use. After calling this, send the form_url to the user, then poll rivault_poll_form.',
    parameters: {
      type: 'object',
      properties: {
        requested_label: {
          type: 'string',
          description: 'Human-readable name for what you need (e.g. "Home Address", "GitHub API Key", "Credit Card Number")',
        },
        requested_category: {
          type: 'string',
          enum: ['identity', 'payment', 'api_key', 'password', 'preference', 'other'],
          description: 'Category of the requested item',
        },
        reason: {
          type: 'string',
          description: 'Brief explanation of why you need this (shown to user on the form page)',
        },
      },
      required: ['requested_label', 'requested_category'],
    },
    async execute(params): Promise<ToolResult> {
      const requestedLabel = params.requested_label as string
      const requestedCategory = params.requested_category as string
      const reason = params.reason as string | undefined
      const callbackSessionId = process.env.RIVAULT_OPENCLAW_SESSION_ID

      try {
        const result = await client.requestForm(requestedLabel, requestedCategory, reason, callbackSessionId)

        const callbackEnabled = !!callbackSessionId

        return textResult(
          `Form request created for "${requestedLabel}".\n\n` +
            `Form Request ID: ${result.formRequestId}\n\n` +
            `Send this EXACT message to the user (do not paraphrase):\n${result.agentMessage}\n\n` +
            `IMMEDIATELY after sending that message, call rivault_poll_form with:\n` +
            `  form_request_id: "${result.formRequestId}"\n\n` +
            `Poll every 8-10 seconds. Do NOT wait for user input. Do NOT end your response. ` +
            `Keep polling silently until status is submitted or expired. ` +
            `When submitted, the item_id is returned — retrieve the value and complete the task.`,
        )
      } catch (err) {
        return textResult(`Failed to create form request: ${err instanceof Error ? err.message : 'Unknown error'}`)
      }
    },
  }
}
