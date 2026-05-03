import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

export function createSearchTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_check',
    description: 'Check if a specific piece of information exists in the user\'s Rivault vault. Query one field at a time (e.g., "email", "phone number"). Returns whether it exists and its item ID — does NOT list or browse vault contents.',
    parameters: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'The specific item to check for (e.g. "email", "phone number", "home address")',
        },
      },
      required: ['query'],
    },
    async execute(params): Promise<ToolResult> {
      const query = params.query as string

      try {
        const result = await client.search(query)

        if (result.results.length === 0) {
          return textResult(`"${query}" is not available in the vault. Use rivault_request_form to ask the user to provide this information.`)
        }

        const match = result.results[0]
        if (match.sensitivityLevel === 1) {
          return textResult(`"${query}" is available (item ID: ${match.id}). Use rivault_get_secret with this item_id to retrieve it.`)
        }
        return textResult(`"${query}" is available but requires Face ID authorization (item ID: ${match.id}). Use rivault_request_auth with this item_id to request access.`)
      } catch (err) {
        return textResult(`Failed to check vault: ${err instanceof Error ? err.message : 'Unknown error'}`)
      }
    },
  }
}
