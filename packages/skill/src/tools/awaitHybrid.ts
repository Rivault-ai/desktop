import type { Tool, ToolResult } from './types.js'
import { textResult } from './types.js'
import type { RivaultClient } from '../client.js'

const POLL_INITIAL_MS = 3_000
const POLL_MAX_MS = 8_000
const TIMEOUT_MS = 180_000

export function createAwaitHybridTool(client: RivaultClient): Tool {
  return {
    name: 'rivault_await_hybrid',
    description:
      'Wait for the user to submit a combined authorization + form request, polling in-process with 3-8s backoff for up to 3 minutes. Call this IMMEDIATELY after rivault_request_hybrid — do not end your response, do not poll manually, do not call any other tools first. Returns the submitted values as soon as the user completes the form, or status=expired if they run out of time.',
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
      const start = Date.now()
      let interval = POLL_INITIAL_MS

      while (Date.now() - start < TIMEOUT_MS) {
        try {
          const result = await client.pollHybrid(hybridRequestId)
          if (result.status === 'pending') {
            await sleep(interval)
            if (interval < POLL_MAX_MS) interval += 1_000
            continue
          }
          if (result.status === 'submitted') {
            const parts: string[] = [`The user has completed the hybrid request.`]
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
          if (result.status === 'expired') {
            return textResult(
              `The hybrid request has expired. If you still need this information, create a new request with rivault_request_hybrid.`,
            )
          }
          return textResult(`Unknown hybrid status: ${result.status}`)
        } catch (err) {
          await sleep(interval)
          if (interval < POLL_MAX_MS) interval += 1_000
        }
      }
      return textResult(
        `Hybrid request timed out after ${Math.round(TIMEOUT_MS / 1000)}s without submission. ` +
          `If the user still wants to proceed, call rivault_request_hybrid again to send a fresh link.`,
      )
    },
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
