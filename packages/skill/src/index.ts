import { RivaultClient } from './client.js'
import { createSearchTool } from './tools/search.js'
import { createGetSecretTool } from './tools/getSecret.js'
import { createRequestAuthTool } from './tools/requestAuth.js'
import { createPollAuthTool } from './tools/pollAuth.js'
import { createAwaitAuthTool } from './tools/awaitAuth.js'
import { createRequestFormTool } from './tools/requestForm.js'
import { createPollFormTool } from './tools/pollForm.js'
import { createRequestHybridTool } from './tools/requestHybrid.js'
import { createPollHybridTool } from './tools/pollHybrid.js'
import { createAwaitHybridTool } from './tools/awaitHybrid.js'
import type { Tool } from './tools/types.js'
import { validateConfig, config } from './config.js'

export type { Tool, ToolResult } from './tools/types.js'
export type {
  SearchResult,
  SearchResponse,
  GetSecretResponse,
  AuthRequestResponse,
  AuthStatusResponse,
  FormRequestResponse,
  FormStatusResponse,
  HybridRequestResponse,
  HybridStatusResponse,
} from './client.js'
export { RivaultClient } from './client.js'

let client: RivaultClient | null = null
let tools: Tool[] = []

export const skill = {
  name: 'rivault',
  version: '0.1.0',
  description: 'Secure vault access for AI agents via Rivault',

  initialize(options?: { apiKey?: string; apiBaseUrl?: string }): void {
    const apiKey = options?.apiKey ?? config.apiKey
    const baseUrl = options?.apiBaseUrl ?? config.apiBaseUrl

    if (!apiKey) {
      validateConfig() // throws with helpful message
    }

    client = new RivaultClient(apiKey, baseUrl)
    tools = [
      createSearchTool(client),
      createGetSecretTool(client),
      createRequestAuthTool(client),
      createPollAuthTool(client),
      createAwaitAuthTool(client),
      createRequestFormTool(client),
      createPollFormTool(client),
      createRequestHybridTool(client),
      createPollHybridTool(client),
      createAwaitHybridTool(client),
    ]
  },

  getTools(): Tool[] {
    if (!client) this.initialize()
    return tools
  },

  getTool(name: string): Tool | undefined {
    return this.getTools().find(t => t.name === name)
  },

  async executeTool(name: string, params: Record<string, unknown>) {
    const tool = this.getTool(name)
    if (!tool) throw new Error(`Unknown tool: ${name}`)
    return tool.execute(params)
  },
}

// Auto-initialize if env var is present (for direct use outside OpenClaw)
if (process.env.RIVAULT_API_KEY) {
  skill.initialize()
}

// --- OpenClaw plugin registration ---

// Marks a plain JSON schema object as a TypeBox-compatible schema so openclaw
// can accept it without requiring @sinclair/typebox as a dependency.
const TYPEBOX_KIND = Symbol.for('TypeBox.Kind')

function toTypeBoxSchema(jsonSchema: {
  type: string
  properties: Record<string, unknown>
  required?: string[]
}) {
  return { ...jsonSchema, [TYPEBOX_KIND]: 'Unsafe' }
}

type PluginCfg = { apiKey?: string; apiUrl?: string }
type OpenClawApi = {
  pluginConfig?: unknown
  registerTool: (tool: unknown, opts?: { optional?: boolean }) => void
}

export default function register(api: OpenClawApi): void {
  const cfg = (api.pluginConfig ?? {}) as PluginCfg

  // Tool definitions — name, description, schema only. No client yet.
  // The client is created lazily inside each execute() so it always picks up
  // the current API key AND base URL from pluginConfig or the environment at
  // call time, rather than snapshotting a potentially empty key or stale URL
  // at gateway startup.
  const toolFactories = [
    createSearchTool,
    createGetSecretTool,
    createRequestAuthTool,
    createPollAuthTool,
    createAwaitAuthTool,
    createRequestFormTool,
    createPollFormTool,
    createRequestHybridTool,
    createPollHybridTool,
    createAwaitHybridTool,
  ]

  // Build tool metadata from a throwaway client (key/URL don't matter here,
  // only name/description/parameters are used from these objects).
  const dummyClient = new RivaultClient('', 'https://api.rivault.ai')
  const toolMeta = toolFactories.map(f => f(dummyClient))

  for (const meta of toolMeta) {
    const label = meta.name
      .replace(/^rivault_/, '')
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c: string) => c.toUpperCase())

    api.registerTool(
      {
        name: meta.name,
        label: `Rivault: ${label}`,
        description: meta.description,
        parameters: toTypeBoxSchema(meta.parameters),
        async execute(_toolCallId: string, params: Record<string, unknown>) {
          // Read both key and URL fresh on every call. `config.apiBaseUrl`
          // performs daemon-URL discovery (~/Library/Application Support/
          // Rivault/daemon.json, 30s-cached) so if the desktop app starts
          // *after* the OpenClaw gateway, the next tool call still routes
          // through the local daemon — which is what makes ledger rows
          // and transcript scrubs work for OpenClaw end-to-end.
          const apiKey = cfg.apiKey ?? config.apiKey ?? ''
          const apiBaseUrl = cfg.apiUrl ?? config.apiBaseUrl
          const client = new RivaultClient(apiKey, apiBaseUrl)
          const tool = toolFactories
            .map(f => f(client))
            .find(t => t.name === meta.name)!
          const result = await tool.execute(params)
          return { content: result.content, details: {} }
        },
      },
      { optional: true },
    )
  }
}
