export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>
}

export interface Tool {
  name: string
  description: string
  parameters: {
    type: 'object'
    properties: Record<string, unknown>
    required?: string[]
  }
  execute(params: Record<string, unknown>): Promise<ToolResult>
}

export function textResult(text: string): ToolResult {
  return { content: [{ type: 'text', text }] }
}
