export const config = {
  get apiKey(): string {
    return process.env.RIVAULT_API_KEY ?? ''
  },
  get apiBaseUrl(): string {
    return process.env.RIVAULT_API_URL ?? 'https://api.rivault.ai'
  },
}

export function validateConfig(): void {
  if (!config.apiKey) {
    throw new Error('[Rivault] RIVAULT_API_KEY environment variable is required. Set it in ~/.openclaw/openclaw.json under skills.entries.rivault.env.RIVAULT_API_KEY')
  }
}
