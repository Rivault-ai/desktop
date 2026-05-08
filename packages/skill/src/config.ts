import { discoverDaemonUrl } from './lib/discovery.js'

export const config = {
  get apiKey(): string {
    return process.env.RIVAULT_API_KEY ?? ''
  },
  /**
   * Resolve the API base URL with a four-step precedence:
   *   1. `RIVAULT_API_URL` env var — explicit user override.
   *   2. Daemon discovery file (`~/Library/Application Support/Rivault/daemon.json`)
   *      — auto-routes through the local daemon when it's running so
   *      releases get observed and transcripts get scrubbed.
   *   3. `https://api.rivault.ai` — public API fallback.
   *
   * Auto-discovery means the user doesn't need to edit `openclaw.json`
   * (whose schema rejects unknown keys) or remember to export an env
   * var. Install the daemon → next plugin tool call routes through it.
   */
  get apiBaseUrl(): string {
    if (process.env.RIVAULT_API_URL) return process.env.RIVAULT_API_URL
    const daemon = discoverDaemonUrl()
    if (daemon) return daemon
    return 'https://api.rivault.ai'
  },
}

export function validateConfig(): void {
  if (!config.apiKey) {
    throw new Error('[Rivault] RIVAULT_API_KEY environment variable is required. Set it in ~/.openclaw/openclaw.json under skills.entries.rivault.env.RIVAULT_API_KEY')
  }
}
