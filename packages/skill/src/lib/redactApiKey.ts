/**
 * Render an API key safely for diagnostic logs.
 *
 * Real keys look like `rv_live_<64 random hex chars>`. The first 8 chars
 * are the brand-public prefix and carry no entropy; logging just that
 * lets operators correlate poller logs to the key that produced them
 * without leaking any of the random suffix. Returns `EMPTY` when the
 * caller has no key — same convention the previous inlined snippet used.
 */
export function redactApiKey(apiKey: string | undefined | null): string {
  if (!apiKey) return 'EMPTY'
  return apiKey.substring(0, 8) + '\u2026'
}
