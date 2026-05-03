import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Props {
  onConfigured: () => void;
  initialBaseUrl?: string;
}

export default function Setup({ onConfigured, initialBaseUrl }: Props) {
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState(
    initialBaseUrl ?? "https://api.rivault.ai"
  );
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await invoke("save_config", {
        apiKey: apiKey.trim(),
        baseUrl: baseUrl.trim() || null,
      });
      onConfigured();
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="setup">
      <div className="setup-card">
        <h1>Welcome to Rivault</h1>
        <p className="setup-blurb">
          The local daemon is running. Paste your API key to wire this Mac to
          your vault — your agents can then retrieve secrets and the daemon
          will scrub them from transcripts after every task.
        </p>

        <form onSubmit={submit}>
          <label>
            <span>API key</span>
            <input
              type="password"
              value={apiKey}
              placeholder="rv_live_…"
              onChange={(e) => setApiKey(e.target.value)}
              autoFocus
              autoComplete="off"
              spellCheck={false}
              disabled={submitting}
            />
          </label>

          <button
            type="button"
            className="link"
            onClick={() => setShowAdvanced((v) => !v)}
          >
            {showAdvanced ? "Hide advanced" : "Advanced"}
          </button>

          {showAdvanced && (
            <label>
              <span>API base URL</span>
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                disabled={submitting}
                spellCheck={false}
              />
            </label>
          )}

          {error && <div className="setup-error">{error}</div>}

          <div className="setup-actions">
            <button type="submit" disabled={submitting || !apiKey.trim()}>
              {submitting ? "Verifying…" : "Connect"}
            </button>
            <a
              href="https://rivault.ai"
              target="_blank"
              rel="noreferrer"
              className="muted"
            >
              Get an API key →
            </a>
          </div>
        </form>

        <p className="setup-foot">
          Your key never leaves this Mac except to call your own Rivault API.
          Stored at <code>~/Library/Application Support/Rivault/config.json</code>{" "}
          (mode 0600).
        </p>
      </div>
    </div>
  );
}
