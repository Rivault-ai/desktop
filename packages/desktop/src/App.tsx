import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Setup from "./Setup";
import "./App.css";

type Tier = "l1" | "l2";
type AgentRuntime =
  | "claude-code"
  | "openclaw"
  | "claude-desktop"
  | "codex"
  | "custom";
type Channel = "ipc" | "localhost" | "websocket";

interface LedgerEntry {
  release_id: string;
  session_id: string;
  value_hash: string;
  tier: Tier;
  agent_runtime: AgentRuntime;
  mcp_mode: string | null;
  channel: Channel;
  plaintext_seen_locally: boolean;
  transcript_paths: string[];
  released_at: string;
  scrubbed_at: string | null;
  rotated_at: string | null;
  trigger_that_fired: string | null;
  scrub_verified: boolean;
}

interface DaemonStatus {
  socket_path: string;
  http_port: number | null;
  browser_token_prefix: string;
  websocket_configured: boolean;
}

interface ConfigStatus {
  configured: boolean;
  user_id: string | null;
  api_key_masked: string | null;
  base_url: string | null;
}

function statusOf(e: LedgerEntry): { label: string; color: string } {
  if (e.scrubbed_at && e.scrub_verified)
    return { label: "scrubbed", color: "#16a34a" };
  if (e.scrubbed_at && !e.scrub_verified)
    return { label: "unverified", color: "#f97316" };
  if (e.rotated_at) return { label: "rotated", color: "#a855f7" };
  return { label: "open", color: "#facc15" };
}

function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleTimeString();
  } catch {
    return iso;
  }
}

export default function App() {
  const [status, setStatus] = useState<DaemonStatus | null>(null);
  const [releases, setReleases] = useState<LedgerEntry[]>([]);
  const [config, setConfig] = useState<ConfigStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const [s, r, c] = await Promise.all([
          invoke<DaemonStatus>("daemon_status"),
          invoke<LedgerEntry[]>("list_releases", { limit: 100 }),
          invoke<ConfigStatus>("get_config_status"),
        ]);
        if (!cancelled) {
          setStatus(s);
          setReleases(r);
          setConfig(c);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
    };
    tick();
    const id = window.setInterval(tick, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  // Wait for first config probe before rendering — avoids flashing the
  // dashboard for a beat before flipping to the setup screen.
  if (config === null) {
    return <div className="app boot" />;
  }

  if (!config.configured) {
    return (
      <Setup
        onConfigured={async () => {
          const c = await invoke<ConfigStatus>("get_config_status");
          setConfig(c);
        }}
      />
    );
  }

  const open = releases.filter((r) => !r.scrubbed_at).length;
  const scrubbed = releases.filter((r) => r.scrubbed_at).length;

  return (
    <div className="app">
      <header>
        <div className="header-row">
          <h1>Rivault</h1>
          {config.user_id && (
            <div className="header-identity">
              <code>{config.api_key_masked}</code>
              <button
                className="link"
                onClick={async () => {
                  await invoke("clear_config");
                  const c = await invoke<ConfigStatus>("get_config_status");
                  setConfig(c);
                }}
              >
                Sign out
              </button>
            </div>
          )}
        </div>
        <p className="subtitle">
          Deterministic local plaintext redaction for AI agent transcripts.
        </p>
      </header>

      <section className="status">
        <div>
          <span className="label">Unix socket</span>
          <code>{status?.socket_path ?? "…"}</code>
        </div>
        <div>
          <span className="label">Localhost HTTP</span>
          <code>{status?.http_port ? `127.0.0.1:${status.http_port}` : "—"}</code>
        </div>
        <div>
          <span className="label">Browser token (prefix)</span>
          <code>{status?.browser_token_prefix ?? "…"}…</code>
        </div>
        <div>
          <span className="label">WebSocket channel</span>
          <code>{status?.websocket_configured ? "configured" : "off"}</code>
        </div>
      </section>

      <section className="counts">
        <div className="count">
          <span className="num">{open}</span>
          <span className="cap">open</span>
        </div>
        <div className="count">
          <span className="num">{scrubbed}</span>
          <span className="cap">scrubbed</span>
        </div>
      </section>

      {error && <div className="error">{error}</div>}

      <section className="releases">
        <h2>Recent releases</h2>
        {releases.length === 0 ? (
          <p className="empty">No release events yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Released</th>
                <th>Tier</th>
                <th>Runtime</th>
                <th>Channel</th>
                <th>Trigger</th>
                <th>Release ID</th>
              </tr>
            </thead>
            <tbody>
              {releases.map((r) => {
                const s = statusOf(r);
                return (
                  <tr key={r.release_id}>
                    <td>
                      <span className="dot" style={{ background: s.color }} />
                      {s.label}
                    </td>
                    <td>{fmtTime(r.released_at)}</td>
                    <td>{r.tier.toUpperCase()}</td>
                    <td>{r.agent_runtime}</td>
                    <td>{r.channel}</td>
                    <td>{r.trigger_that_fired ?? "—"}</td>
                    <td className="mono">{r.release_id}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
