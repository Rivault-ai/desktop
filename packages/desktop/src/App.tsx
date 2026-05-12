import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import Setup from "./Setup";
import rivaultLogo from "./assets/rivault-logo-wide.svg";
import "./App.css";

const VAULT_URL = "https://www.rivault.ai/dashboard";

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
  imported_from_openclaw: boolean;
}

// Build-time metadata injected by Vite (see vite.config.ts). These are
// string literals at runtime, so they survive minification and dead-code
// elimination. Allows the user to identify exactly which build is running
// without having to dig into the macOS package info.
const APP_VERSION = (import.meta as { env: Record<string, string> }).env
  .VITE_APP_VERSION;
const APP_GIT_SHA = (import.meta as { env: Record<string, string> }).env
  .VITE_APP_GIT_SHA;
const APP_BUILT_AT = (import.meta as { env: Record<string, string> }).env
  .VITE_APP_BUILT_AT;

function statusOf(e: LedgerEntry): { label: string; color: string } {
  if (e.scrubbed_at && e.scrub_verified)
    return { label: "redacted", color: "#16a34a" };
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

const PAGE_SIZE = 20;

export default function App() {
  const [status, setStatus] = useState<DaemonStatus | null>(null);
  const [releases, setReleases] = useState<LedgerEntry[]>([]);
  const [config, setConfig] = useState<ConfigStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [toast, setToast] = useState<string | null>(null);

  // Auto-import toast: fires once when the daemon imported an OpenClaw key at startup.
  useEffect(() => {
    if (config?.imported_from_openclaw) {
      setToast("Connected using your OpenClaw API key");
      const t = window.setTimeout(() => setToast(null), 4500);
      return () => window.clearTimeout(t);
    }
  }, [config?.imported_from_openclaw]);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      // Each invoke is allowed to fail independently — a corrupt config
      // shouldn't blank the whole window when the daemon itself is fine.
      const [s, r, c] = await Promise.all([
        invoke<DaemonStatus>("daemon_status").catch(() => null),
        invoke<LedgerEntry[]>("list_releases", { limit: 100 }).catch(
          () => [] as LedgerEntry[],
        ),
        invoke<ConfigStatus>("get_config_status").catch(
          () => ({
            configured: false,
            user_id: null,
            api_key_masked: null,
            base_url: null,
            imported_from_openclaw: false,
          }) as ConfigStatus,
        ),
      ]);
      if (cancelled) return;
      if (s) setStatus(s);
      setReleases(r);
      setConfig(c);
      setError(null);
    };
    tick();
    const id = window.setInterval(tick, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  // Brief boot flash while the very first probe is in flight.
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

  const totalPages = Math.max(1, Math.ceil(releases.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const pageStart = safePage * PAGE_SIZE;
  const pageRows = releases.slice(pageStart, pageStart + PAGE_SIZE);

  return (
    <div className="app">
      {toast && <div className="toast">{toast}</div>}
      <header>
        <div className="header-row">
          <img src={rivaultLogo} alt="Rivault" className="header-logo" />
          {config.user_id && (
            <div className="header-identity">
              <code>{config.api_key_masked}</code>
              <button
                className="link"
                onClick={() => {
                  openUrl(VAULT_URL).catch(() => {
                    /* opener blocked — ignore */
                  });
                }}
              >
                View vault
              </button>
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
          Deterministic redaction agent of values retrieved from your Rivault vault
        </p>
      </header>

      <section className="counts">
        <div className="count">
          <span className="num">{open}</span>
          <span className="cap">open</span>
        </div>
        <div className="count">
          <span className="num">{scrubbed}</span>
          <span className="cap">redacted</span>
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
              {pageRows.map((r) => {
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
        {releases.length > PAGE_SIZE && (
          <div className="pagination">
            <button
              className="page-btn"
              onClick={() => setPage(safePage - 1)}
              disabled={safePage === 0}
            >
              ‹ Prev
            </button>
            <span className="page-info">
              {pageStart + 1}–{Math.min(pageStart + PAGE_SIZE, releases.length)} of {releases.length}
            </span>
            <button
              className="page-btn"
              onClick={() => setPage(safePage + 1)}
              disabled={safePage >= totalPages - 1}
            >
              Next ›
            </button>
          </div>
        )}
      </section>

      <details className="conn-details">
        <summary>Connection details</summary>
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
      </details>

      <BuildInfoFooter />
    </div>
  );
}

function BuildInfoFooter() {
  const [copied, setCopied] = useState(false);
  const builtAtPretty = (() => {
    try {
      return new Date(APP_BUILT_AT).toLocaleString();
    } catch {
      return APP_BUILT_AT;
    }
  })();
  const summary = `Rivault v${APP_VERSION} · ${APP_GIT_SHA} · built ${builtAtPretty}`;
  return (
    <footer
      className="build-footer"
      title="Click to copy build info — useful when filing a bug report"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(summary);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        } catch {
          /* clipboard blocked — silently no-op */
        }
      }}
    >
      <span className="build-version">v{APP_VERSION}</span>
      <span className="build-sep">·</span>
      <span className="build-sha mono">{APP_GIT_SHA}</span>
      <span className="build-sep">·</span>
      <span className="build-time">built {builtAtPretty}</span>
      {copied && <span className="build-copied">copied</span>}
    </footer>
  );
}
