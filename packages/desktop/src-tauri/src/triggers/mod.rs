//! Trigger chain — first to fire wins.
//!
//! - `stop_signal`: ~1s — `stop_reason: "end_turn"` (Claude Code, OpenClaw,
//!   Claude Desktop) or `finish_reason: "stop"` (Codex CLI), parsed from
//!   transcript JSONL append events
//! - `tool_call`: ~5s — per-tool-call write detection; scrub V from the tool
//!   input line after the consuming tool call completes
//! - `process_watcher`: ~2min — agent process exit / MCP disconnect
//! - `hard_cap`: 15min — last-resort timer from release time
//!
//! On all-trigger failure, the catastrophic fail-safe is upstream credential
//! rotation (only for credential types where Rivault has rotation integration).

pub mod hard_cap;
pub mod process_watcher;
pub mod stop_signal;
pub mod tool_call;

pub const HARD_CAP_SECONDS: u64 = 15 * 60;
