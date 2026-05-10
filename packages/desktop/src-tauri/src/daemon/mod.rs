//! Daemon core: release listener, file watcher, scrub engine, ledger orchestration.
//!
//! Receives release events from the three IPC channels, watches allowlisted
//! transcript paths, dispatches scrubs when a trigger fires, and records
//! everything in the local ledger.

pub mod allowlist;
pub mod cross_runtime_scanner;
pub mod orchestrator;
pub mod recent_index;
pub mod release;
pub mod watcher;

pub use orchestrator::Daemon;
