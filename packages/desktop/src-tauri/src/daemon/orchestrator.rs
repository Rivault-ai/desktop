//! Wires release events through allowlist validation, ledger insert, watcher
//! arming, trigger race, and scrub.
//!
//! On every release event:
//! 1. Validate every transcript path against the runtime's allowlist
//! 2. Insert ledger row (open: scrubbed_at NULL)
//! 3. Build needles (plaintext + variants, when permitted by the path)
//! 4. Race a stop-signal watcher against the 15-min hard cap
//! 5. First fire wins → run scrubber → mark ledger scrubbed
//! 6. On verify failure (or out-of-band rotation flag) → enqueue rotation

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::oneshot;

use crate::daemon::allowlist;
use crate::daemon::release::ReleaseEvent;
use crate::daemon::watcher::watch_for_stop;
use crate::ledger::{Channel, Ledger, LedgerEntry};
use crate::scrubber::{build_needles, scrub_paths};
use crate::triggers::HARD_CAP_SECONDS;

#[derive(Clone)]
pub struct Daemon {
    ledger: Ledger,
}

impl Daemon {
    pub fn new(ledger: Ledger) -> Self {
        Self { ledger }
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Accept a release event from any IPC channel. Returns Ok(release_id)
    /// once the release has been validated and persisted; the actual scrub
    /// runs as a background task.
    pub fn accept(self: &Arc<Self>, event: ReleaseEvent, channel: Channel) -> Result<String> {
        let validated = self.validate(&event)?;

        // Snapshot file size at release time. The scrubber later confines its
        // edits to bytes written after this point so existing pre-release
        // content (and the user's older saves) stay byte-identical.
        let mut transcript_offsets: HashMap<String, u64> = HashMap::new();
        for path in &validated {
            let key = path.display().to_string();
            match std::fs::metadata(path) {
                Ok(meta) => {
                    transcript_offsets.insert(key, meta.len());
                }
                Err(_) => {
                    // File doesn't exist yet — treat as offset 0 so the
                    // entire file is in the task window when it's created.
                    transcript_offsets.insert(key, 0);
                }
            }
        }

        let entry = LedgerEntry {
            release_id: event.release_id.clone(),
            session_id: event.session_id.clone(),
            value_hash: event.value_hash.clone(),
            tier: event.tier.clone(),
            agent_runtime: event.agent_runtime.clone(),
            mcp_mode: event.mcp_mode.clone(),
            channel,
            plaintext_seen_locally: event.value_plaintext.is_some(),
            transcript_paths: validated.iter().map(|p| p.display().to_string()).collect(),
            transcript_offsets: transcript_offsets.clone(),
            released_at: event.released_at.clone(),
            scrubbed_at: None,
            rotated_at: None,
            trigger_that_fired: None,
            scrub_verified: false,
        };
        self.ledger.insert(&entry).context("ledger insert")?;

        let needles = build_needles(
            event.value_plaintext.as_deref(),
            &event.encoded_variants,
        );

        if needles.is_empty() {
            tracing::warn!(
                release_id = %event.release_id,
                "no needles built (true-E2E with no variants); hash-content scan not yet implemented"
            );
        }

        let me = Arc::clone(self);
        let release_id = event.release_id.clone();
        let paths = validated.clone();
        let rotation_supported = event.rotation_supported;

        tokio::spawn(async move {
            if let Err(e) = me
                .run_lifecycle(release_id, paths, needles, transcript_offsets, rotation_supported)
                .await
            {
                tracing::error!("release lifecycle: {e:#}");
            }
        });

        Ok(event.release_id)
    }

    fn validate(&self, event: &ReleaseEvent) -> Result<Vec<PathBuf>> {
        let mut out = Vec::with_capacity(event.transcript_paths.len());
        for p in &event.transcript_paths {
            let resolved = allowlist::validate_path(&event.agent_runtime, p)
                .with_context(|| format!("allowlist reject: {p}"))?;
            out.push(resolved);
        }
        Ok(out)
    }

    async fn run_lifecycle(
        self: Arc<Self>,
        release_id: String,
        paths: Vec<PathBuf>,
        needles: Vec<String>,
        offsets: HashMap<String, u64>,
        rotation_supported: bool,
    ) -> Result<()> {
        let watcher_rx = if !paths.is_empty() {
            match watch_for_stop(paths.clone()) {
                Ok(rx) => Some(rx),
                Err(e) => {
                    tracing::warn!("watcher arm failed: {e:#}");
                    None
                }
            }
        } else {
            None
        };

        let trigger = race_triggers(watcher_rx).await;

        let path_strs: Vec<String> =
            paths.iter().map(|p| p.display().to_string()).collect();

        let scrub_outcome = if needles.is_empty() {
            ScrubOutcome::Skipped
        } else {
            match scrub_paths(&path_strs, &needles, &offsets) {
                Ok(report) => {
                    if report.verified {
                        ScrubOutcome::Verified
                    } else {
                        ScrubOutcome::Unverified
                    }
                }
                Err(e) => {
                    tracing::error!("scrub failed for {release_id}: {e:#}");
                    ScrubOutcome::Failed
                }
            }
        };

        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::new());

        let verified = matches!(scrub_outcome, ScrubOutcome::Verified);
        self.ledger
            .mark_scrubbed(&release_id, &now, trigger.as_str(), verified)?;

        if !verified && rotation_supported {
            tracing::warn!(release_id = %release_id, "scrub unverified; enqueueing rotation");
            self.ledger.mark_rotated(&release_id, &now)?;
        }

        Ok(())
    }

    /// On daemon start, re-enqueue any release whose row remains unscrubbed.
    /// Each gets a fresh hard-cap window — the scrub will fire either when
    /// the agent emits a late stop signal or when the timer expires.
    pub fn recover_unscrubbed(self: &Arc<Self>) -> Result<()> {
        let open = self.ledger.list_unscrubbed()?;
        for entry in open {
            tracing::info!("re-enqueuing orphaned release {}", entry.release_id);
            let needles: Vec<String> = Vec::new();
            let paths: Vec<PathBuf> =
                entry.transcript_paths.iter().map(PathBuf::from).collect();
            let offsets = entry.transcript_offsets.clone();
            let me = Arc::clone(self);
            tokio::spawn(async move {
                let _ = me
                    .run_lifecycle(entry.release_id, paths, needles, offsets, false)
                    .await;
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum Trigger {
    StopSignal,
    HardCap,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Trigger::StopSignal => "stop_signal",
            Trigger::HardCap => "hard_cap",
        }
    }
}

enum ScrubOutcome {
    Verified,
    Unverified,
    Failed,
    Skipped,
}

async fn race_triggers(stop_rx: Option<oneshot::Receiver<()>>) -> Trigger {
    let hard_cap = tokio::time::sleep(std::time::Duration::from_secs(HARD_CAP_SECONDS));
    tokio::pin!(hard_cap);

    match stop_rx {
        Some(rx) => tokio::select! {
            _ = rx => Trigger::StopSignal,
            _ = &mut hard_cap => Trigger::HardCap,
        },
        None => {
            (&mut hard_cap).await;
            Trigger::HardCap
        }
    }
}
