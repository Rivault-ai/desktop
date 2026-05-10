//! Stop-signal detection for transcript JSONL files.
//!
//! Different runtimes serialise the end-of-turn marker differently. We
//! accept any of the following shapes anywhere in the JSON object tree:
//! - `"stop_reason": "end_turn"` — Anthropic API snake_case (Claude Code, Claude Desktop).
//! - `"stopReason": "end_turn"` / `"endTurn"` — Anthropic API camelCase variants.
//! - `"stopReason": "stop"` — OpenClaw's emitted shape on a final assistant message
//!   (OpenClaw transcripts mix camelCase keys with the bare value `"stop"`).
//! - `"finish_reason": "stop"` — OpenAI Chat Completions (Codex CLI).
//!
//! Tool-use stop reasons (`"tool_use"`, `"toolUse"`, `"tool_calls"`) explicitly
//! do NOT signal end-of-turn — the model is mid-conversation and will keep
//! taking actions.
//!
//! The check walks any JSON value (top-level object or nested), so it tolerates
//! the various wrappers different runtimes wrap around the raw API response.

use serde_json::Value;

pub fn line_signals_stop(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
        return false;
    };
    walk(&v)
}

fn walk(v: &Value) -> bool {
    match v {
        Value::Object(map) => {
            // Anthropic snake_case + camelCase. `end_turn` / `endTurn`
            // are Anthropic's terminal values; `stop` is OpenClaw's
            // emitted form on a final assistant message.
            for key in &["stop_reason", "stopReason"] {
                if let Some(Value::String(s)) = map.get(*key) {
                    if matches!(s.as_str(), "end_turn" | "endTurn" | "stop") {
                        return true;
                    }
                }
            }
            // OpenAI Chat Completions (Codex).
            for key in &["finish_reason", "finishReason"] {
                if let Some(Value::String(s)) = map.get(*key) {
                    if s == "stop" {
                        return true;
                    }
                }
            }
            for (_, child) in map.iter() {
                if walk(child) {
                    return true;
                }
            }
            false
        }
        Value::Array(items) => items.iter().any(walk),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_end_turn() {
        assert!(line_signals_stop(
            r#"{"type":"assistant","message":{"stop_reason":"end_turn"}}"#
        ));
    }

    #[test]
    fn openai_finish_stop() {
        assert!(line_signals_stop(
            r#"{"choices":[{"finish_reason":"stop","message":{"role":"assistant"}}]}"#
        ));
    }

    #[test]
    fn tool_use_does_not_signal() {
        assert!(!line_signals_stop(
            r#"{"type":"assistant","message":{"stop_reason":"tool_use"}}"#
        ));
        assert!(!line_signals_stop(
            r#"{"choices":[{"finish_reason":"tool_calls"}]}"#
        ));
    }

    #[test]
    fn ignores_invalid_json() {
        assert!(!line_signals_stop("not json"));
        assert!(!line_signals_stop(""));
    }

    #[test]
    fn openclaw_camelcase_stop_reason_signals() {
        // OpenClaw's transcript shape — camelCase key, plain "stop" value
        // on a final assistant message (no toolCall children).
        assert!(line_signals_stop(
            r#"{"type":"message","message":{"role":"assistant","stopReason":"stop","content":[{"type":"text","text":"Done!"}]}}"#
        ));
    }

    #[test]
    fn openclaw_camelcase_tool_use_does_not_signal() {
        assert!(!line_signals_stop(
            r#"{"type":"message","message":{"role":"assistant","stopReason":"toolUse"}}"#
        ));
    }

    #[test]
    fn anthropic_camelcase_end_turn_signals() {
        assert!(line_signals_stop(
            r#"{"message":{"stopReason":"end_turn"}}"#
        ));
        assert!(line_signals_stop(
            r#"{"message":{"stopReason":"endTurn"}}"#
        ));
    }
}
