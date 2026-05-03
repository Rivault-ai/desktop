//! Stop-signal detection for transcript JSONL files.
//!
//! Looks for one of:
//! - `"stop_reason": "end_turn"` (Anthropic API shape — Claude Code, OpenClaw, Claude Desktop)
//! - `"finish_reason": "stop"` (OpenAI Chat Completions — Codex CLI)
//!
//! The check walks any JSON value (top-level object or nested), so it tolerates
//! the various wrappers different runtimes use around the raw API response.

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
            if let Some(Value::String(s)) = map.get("stop_reason") {
                if s == "end_turn" {
                    return true;
                }
            }
            if let Some(Value::String(s)) = map.get("finish_reason") {
                if s == "stop" {
                    return true;
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
}
