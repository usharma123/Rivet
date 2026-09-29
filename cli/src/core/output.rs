use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};

pub const SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
    Events,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    schema_version: u8,
    event: String,
    #[serde(flatten)]
    payload: serde_json::Map<String, Value>,
}

impl Event {
    pub fn new(event: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event: event.into(),
            payload: serde_json::Map::new(),
        }
    }

    pub fn with(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        self.payload.insert(
            key.into(),
            serde_json::to_value(value).unwrap_or(Value::Null),
        );
        self
    }
}

/// Flush each event as it happens so piped agents can observe a long install.
pub fn progress(mode: OutputMode, event: Event) -> Result<()> {
    if mode == OutputMode::Events {
        let mut out = io::stdout().lock();
        serde_json::to_writer(&mut out, &event)?;
        writeln!(out)?;
        out.flush()?;
    }
    Ok(())
}

pub fn failure(mode: OutputMode, error: &super::error::Failure) -> Result<()> {
    match mode {
        OutputMode::Human => eprintln!(
            "error [{}]: {}\n{}",
            error.code, error.message, error.suggestion
        ),
        OutputMode::Json => println!(
            "{}",
            serde_json::json!({"schema_version": SCHEMA_VERSION, "ok": false, "error": error})
        ),
        OutputMode::Events => progress(mode, Event::new("command.failed").with("error", error))?,
    }
    Ok(())
}

pub fn emit(
    mode: OutputMode,
    title: &str,
    lines: Vec<String>,
    event: Event,
    value: impl Serialize,
) -> Result<()> {
    emit_many(mode, title, lines, vec![event], value)
}

pub fn emit_many(
    mode: OutputMode,
    title: &str,
    lines: Vec<String>,
    events: Vec<Event>,
    value: impl Serialize,
) -> Result<()> {
    match mode {
        OutputMode::Human => {
            println!("{title}\n");
            for line in lines {
                println!("  {line}");
            }
        }
        OutputMode::Json => {
            let mut value = serde_json::to_value(value)?;
            if let Some(object) = value.as_object_mut() {
                object.insert("schema_version".into(), SCHEMA_VERSION.into());
                object.insert("ok".into(), true.into());
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        OutputMode::Events => {
            for event in events {
                progress(mode, event)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Event;

    #[test]
    fn event_serializes_with_stable_event_key() {
        let event = Event::new("install.started").with("project", "demo");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"install.started\""));
        assert!(json.contains("\"project\":\"demo\""));
    }
}
