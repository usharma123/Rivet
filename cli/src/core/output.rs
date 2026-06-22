use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
    Events,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    event: String,
    #[serde(flatten)]
    payload: serde_json::Map<String, Value>,
}

impl Event {
    pub fn new(event: impl Into<String>) -> Self {
        Self {
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
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        OutputMode::Events => {
            for event in events {
                println!("{}", serde_json::to_string(&event)?);
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
