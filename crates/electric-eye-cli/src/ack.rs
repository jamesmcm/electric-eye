//! Local incident review state.
//!
//! The daemon remains read-only. Acknowledgements and mutes live in a user-owned
//! JSON file and only affect what this user's client displays.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn state_path() -> PathBuf {
    if let Some(path) = std::env::var_os("ELECTRIC_EYE_REVIEW_STATE") {
        return PathBuf::from(path);
    }
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(state)
            .join("electric-eye")
            .join("incidents.json");
    }
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join(".local/state/electric-eye/incidents.json")
}

pub struct Store {
    path: PathBuf,
    value: Value,
}

impl Store {
    pub fn load() -> Self {
        Self::at(state_path())
    }
    pub fn at(path: PathBuf) -> Self {
        let value = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_else(|| json!({"acks": {}, "mutes": []}));
        Self { path, value }
    }
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
    fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, serde_json::to_string_pretty(&self.value)?)?;
        Ok(())
    }
    pub fn ack(&mut self, id: &str, until_ms: Option<u64>) -> anyhow::Result<()> {
        let acks = self
            .value
            .as_object_mut()
            .map(|value| {
                value
                    .entry("acks")
                    .or_insert_with(|| Value::Object(Map::new()))
            })
            .and_then(Value::as_object_mut)
            .ok_or_else(|| anyhow::anyhow!("review state is not an object"))?;
        acks.insert(
            id.to_string(),
            json!({"acknowledged_ms": now_ms(), "until_ms": until_ms}),
        );
        self.save()
    }
    pub fn unack(&mut self, id: &str) -> anyhow::Result<()> {
        if let Some(acks) = self.value["acks"].as_object_mut() {
            acks.remove(id);
        }
        self.save()
    }
    pub fn mute(&mut self, app: &str, rule: &str, until_ms: u64) -> anyhow::Result<()> {
        let mutes = self
            .value
            .as_object_mut()
            .map(|value| value.entry("mutes").or_insert_with(|| json!([])))
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow::anyhow!("review state mutes is not an array"))?;
        mutes.retain(|entry| {
            !(entry["app"].as_str() == Some(app) && entry["rule"].as_str() == Some(rule))
        });
        mutes.push(json!({"app": app, "rule": rule, "until_ms": until_ms}));
        self.save()
    }
    pub fn unmute(&mut self, app: &str, rule: &str) -> anyhow::Result<()> {
        if let Some(mutes) = self.value["mutes"].as_array_mut() {
            mutes.retain(|entry| {
                !(entry["app"].as_str() == Some(app) && entry["rule"].as_str() == Some(rule))
            });
        }
        self.save()
    }
    pub fn prune(&mut self) {
        let now = now_ms();
        let mut changed = false;
        if let Some(acks) = self.value["acks"].as_object_mut() {
            let before = acks.len();
            acks.retain(|_, entry| entry["until_ms"].as_u64().is_none_or(|until| until > now));
            changed |= acks.len() != before;
        }
        if let Some(mutes) = self.value["mutes"].as_array_mut() {
            let before = mutes.len();
            mutes.retain(|entry| entry["until_ms"].as_u64().is_some_and(|until| until > now));
            changed |= mutes.len() != before;
        }
        if changed {
            let _ = self.save();
        }
    }
    pub fn state(&self, incident: &Value) -> Option<&'static str> {
        let now = now_ms();
        if let Some(id) = incident["id"].as_str()
            && let Some(entry) = self.value["acks"].get(id)
            && entry["until_ms"].as_u64().is_none_or(|until| until > now)
        {
            return Some("acked");
        }
        let app = incident["comm"].as_str().unwrap_or_default();
        let actor = incident["details"]["actor"]["application"]["name"]
            .as_str()
            .unwrap_or_default();
        let rule = incident["details"]["rule"]
            .as_str()
            .or_else(|| incident["title"].as_str())
            .unwrap_or_default();
        if let Some(mutes) = self.value["mutes"].as_array() {
            for entry in mutes {
                if entry["until_ms"].as_u64().is_none_or(|until| until <= now) {
                    continue;
                }
                let mute_app = entry["app"].as_str().unwrap_or_default();
                let mute_rule = entry["rule"].as_str().unwrap_or_default();
                if (mute_app.is_empty() || app.contains(mute_app) || actor.contains(mute_app))
                    && (mute_rule.is_empty()
                        || rule
                            .to_ascii_lowercase()
                            .contains(&mute_rule.to_ascii_lowercase())
                        || incident["title"]
                            .as_str()
                            .unwrap_or_default()
                            .to_ascii_lowercase()
                            .contains(&mute_rule.to_ascii_lowercase()))
                {
                    return Some("muted");
                }
            }
        }
        None
    }
    pub fn annotate(&self, incidents: &mut Value) {
        if let Some(rows) = incidents["incidents"].as_array_mut() {
            for row in rows {
                if let Some(state) = self.state(row) {
                    row["review_state"] = json!(state);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incident(id: &str, app: &str, rule: &str) -> Value {
        json!({
            "id": id,
            "comm": app,
            "title": rule,
            "details": {"rule": rule, "actor": {"application": {"name": app}}}
        })
    }

    #[test]
    fn ack_and_mute_are_local_and_expire() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::at(temp.path().join("review.json"));
        let first = incident("one", "curl", "novel_network");
        assert_eq!(store.state(&first), None);
        store.ack("one", None).unwrap();
        assert_eq!(store.state(&first), Some("acked"));
        store.unack("one").unwrap();
        assert_eq!(store.state(&first), None);
        store
            .mute("curl", "novel_network", now_ms() + 60_000)
            .unwrap();
        let second = incident("two", "curl", "novel_network");
        assert_eq!(store.state(&second), Some("muted"));
        store
            .mute("curl", "novel_network", now_ms().saturating_sub(1))
            .unwrap();
        assert_eq!(store.state(&second), None);
    }

    #[test]
    fn annotations_are_visible_to_clients() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::at(temp.path().join("review.json"));
        store.ack("one", None).unwrap();
        let mut value = json!({"incidents": [incident("one", "curl", "egress")]});
        store.annotate(&mut value);
        assert_eq!(value["incidents"][0]["review_state"], "acked");
    }
}
