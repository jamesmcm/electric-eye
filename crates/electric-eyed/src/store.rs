use std::ffi::CString;
use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use electric_eye_core::{FileKind, ObservedEvent};
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};

use crate::api::ActivityEntry;
use crate::rules::BaselineData;

#[cfg(test)]
pub const RAW_RETENTION_MS: i64 = 5 * 60 * 1000;

enum StoreMsg {
    Event(Box<StoreEvent>),
    Incident(IncidentRow),
    Document(String, String, u64, String),
    Compact(SyncSender<Result<Value>>),
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct IncidentRow {
    pub ts_ms: i64,
    pub id: String,
    pub json: String,
    pub severity: String,
    pub title: String,
    pub details: String,
}

impl IncidentRow {
    pub fn from_incident(incident: &crate::rules::Incident) -> Self {
        Self {
            ts_ms: incident.ts_ms as i64,
            id: incident.id.clone(),
            json: serde_json::to_string(incident).unwrap_or_default(),
            severity: incident.severity.as_str().into(),
            title: incident.title.clone(),
            details: incident.details.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct StoreEvent {
    ts_ms: i64,
    kind: String,
    pid: i64,
    uid: i64,
    comm: String,
    exe: Option<String>,
    unit: Option<String>,
    nix: Option<String>,
    parent: Option<String>,
    path: Option<String>,
    from_path: Option<String>,
    to_path: Option<String>,
    family: Option<i64>,
    addr: Option<String>,
    local_port: Option<i64>,
    remote_port: Option<i64>,
    bytes: Option<i64>,
    count: Option<i64>,
    hostname: Option<String>,
    subject: String,
    json: String,
}

pub struct Store {
    tx: SyncSender<StoreMsg>,
    join: Option<JoinHandle<()>>,
    client: StoreClient,
}

#[derive(Clone)]
pub struct StoreClient {
    tx: SyncSender<StoreMsg>,
    path: PathBuf,
    dropped: Arc<AtomicU64>,
    limits: crate::config::Limits,
    baseline_limit: usize,
}

impl Store {
    #[cfg(test)]
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_config(path, crate::config::Config::default())
    }
    pub fn open_with_config(path: &Path, config: crate::config::Config) -> Result<Self> {
        prepare_database(path)?;
        let conn = Connection::open_with_flags(path, writer_flags())
            .with_context(|| format!("opening SQLite database {}", path.display()))?;
        configure(&conn)?;
        init_schema(&conn)?;
        conn.execute("UPDATE documents SET json=json_set(json,'$.last_known_state',json_extract(json,'$.state'),'$.state','observation_ended','$.observation_ended_ms',?1)
            WHERE collection='flows' AND json_extract(json,'$.closed_ms') IS NULL AND COALESCE(json_extract(json,'$.state'),'')<>'observation_ended'",params![now_ms()])?;
        drop(conn);

        let (tx, rx) = sync_channel(config.limits.store_queue);
        let dropped = Arc::new(AtomicU64::new(0));
        let path_owned = path.to_path_buf();
        let dropped_writer = Arc::clone(&dropped);
        let limits = config.limits.clone();
        let baseline_limit = config.rules.max_baseline_entries;
        let join = std::thread::Builder::new()
            .name("electric-eye-store".into())
            .spawn(move || writer_loop(path_owned, rx, dropped_writer, config))
            .context("spawning SQLite writer thread")?;

        Ok(Self {
            tx: tx.clone(),
            join: Some(join),
            client: StoreClient {
                tx,
                path: path.to_path_buf(),
                dropped,
                limits,
                baseline_limit,
            },
        })
    }

    pub fn client(&self) -> StoreClient {
        self.client.clone()
    }

    pub fn shutdown(mut self) {
        let _ = self.tx.send(StoreMsg::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn writer_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW
}

// SQLite derives WAL/SHM permissions from the main database. Create that file
// privately before SQLite opens it; never chmod an arbitrary existing path.
fn prepare_database(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let directory = std::fs::metadata(parent)?;
    let uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        directory.uid() == uid && directory.mode() & 0o022 == 0,
        "state directory must be owned by the daemon user and not writable by group/others: {}",
        parent.display()
    );
    let check = |file: std::fs::File, name: &Path| -> Result<()> {
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == uid
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "database files must be regular, privately owned (0600), and not hard-linked: {}",
            name.display()
        );
        Ok(())
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = match options.clone().create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => options.open(path)?,
        Err(error) => return Err(error.into()),
    };
    check(file, path)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let name = sidecar(path, suffix);
        match options.open(&name) {
            Ok(file) => check(file, &name)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl StoreClient {
    pub fn document(&self, collection: &str, key: &str, ts: u64, value: &impl serde::Serialize) {
        if let Ok(json) = serde_json::to_string(value)
            && self
                .tx
                .try_send(StoreMsg::Document(collection.into(), key.into(), ts, json))
                .is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn documents(&self, collection: &str, limit: usize) -> Result<Vec<Value>> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare(
            "SELECT json FROM documents WHERE collection=?1 ORDER BY ts_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![collection, limit.min(self.limits.api_process_rows) as i64],
            |row| row.get::<_, String>(0),
        )?;
        rows.map(|s| Ok(serde_json::from_str(&s?)?)).collect()
    }
    /// Select before applying the history limit, so old actors remain queryable.
    pub fn process_documents(
        &self,
        selector: &str,
        tree: bool,
        limit: usize,
    ) -> Result<Vec<Value>> {
        let conn = self.read_connection()?;
        let pid = selector.parse::<u32>().ok();
        let mut stmt = conn.prepare(
            "WITH RECURSIVE found(key,json) AS (
                SELECT key,json FROM documents WHERE collection='processes'
                  AND (?1='' OR key=?1 OR json_extract(json,'$.identity.pid')=?2)
                UNION
                SELECT d.key,d.json FROM documents d JOIN found p
                  ON json_extract(d.json,'$.parent.pid')=json_extract(p.json,'$.identity.pid')
                 AND json_extract(d.json,'$.parent.start_ns')=json_extract(p.json,'$.identity.start_ns')
                 AND json_extract(d.json,'$.parent.boot_id')=json_extract(p.json,'$.identity.boot_id')
                 WHERE d.collection='processes' AND ?3 AND ?1<>''
                UNION
                SELECT d.key,d.json FROM found p JOIN documents a
                  ON a.collection='processes' AND json_extract(a.json,'$.superseded_by')=p.key
                  JOIN documents d ON d.collection='processes'
                 AND json_extract(d.json,'$.parent.pid')=json_extract(a.json,'$.identity.pid')
                 AND json_extract(d.json,'$.parent.start_ns')=json_extract(a.json,'$.identity.start_ns')
                 AND json_extract(d.json,'$.parent.boot_id')=json_extract(a.json,'$.identity.boot_id')
                 WHERE ?3 AND ?1<>''
            ) SELECT json FROM found WHERE json_extract(json,'$.superseded_by') IS NULL
              ORDER BY json_extract(json,'$.last_seen_ms') DESC LIMIT ?4"
        )?;
        let rows = stmt.query_map(params![selector, pid, tree, limit as i64], |r| {
            r.get::<_, String>(0)
        })?;
        let mut result: Vec<Value> = rows
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect::<Result<_>>()?;
        let mut parent = conn.prepare(
            "SELECT json_extract(p.json,'$.identity') FROM documents a JOIN documents p
            ON p.collection='processes' AND p.key=json_extract(a.json,'$.superseded_by')
            WHERE a.collection='processes' AND a.key=?1",
        )?;
        for row in &mut result {
            if let Ok(identity) =
                serde_json::from_value::<crate::api::ProcessIdentity>(row["parent"].clone())
            {
                let value: rusqlite::Result<String> =
                    parent.query_row(params![crate::process::key(&identity)], |r| r.get(0));
                if let Ok(value) = value {
                    row["parent"] = serde_json::from_str(&value)?;
                }
            }
        }
        Ok(result)
    }
    pub fn exec_history(&self, ids: &[String], limit: usize) -> Result<Vec<Value>> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare(
            "SELECT json FROM documents WHERE collection='execs'
            AND json_extract(json,'$.id') IN (SELECT value FROM json_each(?1))
            ORDER BY ts_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![serde_json::to_string(ids)?, limit as i64], |r| {
            r.get::<_, String>(0)
        })?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn events_page(
        &self,
        history: &crate::api::HistoryQuery,
        limit: usize,
    ) -> Result<Vec<Value>> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare(
            "SELECT json,COALESCE(json_extract(json,'$.event_id'),'legacy-event-'||id) AS event_key
             FROM events WHERE (?1 IS NULL OR ts_ms >= ?1) AND (?2 IS NULL OR ts_ms < ?2)
             AND (?3 IS NULL OR ts_ms < ?3 OR (ts_ms = ?3 AND event_key < ?4))
             ORDER BY ts_ms DESC,event_key DESC LIMIT ?5",
        )?;
        let rows = stmt.query_map(
            params![
                history.since_ms.map(sql_timestamp),
                history.before_ms.map(sql_timestamp),
                history.cursor.as_ref().map(|c| sql_timestamp(c.0)),
                history.cursor.as_ref().map(|c| c.1.as_str()),
                limit.clamp(1, self.limits.api_query_rows.saturating_add(1)) as i64,
            ],
            |row| {
                let raw: String = row.get(0)?;
                let id: String = row.get(1)?;
                Ok((raw, id))
            },
        )?;
        rows.map(|row| {
            let (raw, id) = row?;
            let mut value: Value = serde_json::from_str(&raw)?;
            value["event_id"] = json!(id);
            Ok(value)
        })
        .collect()
    }
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn record(&self, entry: &ActivityEntry) {
        let Some(event) = StoreEvent::from_entry(entry) else {
            return;
        };
        if self.tx.try_send(StoreMsg::Event(Box::new(event))).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_incident(&self, incident: IncidentRow) {
        if self.tx.try_send(StoreMsg::Incident(incident)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn status_value(&self) -> Value {
        let Ok(conn) = self.read_connection() else {
            return json!({
                "path": self.path.display().to_string(),
                "dropped": self.dropped(),
                "error": "database unavailable",
            });
        };
        let raw = scalar(&conn, "SELECT COUNT(*) FROM events");
        let activities = scalar(&conn, "SELECT COUNT(*) FROM activities");
        let incidents = scalar(&conn, "SELECT COUNT(*) FROM incidents");
        let bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        json!({
            "path": self.path.display().to_string(),
            "db_bytes": bytes,
            "raw_events": raw,
            "activities": activities,
            "incidents": incidents,
            "dropped": self.dropped(),
        })
    }

    pub fn db_status(&self, config: &crate::config::Config) -> Result<Value> {
        let conn = self.read_connection()?;
        let mut value = db_stats(&conn, &self.path, config)?;
        value["dropped"] = json!(self.dropped());
        Ok(value)
    }

    pub fn compact(&self) -> Result<Value> {
        let (reply, response) = sync_channel(1);
        self.tx
            .send(StoreMsg::Compact(reply))
            .context("store writer is not accepting maintenance requests")?;
        response
            .recv_timeout(Duration::from_secs(30))
            .context("timed out waiting for database compaction")?
    }

    pub fn baseline(&self) -> Result<BaselineData> {
        let conn = self.read_connection()?;
        let mut paths = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT COALESCE(exe, nix, comm), subject FROM events WHERE kind LIKE 'file.%' AND kind NOT LIKE '%.attempt'
             UNION
             SELECT COALESCE(exe, nix, app), subject FROM activities WHERE kind LIKE 'file.%' AND kind NOT LIKE '%.attempt' LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![self.baseline_limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            paths.push(row?);
        }

        let mut network = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT COALESCE(exe, nix, comm), subject FROM events
             WHERE kind LIKE 'net.%' AND kind NOT IN ('net.traffic', 'net.listen')
             UNION
             SELECT COALESCE(exe, nix, app), subject FROM activities
             WHERE kind LIKE 'net.%' AND kind NOT IN ('net.traffic', 'net.listen') LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![self.baseline_limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            network.push(row?);
        }
        Ok(BaselineData::from_pairs(paths, network))
    }

    pub fn recent_activities(&self, limit: usize) -> Result<Value> {
        let conn = self.read_connection()?;
        let limit = limit.clamp(1, self.limits.api_query_rows);
        let mut stmt = conn.prepare(
            "SELECT bucket_ms, kind, app, subject, count, bytes, unit, nix, from_path, to_path, exe, app_name, task_id, comm
             FROM activities ORDER BY bucket_ms DESC, count DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], activity_row)?;
        Ok(json!({ "activities": collect(rows)? }))
    }

    pub fn app_activities(&self, app: &str, limit: usize) -> Result<Value> {
        let conn = self.read_connection()?;
        let limit = limit.clamp(1, self.limits.api_query_rows);
        let mut stmt = conn.prepare(
            "SELECT bucket_ms, kind, app, subject, count, bytes, unit, nix, from_path, to_path, exe, app_name, task_id, comm
             FROM activities WHERE app = ?1 OR app_name = ?1 OR task_id = ?1 OR comm = ?1 ORDER BY bucket_ms DESC, count DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![app, limit as i64], activity_row)?;
        let activities = collect(rows)?;

        let mut stmt = conn.prepare(
            "SELECT ts_ms, kind, comm, subject, path, from_path, to_path,
                    addr, local_port, remote_port, bytes, count, json
             FROM events WHERE comm = ?1 OR json_extract(json,'$.application.id')=?1 OR json_extract(json,'$.application.name')=?1 OR json_extract(json,'$.application.task_id')=?1 ORDER BY ts_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![app, limit as i64], raw_row)?;
        Ok(json!({
            "app": app,
            "activities": activities,
            "events": collect(rows)?,
        }))
    }

    pub fn file_activities(&self, path: &str, limit: usize) -> Result<Value> {
        self.why(path, limit)
    }

    pub fn network_activities(&self, limit: usize) -> Result<Value> {
        let conn = self.read_connection()?;
        let limit = limit.clamp(1, self.limits.api_query_rows);
        let mut stmt = conn.prepare(
            "SELECT bucket_ms, kind, app, subject, count, bytes, unit, nix, from_path, to_path, exe, app_name, task_id, comm
             FROM activities WHERE kind LIKE 'net.%'
             ORDER BY bucket_ms DESC, bytes DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], activity_row)?;
        let activities = collect(rows)?;

        let mut stmt = conn.prepare(
            "SELECT ts_ms, kind, comm, subject, path, from_path, to_path,
                    addr, local_port, remote_port, bytes, count, json
             FROM events WHERE kind LIKE 'net.%' ORDER BY ts_ms DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], raw_row)?;
        Ok(json!({
            "activities": activities,
            "events": collect(rows)?,
        }))
    }

    pub fn why(&self, path: &str, limit: usize) -> Result<Value> {
        let conn = self.read_connection()?;
        let limit = limit.clamp(1, self.limits.api_query_rows);
        let mut stmt = conn.prepare(
            "SELECT bucket_ms, kind, app, subject, count, bytes, unit, nix, from_path, to_path, exe, app_name, task_id, comm
             FROM activities WHERE (subject = ?1 OR from_path = ?1 OR to_path = ?1) ORDER BY bucket_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![path, limit as i64], activity_row)?;
        let activities = collect(rows)?;

        let mut stmt = conn.prepare(
            "SELECT ts_ms, kind, comm, subject, path, from_path, to_path,
                    addr, local_port, remote_port, bytes, count, json
             FROM events
             WHERE path = ?1 OR from_path = ?1 OR to_path = ?1
             ORDER BY ts_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![path, limit as i64], raw_row)?;
        Ok(json!({
            "path": path,
            "activities": activities,
            "events": collect(rows)?,
        }))
    }

    pub fn incidents(&self, limit: usize) -> Result<Value> {
        Ok(json!({"incidents":self.incidents_page(&crate::api::HistoryQuery::default(),limit)?}))
    }
    pub fn incidents_page(
        &self,
        history: &crate::api::HistoryQuery,
        limit: usize,
    ) -> Result<Vec<Value>> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare(
            "SELECT ts_ms,severity,title,details,COALESCE(incident_id,'legacy-'||id) AS incident_key,json
             FROM incidents WHERE (?1 IS NULL OR ts_ms >= ?1) AND (?2 IS NULL OR ts_ms < ?2)
             AND (?3 IS NULL OR ts_ms < ?3 OR (ts_ms = ?3 AND incident_key < ?4))
             ORDER BY ts_ms DESC,incident_key DESC LIMIT ?5")?;
        let rows = stmt.query_map(
            params![
                history.since_ms.map(sql_timestamp),
                history.before_ms.map(sql_timestamp),
                history.cursor.as_ref().map(|c| sql_timestamp(c.0)),
                history.cursor.as_ref().map(|c| c.1.as_str()),
                limit.clamp(1, self.limits.api_query_rows.saturating_add(1)) as i64,
            ],
            incident_value,
        )?;
        rows.map(|row| Ok(row?)).collect()
    }
    pub fn incident(&self, id: &str) -> Result<Option<Value>> {
        use rusqlite::OptionalExtension;
        let conn = self.read_connection()?;
        Ok(conn
            .query_row(
                "SELECT ts_ms,severity,title,details,COALESCE(incident_id,'legacy-'||id),json
             FROM incidents WHERE incident_id=?1 OR (incident_id IS NULL AND 'legacy-'||id=?1)",
                params![id],
                incident_value,
            )
            .optional()?)
    }

    fn read_connection(&self) -> Result<Connection> {
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("opening database {} read-only", self.path.display()))?;
        conn.busy_timeout(Duration::from_millis(2000))?;
        Ok(conn)
    }
}

fn sql_timestamp(timestamp: u64) -> i64 {
    i64::try_from(timestamp).unwrap_or(i64::MAX)
}

fn incident_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let id: String = row.get(4)?;
    let ts: i64 = row.get(0)?;
    if let Some(full) = row.get::<_, Option<String>>(5)?
        && let Ok(mut value) = serde_json::from_str::<Value>(&full)
        && value.is_object()
    {
        value["id"] = json!(id);
        value["ts_ms"] = json!(ts);
        return Ok(value);
    }
    let details: String = row.get(3)?;
    Ok(
        json!({"id":id,"ts_ms":ts,"severity":row.get::<_,String>(1)?,
        "title":row.get::<_,String>(2)?,
        "details":serde_json::from_str::<Value>(&details).unwrap_or(Value::String(details))}),
    )
}

fn activity_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "bucket_ms": row.get::<_, i64>(0)?,
        "kind": row.get::<_, String>(1)?,
        "app": row.get::<_, String>(2)?,
        "subject": row.get::<_, String>(3)?,
        "count": row.get::<_, i64>(4)?,
        "bytes": row.get::<_, i64>(5)?,
        "unit": row.get::<_, Option<String>>(6)?,
        "nix": row.get::<_, Option<String>>(7)?,
        "from_path": row.get::<_, Option<String>>(8)?,
        "to_path": row.get::<_, Option<String>>(9)?,
        "exe": row.get::<_, Option<String>>(10)?,
        "app_name": row.get::<_, Option<String>>(11)?,
        "task_id": row.get::<_, Option<String>>(12)?,
        "comm": row.get::<_, Option<String>>(13)?,
    }))
}

fn raw_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let entry: String = row.get(12)?;
    let entry = serde_json::from_str::<Value>(&entry).unwrap_or(Value::Null);
    Ok(json!({
        "entry":entry,
        "process":entry["process"],
        "exe":entry["exe"],
        "pid":entry["event"]["pid"],
        "uid":entry["event"]["uid"],
        "unit":entry["unit"],
        "ts_ms": row.get::<_, i64>(0)?,
        "kind": row.get::<_, String>(1)?,
        "comm": row.get::<_, String>(2)?,
        "subject": row.get::<_, String>(3)?,
        "path": row.get::<_, Option<String>>(4)?,
        "from_path": row.get::<_, Option<String>>(5)?,
        "to_path": row.get::<_, Option<String>>(6)?,
        "addr": row.get::<_, Option<String>>(7)?,
        "local_port": row.get::<_, Option<i64>>(8)?,
        "remote_port": row.get::<_, Option<i64>>(9)?,
        "bytes": row.get::<_, Option<i64>>(10)?,
        "count": row.get::<_, Option<i64>>(11)?,
    }))
}

fn collect<T>(rows: rusqlite::MappedRows<'_, T>) -> Result<Vec<Value>>
where
    T: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
{
    let mut values = Vec::new();
    for row in rows {
        values.push(row?);
    }
    Ok(values)
}

fn scalar(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap_or(0)
}

impl StoreEvent {
    fn from_entry(entry: &ActivityEntry) -> Option<Self> {
        let event = &entry.event;
        let json = serde_json::to_string(entry).ok()?;
        let (kind, pid, uid, comm) = identity(event);
        let mut row = Self {
            ts_ms: entry.ts_ms as i64,
            kind,
            pid: pid as i64,
            uid: uid as i64,
            comm,
            exe: entry.exe.clone(),
            unit: entry.unit.clone(),
            nix: entry.nix.clone(),
            parent: entry.parent.clone(),
            path: None,
            from_path: None,
            to_path: None,
            family: None,
            addr: None,
            local_port: None,
            remote_port: None,
            bytes: None,
            count: None,
            hostname: None,
            subject: String::new(),
            json,
        };
        match event {
            ObservedEvent::Exec(event) | ObservedEvent::Fork(event) => {
                row.subject = event.exe.display().to_string();
            }
            ObservedEvent::Exit(event) => {
                row.subject = event.comm.clone();
            }
            ObservedEvent::Connect(event)
            | ObservedEvent::Accept(event)
            | ObservedEvent::Listen(event) => {
                row.family = Some(event.family as i64);
                row.addr = Some(event.addr_string());
                row.local_port = Some(event.local_port as i64);
                row.remote_port = Some(event.remote_port as i64);
                row.hostname = event.hostname.clone();
                row.subject = if event.remote_port == 0 {
                    event.local_endpoint()
                } else {
                    event.remote_endpoint()
                };
            }
            ObservedEvent::FileRead(event) => {
                row.path = Some(event.path.clone());
                row.subject = event.path.clone();
            }
            ObservedEvent::FileOpen(event) => {
                row.path = Some(event.path.clone());
                row.subject = event.path.clone();
            }
            ObservedEvent::FileWrite(event) => {
                row.path = Some(event.path.clone());
                row.bytes = event.bytes.map(|b| b as i64);
                row.count = event.count.map(|c| c as i64);
                row.subject = event.path.clone();
            }
            ObservedEvent::FileUnlink(event) => {
                row.path = Some(event.path.clone());
                row.subject = event.path.clone();
            }
            ObservedEvent::FileRename(event) => {
                row.from_path = Some(event.from_path.clone());
                row.to_path = Some(event.to_path.clone());
                row.subject = event.to_path.clone();
            }
            ObservedEvent::Traffic(summary) => {
                row.bytes = Some(summary.total() as i64);
                row.count = Some(1);
                row.subject = summary.comm.clone();
            }
        }
        if entry.syscall_result.is_some_and(|result| result < 0) {
            row.kind.push_str(".attempt");
            row.bytes = None;
            row.count = None;
        }
        Some(row)
    }
}

fn identity(event: &ObservedEvent) -> (String, u32, u32, String) {
    match event {
        ObservedEvent::Fork(event) => {
            ("proc.fork".into(), event.pid, event.uid, event.comm.clone())
        }
        ObservedEvent::Exec(event) => {
            ("proc.exec".into(), event.pid, event.uid, event.comm.clone())
        }
        ObservedEvent::Exit(event) => {
            ("proc.exit".into(), event.pid, event.uid, event.comm.clone())
        }
        ObservedEvent::Connect(event) => (
            "net.connect".into(),
            event.pid,
            event.uid,
            event.comm.clone(),
        ),
        ObservedEvent::Accept(event) => (
            "net.accept".into(),
            event.pid,
            event.uid,
            event.comm.clone(),
        ),
        ObservedEvent::Listen(event) => (
            "net.listen".into(),
            event.pid,
            event.uid,
            event.comm.clone(),
        ),
        ObservedEvent::FileRead(event) => {
            ("file.read".into(), event.pid, event.uid, event.comm.clone())
        }
        ObservedEvent::FileOpen(event) => {
            let kind = match event.kind {
                FileKind::Read => "file.read",
                FileKind::Open => "file.open",
                FileKind::Create => "file.create",
                FileKind::Truncate => "file.truncate",
                FileKind::Write => "file.write",
                FileKind::Mmap => "file.mmap",
                FileKind::Unlink => "file.unlink",
            };
            (kind.into(), event.pid, event.uid, event.comm.clone())
        }
        ObservedEvent::FileWrite(event) => (
            match event.kind {
                FileKind::Mmap => "file.mmap",
                _ => "file.write",
            }
            .into(),
            event.pid,
            event.uid,
            event.comm.clone(),
        ),
        ObservedEvent::FileUnlink(event) => (
            "file.unlink".into(),
            event.pid,
            event.uid,
            event.comm.clone(),
        ),
        ObservedEvent::FileRename(event) => (
            "file.rename".into(),
            event.pid,
            event.uid,
            event.comm.clone(),
        ),
        ObservedEvent::Traffic(summary) => {
            ("net.traffic".into(), summary.pid, 0, summary.comm.clone())
        }
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn disk_space(path: &Path) -> Option<(u64, u64)> {
    let parent = path.parent().unwrap_or(Path::new("/"));
    let path = CString::new(parent.as_os_str().as_bytes()).ok()?;
    let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let block = if stat.f_frsize > 0 {
        stat.f_frsize
    } else {
        stat.f_bsize
    };
    Some((
        stat.f_blocks.saturating_mul(block),
        stat.f_bavail.saturating_mul(block),
    ))
}

fn db_stats(conn: &Connection, path: &Path, config: &crate::config::Config) -> Result<Value> {
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let free_pages: i64 = conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
    let mut documents = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT collection, COUNT(*) FROM documents GROUP BY collection ORDER BY collection",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(json!({
                "collection": row.get::<_, String>(0)?,
                "count": row.get::<_, i64>(1)?,
            }))
        })?;
        for row in rows {
            documents.push(row?);
        }
    }
    let (oldest_activity_ms, newest_activity_ms) = conn.query_row(
        "SELECT MIN(bucket_ms), MAX(bucket_ms) FROM activities",
        [],
        |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
    )?;
    let (disk_total, disk_free) = disk_space(path).unzip();
    let wal = sidecar(path, "-wal");
    let shm = sidecar(path, "-shm");
    Ok(json!({
        "path": path.display().to_string(),
        "db_bytes": file_size(path),
        "wal_bytes": file_size(&wal),
        "shm_bytes": file_size(&shm),
        "page_size": page_size,
        "page_count": page_count,
        "free_pages": free_pages,
        "raw_events": scalar(conn, "SELECT COUNT(*) FROM events"),
        "activities": scalar(conn, "SELECT COUNT(*) FROM activities"),
        "incidents": scalar(conn, "SELECT COUNT(*) FROM incidents"),
        "documents": documents,
        "documents_total": scalar(conn, "SELECT COUNT(*) FROM documents"),
        "oldest_activity_ms": oldest_activity_ms,
        "newest_activity_ms": newest_activity_ms,
        "retention": {
            "raw_retention_minutes": config.raw_retention_minutes,
            "activity_retention_days": config.activity_retention_days,
            "process_retention_days": config.process_retention_days,
            "flow_retention_days": config.flow_retention_days,
            "summary_retention_days": config.summary_retention_days,
            "noise_retention_days": config.noise_retention_days,
            "incident_high_retention_days": config.incident_high_retention_days,
            "incident_medium_retention_days": config.incident_medium_retention_days,
            "incident_low_retention_days": config.incident_low_retention_days,
        },
        "disk_total_bytes": disk_total,
        "disk_free_bytes": disk_free,
    }))
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA foreign_keys=ON;",
    )?;
    Ok(())
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS documents(collection TEXT NOT NULL,key TEXT NOT NULL,ts_ms INTEGER NOT NULL,json TEXT NOT NULL,PRIMARY KEY(collection,key));
        CREATE INDEX IF NOT EXISTS documents_time ON documents(collection,ts_ms);
        CREATE INDEX IF NOT EXISTS documents_pid ON documents(collection,json_extract(json,'$.identity.pid'));
        CREATE INDEX IF NOT EXISTS documents_parent ON documents(collection,json_extract(json,'$.parent.pid'),json_extract(json,'$.parent.start_ns'),json_extract(json,'$.parent.boot_id'));
        CREATE INDEX IF NOT EXISTS documents_superseded ON documents(collection,json_extract(json,'$.superseded_by'));
        CREATE INDEX IF NOT EXISTS documents_actor ON documents(collection,json_extract(json,'$.id'));
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            ts_ms INTEGER NOT NULL,
            kind TEXT NOT NULL,
            pid INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            comm TEXT NOT NULL,
            exe TEXT,
            unit TEXT,
            nix TEXT,
            parent TEXT,
            path TEXT,
            from_path TEXT,
            to_path TEXT,
            family INTEGER,
            addr TEXT,
            local_port INTEGER,
            remote_port INTEGER,
            bytes INTEGER,
            count INTEGER,
            hostname TEXT,
            subject TEXT NOT NULL,
            json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS events_ts ON events(ts_ms);
        CREATE INDEX IF NOT EXISTS events_comm_ts ON events(comm, ts_ms);
        CREATE INDEX IF NOT EXISTS events_path_ts ON events(path, ts_ms);

        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY,
            bucket_ms INTEGER NOT NULL,
            kind TEXT NOT NULL,
            app TEXT NOT NULL,
            subject TEXT NOT NULL,
            count INTEGER NOT NULL,
            bytes INTEGER NOT NULL,
            unit TEXT,
            nix TEXT,
            exe TEXT,
            from_path TEXT,
            to_path TEXT
        );
        CREATE INDEX IF NOT EXISTS activities_bucket ON activities(bucket_ms);
        CREATE INDEX IF NOT EXISTS activities_app ON activities(app, bucket_ms);
        CREATE INDEX IF NOT EXISTS activities_subject ON activities(subject, bucket_ms);

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY,
            ts_ms INTEGER NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT NOT NULL,
            incident_id TEXT,
            json TEXT
        );
        CREATE INDEX IF NOT EXISTS incidents_ts ON incidents(ts_ms);
        CREATE INDEX IF NOT EXISTS incidents_severity_ts ON incidents(severity,ts_ms);",
    )?;
    let _ = conn.execute("ALTER TABLE events ADD COLUMN exe TEXT", []);
    let _ = conn.execute("ALTER TABLE activities ADD COLUMN exe TEXT", []);
    for column in ["from_path", "to_path", "app_name", "task_id", "comm"] {
        ensure_column(conn, "activities", column, "TEXT")?;
    }
    ensure_column(conn, "incidents", "incident_id", "TEXT")?;
    ensure_column(conn, "incidents", "json", "TEXT")?;
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS incidents_identity ON incidents(incident_id);",
    )?;
    Ok(())
}
fn ensure_column(conn: &Connection, table: &str, column: &str, ty: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|name| name == column) {
        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {ty}"), [])?;
    }
    Ok(())
}

fn writer_loop(
    path: PathBuf,
    rx: Receiver<StoreMsg>,
    dropped: Arc<AtomicU64>,
    config: crate::config::Config,
) {
    let mut conn = match Connection::open_with_flags(&path, writer_flags())
        .context("opening writer connection")
    {
        Ok(conn) => conn,
        Err(err) => {
            log::error!("store writer could not open {}: {err:#}", path.display());
            return;
        }
    };
    if let Err(err) = configure(&conn).and_then(|_| init_schema(&conn)) {
        log::error!("store writer schema initialization failed: {err:#}");
        return;
    }

    let mut batch: Vec<StoreEvent> = Vec::new();
    let mut documents: Vec<(String, String, u64, String)> = Vec::new();
    let mut last_maintenance = Instant::now();
    let mut last_flush = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(config.limits.store_flush_ms)) {
            Ok(StoreMsg::Event(event)) => {
                batch.push(*event);
                if batch.len() >= config.limits.store_batch
                    && let Err(err) = flush_events(&mut conn, &mut batch)
                {
                    log::error!("store event flush failed: {err:#}");
                }
            }
            Ok(StoreMsg::Document(collection, key, ts, json)) => {
                documents.push((collection, key, ts, json));
                if documents.len() >= config.limits.store_batch
                    && let Err(err) = flush_documents(&mut conn, &mut documents, &dropped)
                {
                    log::error!("document persistence failed: {err:#}");
                }
            }
            Ok(StoreMsg::Incident(incident)) => {
                if let Err(err) = flush_events(&mut conn, &mut batch) {
                    log::error!("store event flush failed: {err:#}");
                }
                if let Err(err) = flush_documents(&mut conn, &mut documents, &dropped) {
                    log::error!("document persistence failed: {err:#}");
                }
                if let Err(err) = insert_incident(&conn, &incident) {
                    log::error!("store incident insert failed: {err:#}");
                }
            }
            Ok(StoreMsg::Compact(reply)) => {
                let result = (|| -> Result<Value> {
                    flush_events(&mut conn, &mut batch)?;
                    flush_documents(&mut conn, &mut documents, &dropped)?;
                    // VACUUM itself writes a large WAL in WAL mode. Checkpoint
                    // and truncate after it so compaction actually releases
                    // disk space back to the filesystem.
                    conn.execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")?;
                    let mut value = db_stats(&conn, &path, &config)?;
                    value["dropped"] = json!(dropped.load(Ordering::Relaxed));
                    Ok(value)
                })();
                let _ = reply.send(result);
            }
            Ok(StoreMsg::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                if let Err(err) = flush_events(&mut conn, &mut batch) {
                    log::error!("store final flush failed: {err:#}");
                }
                if let Err(err) = flush_documents(&mut conn, &mut documents, &dropped) {
                    log::error!("store final document flush failed: {err:#}");
                }
                break;
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Err(err) = flush_events(&mut conn, &mut batch) {
                    log::error!("store timed flush failed: {err:#}");
                }
                if let Err(err) = flush_documents(&mut conn, &mut documents, &dropped) {
                    log::error!("store timed document flush failed: {err:#}");
                }
            }
        }

        if last_flush.elapsed() >= Duration::from_millis(config.limits.store_flush_ms) {
            last_flush = Instant::now();
            if let Err(err) = flush_events(&mut conn, &mut batch) {
                log::error!("store timed flush failed: {err:#}");
            }
            if let Err(err) = flush_documents(&mut conn, &mut documents, &dropped) {
                log::error!("store timed document flush failed: {err:#}");
            }
        }
        if last_maintenance.elapsed() >= Duration::from_millis(config.limits.store_maintenance_ms) {
            last_maintenance = Instant::now();
            if let Err(err) = maintain_with_config(&mut conn, &config) {
                log::error!("store maintenance failed: {err:#}");
            }
        }
    }
    let _ = dropped;
}

fn flush_documents(
    conn: &mut Connection,
    documents: &mut Vec<(String, String, u64, String)>,
    dropped: &AtomicU64,
) -> Result<()> {
    if documents.is_empty() {
        return Ok(());
    }
    let result = (|| -> Result<()> {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO documents VALUES(?1,?2,?3,?4)
                 ON CONFLICT(collection,key) DO UPDATE SET ts_ms=excluded.ts_ms,json=excluded.json",
            )?;
            for (collection, key, ts, json) in documents.iter() {
                stmt.execute(params![collection, key, *ts as i64, json])?;
            }
        }
        tx.commit()?;
        Ok(())
    })();
    if let Err(err) = &result {
        log::error!("document batch flush failed: {err:#}");
        dropped.fetch_add(documents.len() as u64, Ordering::Relaxed);
    }
    documents.clear();
    result
}

fn flush_events(conn: &mut Connection, batch: &mut Vec<StoreEvent>) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO events (
                ts_ms, kind, pid, uid, comm, exe, unit, nix, parent,
                path, from_path, to_path, family, addr, local_port, remote_port,
                bytes, count, hostname, subject, json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                       ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        )?;
        for event in batch.drain(..) {
            stmt.execute(params![
                event.ts_ms,
                event.kind,
                event.pid,
                event.uid,
                event.comm,
                event.exe,
                event.unit,
                event.nix,
                event.parent,
                event.path,
                event.from_path,
                event.to_path,
                event.family,
                event.addr,
                event.local_port,
                event.remote_port,
                event.bytes,
                event.count,
                event.hostname,
                event.subject,
                event.json,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn insert_incident(conn: &Connection, incident: &IncidentRow) -> Result<()> {
    conn.execute(
        "INSERT INTO incidents (ts_ms, severity, title, details, incident_id, json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(incident_id) DO UPDATE SET details=excluded.details, json=excluded.json",
        params![
            incident.ts_ms,
            incident.severity,
            incident.title,
            incident.details,
            incident.id,
            incident.json
        ],
    )?;
    Ok(())
}

#[cfg(test)]
fn maintain(conn: &mut Connection) -> Result<()> {
    maintain_with_config(conn, &crate::config::Config::default())
}
fn maintain_with_config(conn: &mut Connection, config: &crate::config::Config) -> Result<()> {
    let now = now_ms();
    let raw_cutoff = now - config.raw_retention_minutes as i64 * 60_000;
    let activity_cutoff = now - config.activity_retention_days as i64 * 86_400_000;
    let process_cutoff = now - config.process_retention_days as i64 * 86_400_000;
    let flow_cutoff = now - config.flow_retention_days as i64 * 86_400_000;
    let summary_cutoff = now - config.summary_retention_days as i64 * 86_400_000;
    let noise_cutoff = now - config.noise_retention_days as i64 * 86_400_000;
    let high_incident_cutoff = now - config.incident_high_retention_days as i64 * 86_400_000;
    let medium_incident_cutoff = now - config.incident_medium_retention_days as i64 * 86_400_000;
    let low_incident_cutoff = now - config.incident_low_retention_days as i64 * 86_400_000;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO activities (bucket_ms, kind, app, subject, count, bytes, unit, nix, exe, from_path, to_path, app_name, task_id, comm)
         SELECT (ts_ms / ?1) * ?1, kind, COALESCE(json_extract(json,'$.application.id'),comm), subject, SUM(COALESCE(count, 1)),
                COALESCE(SUM(bytes), 0), MAX(unit), MAX(nix), exe, from_path, to_path,
                json_extract(json,'$.application.name'),json_extract(json,'$.application.task_id'),comm
         FROM events WHERE ts_ms < ?2
         GROUP BY (ts_ms / ?1) * ?1, kind, COALESCE(json_extract(json,'$.application.id'),comm), subject, exe, from_path, to_path,
                  json_extract(json,'$.application.name'),json_extract(json,'$.application.task_id'),comm",
        params![config.limits.activity_bucket_ms, raw_cutoff],
    )?;
    tx.execute("DELETE FROM events WHERE ts_ms < ?1", params![raw_cutoff])?;
    tx.execute(
        "DELETE FROM activities WHERE bucket_ms < ?1",
        params![activity_cutoff],
    )?;
    tx.execute(
        "DELETE FROM documents WHERE collection IN ('processes','execs') AND ts_ms < ?1",
        params![process_cutoff],
    )?;
    tx.execute(
        "DELETE FROM documents WHERE collection='applications' AND ts_ms < ?1",
        params![activity_cutoff],
    )?;
    tx.execute(
        "DELETE FROM documents WHERE collection='flows' AND ts_ms < ?1",
        params![flow_cutoff],
    )?;
    tx.execute(
        "DELETE FROM documents WHERE collection='summaries'
         AND json_extract(json,'$.confidence')='heuristic' AND ts_ms < ?1",
        params![noise_cutoff],
    )?;
    tx.execute(
        "DELETE FROM documents WHERE collection='summaries' AND ts_ms < ?1",
        params![summary_cutoff],
    )?;
    tx.execute(
        "DELETE FROM incidents
         WHERE (severity='high' AND ts_ms < ?1)
            OR (severity='medium' AND ts_ms < ?2)
            OR (severity='low' AND ts_ms < ?3)",
        params![
            high_incident_cutoff,
            medium_incident_cutoff,
            low_incident_cutoff
        ],
    )?;
    tx.commit()?;
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE); PRAGMA optimize;");
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ActivityEntry;
    use electric_eye_core::{ExecEvent, FileEvent, FileKind};
    use std::path::PathBuf;

    fn entry(_comm: &str, event: ObservedEvent) -> ActivityEntry {
        ActivityEntry {
            executable_identity: None,
            ts_ms: now_ms() as u64,
            syscall_result: None,
            event_id: None,
            process_info: None,
            application: None,
            process: None,
            path_resolution: None,
            event,
            unit: Some("test.service".into()),
            nix: None,
            parent: Some("bash".into()),
            exe: None,
        }
    }

    fn temp_db() -> PathBuf {
        tempfile::tempdir().unwrap().keep().join("test.db")
    }

    #[test]
    fn stores_and_queries_raw_events() {
        let path = temp_db();
        let store = Store::open(&path).unwrap();
        let client = store.client();
        client.record(&entry(
            "touch",
            ObservedEvent::FileOpen(FileEvent {
                pid: 42,
                uid: 1000,
                comm: "touch".into(),
                path: "/tmp/test-file".into(),
                kind: FileKind::Create,
                bytes: None,
                count: None,
            }),
        ));
        std::thread::sleep(Duration::from_millis(300));
        let why = client.why("/tmp/test-file", 10).unwrap();
        assert_eq!(why["events"].as_array().unwrap().len(), 1);
        assert_eq!(why["events"][0]["kind"], "file.create");
        store.shutdown();
    }

    #[test]
    fn rolls_raw_events_into_activities() {
        let path = temp_db();
        let store = Store::open(&path).unwrap();
        let client = store.client();
        let mut old = entry(
            "python3",
            ObservedEvent::FileWrite(FileEvent {
                pid: 7,
                uid: 0,
                comm: "python3".into(),
                path: "/tmp/write-target".into(),
                kind: FileKind::Write,
                bytes: Some(4096),
                count: Some(2),
            }),
        );
        old.ts_ms = (now_ms() - RAW_RETENTION_MS - 1000) as u64;
        client.record(&old);
        std::thread::sleep(Duration::from_millis(300));
        let mut conn = Connection::open(&path).unwrap();
        maintain(&mut conn).unwrap();
        let activities = client.recent_activities(10).unwrap();
        assert_eq!(activities["activities"].as_array().unwrap().len(), 1);
        assert_eq!(activities["activities"][0]["kind"], "file.write");
        assert_eq!(activities["activities"][0]["count"], 2);
        assert_eq!(activities["activities"][0]["bytes"], 4096);
        store.shutdown();
    }

    #[test]
    fn baselines_from_stored_events() {
        let path = temp_db();
        let store = Store::open(&path).unwrap();
        let client = store.client();
        client.record(&entry(
            "sudo",
            ObservedEvent::FileRead(FileEvent {
                pid: 1,
                uid: 0,
                comm: "sudo".into(),
                path: "/root/.ssh/id_rsa".into(),
                kind: FileKind::Read,
                bytes: None,
                count: None,
            }),
        ));
        std::thread::sleep(Duration::from_millis(300));
        let baseline = client.baseline().unwrap();
        assert!(baseline.knows_path("sudo", "/root/.ssh/id_rsa"));
        store.shutdown();
    }

    #[test]
    fn exec_rows_have_process_identity() {
        let entry = entry(
            "ls",
            ObservedEvent::Exec(ExecEvent {
                pid: 1,
                ppid: 0,
                uid: 0,
                comm: "ls".into(),
                exe: PathBuf::from("/usr/bin/ls"),
                start_ticks: 1,
            }),
        );
        let row = StoreEvent::from_entry(&entry).unwrap();
        assert_eq!(row.kind, "proc.exec");
        assert_eq!(row.subject, "/usr/bin/ls");
    }
}

#[cfg(test)]
mod persistence_regressions {
    use super::*;
    use electric_eye_core::{FileEvent, RenameEvent};
    #[test]
    fn rename_source_and_destination_survive_compaction() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.db");
        let store = Store::open(&path).unwrap();
        let client = store.client();
        store.shutdown();
        let mut conn = Connection::open(&path).unwrap();
        let entry = ActivityEntry {
            executable_identity: None,
            ts_ms: (now_ms() - RAW_RETENTION_MS - 1000) as u64,
            syscall_result: None,
            event_id: None,
            process_info: None,
            application: None,
            process: None,
            path_resolution: Some("kernel".into()),
            event: ObservedEvent::FileRename(RenameEvent {
                pid: 7,
                uid: 1000,
                comm: "test-app".into(),
                from_path: "/home/review/before".into(),
                to_path: "/home/review/after".into(),
            }),
            unit: None,
            nix: None,
            parent: None,
            exe: Some("/opt/test-app".into()),
        };
        flush_events(
            &mut conn,
            &mut vec![StoreEvent::from_entry(&entry).unwrap()],
        )
        .unwrap();
        maintain(&mut conn).unwrap();
        for name in ["before", "after"] {
            let result = client.why(&format!("/home/review/{name}"), 10).unwrap();
            assert!(result["events"].as_array().unwrap().is_empty());
            assert_eq!(result["activities"].as_array().unwrap().len(), 1);
            assert_eq!(result["activities"][0]["from_path"], "/home/review/before");
            assert_eq!(result["activities"][0]["exe"], "/opt/test-app");
        }
    }
    #[test]
    fn complete_incident_survives_restart_and_enrichment_updates_same_id() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.db");
        let mut engine = crate::rules::AnomalyEngine::new();
        let entry = ActivityEntry {
            executable_identity: None,
            ts_ms: now_ms() as u64,
            syscall_result: None,
            event_id: None,
            process_info: None,
            application: None,
            process: Some(crate::api::ProcessIdentity {
                pid: 7,
                start_ns: 123,
                boot_id: "boot".into(),
            }),
            path_resolution: Some("kernel".into()),
            event: ObservedEvent::FileRead(FileEvent {
                pid: 7,
                uid: 1000,
                comm: "test-app".into(),
                path: "/root/.ssh/key".into(),
                kind: FileKind::Read,
                bytes: None,
                count: None,
            }),
            unit: Some("test.service".into()),
            nix: None,
            parent: None,
            exe: Some("/opt/test-app".into()),
        };
        let mut incident = engine.observe(&entry).remove(0);
        let id = incident.id.clone();
        let store = Store::open(&path).unwrap();
        let client = store.client();
        client.record_incident(IncidentRow::from_incident(&incident));
        incident.details["journal"] = json!(["preceding context"]);
        client.record_incident(IncidentRow::from_incident(&incident));
        store.shutdown();
        let restarted = Store::open(&path).unwrap();
        let result = restarted.client().incidents(10).unwrap();
        let incidents = result["incidents"].as_array().unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0]["id"], id);
        assert_eq!(incidents[0]["pid"], 7);
        assert_eq!(incidents[0]["comm"], "test-app");
        assert_eq!(incidents[0]["path"], "/root/.ssh/key");
        assert_eq!(incidents[0]["exe"], "/opt/test-app");
        assert_eq!(incidents[0]["process"]["start_ns"], 123);
        assert_eq!(incidents[0]["details"]["journal"][0], "preceding context");
        restarted.shutdown();
    }
    #[test]
    fn legacy_incident_schema_migrates_without_losing_existing_rows() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.db");
        prepare_database(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE incidents(id INTEGER PRIMARY KEY,ts_ms INTEGER NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,details TEXT NOT NULL);INSERT INTO incidents VALUES(1,1,'high','legacy','{}');").unwrap();
        drop(conn);
        let store = Store::open(&path).unwrap();
        let result = store.client().incidents(10).unwrap();
        assert_eq!(result["incidents"][0]["id"], "legacy-1");
        assert_eq!(result["incidents"][0]["title"], "legacy");
        assert_eq!(
            store.client().incident("legacy-1").unwrap().unwrap()["title"],
            "legacy"
        );
        store.shutdown();
    }
}

#[cfg(test)]
mod retention_regressions {
    use super::*;
    #[test]
    fn configurable_document_retention_is_independent_of_raw_window() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let now = now_ms();
        for (collection, age) in [
            ("processes", 2 * 86_400_000),
            ("execs", 30 * 60_000),
            ("summaries", 2 * 86_400_000),
            ("flows", 30 * 60_000),
        ] {
            conn.execute(
                "INSERT INTO documents VALUES(?1,?1,?2,'{}')",
                params![collection, now - age],
            )
            .unwrap();
        }
        let config = crate::config::Config {
            process_retention_days: 1,
            activity_retention_days: 1,
            summary_retention_days: 1,
            ..Default::default()
        };
        maintain_with_config(&mut conn, &config).unwrap();
        assert_eq!(scalar(&conn, "SELECT count(*) FROM documents"), 2);
        assert_eq!(
            scalar(
                &conn,
                "SELECT count(*) FROM documents WHERE collection='execs'"
            ),
            1
        );
    }

    #[test]
    fn incidents_and_noise_summaries_use_independent_retention() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let now = now_ms();
        let day = 86_400_000;
        for (severity, age, id) in [
            ("high", 40 * day, "high-old"),
            ("medium", 20 * day, "medium-old"),
            ("low", 5 * day, "low-old"),
            ("high", 5 * day, "high-new"),
            ("medium", 5 * day, "medium-new"),
            ("low", day, "low-new"),
        ] {
            conn.execute(
                "INSERT INTO incidents (ts_ms,severity,title,details,incident_id,json)
                 VALUES (?1,?2,'test','{}',?3,'{}')",
                params![now - age, severity, id],
            )
            .unwrap();
        }
        for (confidence, age, key) in [
            ("heuristic", 10 * day, "noise-old"),
            ("correlated", 10 * day, "general-old"),
            ("heuristic", day, "noise-new"),
            ("correlated", day, "general-new"),
        ] {
            conn.execute(
                "INSERT INTO documents VALUES('summaries',?1,?2,?3)",
                params![
                    key,
                    now - age,
                    serde_json::json!({"confidence": confidence}).to_string()
                ],
            )
            .unwrap();
        }
        let config = crate::config::Config {
            incident_high_retention_days: 30,
            incident_medium_retention_days: 10,
            incident_low_retention_days: 3,
            noise_retention_days: 3,
            summary_retention_days: 30,
            ..Default::default()
        };
        maintain_with_config(&mut conn, &config).unwrap();
        assert_eq!(scalar(&conn, "SELECT count(*) FROM incidents"), 3);
        assert_eq!(
            scalar(
                &conn,
                "SELECT count(*) FROM incidents WHERE severity='high' AND incident_id='high-new'"
            ),
            1
        );
        assert_eq!(
            scalar(
                &conn,
                "SELECT count(*) FROM documents WHERE collection='summaries'"
            ),
            3
        );
        assert_eq!(
            scalar(
                &conn,
                "SELECT count(*) FROM documents WHERE collection='summaries' AND key='noise-old'"
            ),
            0
        );
        assert_eq!(
            scalar(
                &conn,
                "SELECT count(*) FROM documents WHERE collection='summaries' AND key='general-old'"
            ),
            1
        );
    }
}

#[cfg(test)]
mod usability_regressions {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Connection, StoreClient) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        prepare_database(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn).unwrap();
        let (tx, _) = sync_channel(1);
        let client = StoreClient {
            tx,
            path,
            dropped: Arc::new(AtomicU64::new(0)),
            limits: crate::config::Limits::default(),
            baseline_limit: crate::config::RuleConfig::default().max_baseline_entries,
        };
        (dir, conn, client)
    }
    fn document(conn: &Connection, collection: &str, key: &str, ts: u64, value: Value) {
        conn.execute(
            "INSERT INTO documents VALUES(?1,?2,?3,?4)",
            params![collection, key, ts as i64, value.to_string()],
        )
        .unwrap();
    }
    #[test]
    fn actors_and_execs_older_than_ten_thousand_documents_remain_queryable() {
        let (_dir, conn, client) = fixture();
        document(
            &conn,
            "processes",
            "boot:42:123",
            1,
            json!({"id":"boot:42:123","identity":{"pid":42,"start_ns":123,"boot_id":"boot"},"last_seen_ms":1}),
        );
        document(
            &conn,
            "execs",
            "boot:42:123:1",
            1,
            json!({"id":"boot:42:123","exec_id":1}),
        );
        conn.execute_batch("WITH RECURSIVE n(x) AS (VALUES(100) UNION ALL SELECT x+1 FROM n WHERE x<10200)
            INSERT INTO documents SELECT 'processes','new:'||x,x,json_object('id','new:'||x,'identity',json_object('pid',x,'start_ns',x,'boot_id','boot'),'last_seen_ms',x) FROM n;
            INSERT INTO documents SELECT 'execs',key||':1',ts_ms,json FROM documents WHERE collection='processes' AND ts_ms>1;").unwrap();
        assert_eq!(
            client.process_documents("42", false, 100).unwrap()[0]["id"],
            "boot:42:123"
        );
        assert_eq!(
            client
                .process_documents("boot:42:123", false, 100)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            client
                .exec_history(&["boot:42:123".into()], 100)
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn application_names_and_tasks_survive_raw_compaction() {
        let (_dir, mut conn, client) = fixture();
        let ts = now_ms() - RAW_RETENTION_MS - 1000;
        conn.execute("INSERT INTO events(ts_ms,kind,pid,uid,comm,subject,json) VALUES(?1,'file.write',1,1000,'helper','/work/output',?2)",params![ts,json!({"application":{"id":"desktop:editor.desktop","name":"Editor","task_id":"task:1"}}).to_string()]).unwrap();
        maintain(&mut conn).unwrap();
        for selector in ["Editor", "desktop:editor.desktop", "task:1", "helper"] {
            let result = client.app_activities(selector, 10).unwrap();
            assert_eq!(
                result["activities"].as_array().unwrap().len(),
                1,
                "{selector}: {result}"
            );
            assert_eq!(result["activities"][0]["app_name"], "Editor");
        }
    }
    #[test]
    fn inventory_parent_links_resolve_to_exact_identities_in_trees() {
        let (_dir, conn, client) = fixture();
        document(
            &conn,
            "processes",
            "boot:1:10",
            1,
            json!({"id":"boot:1:10","identity":{"pid":1,"start_ns":10,"boot_id":"boot"},"superseded_by":"boot:1:11"}),
        );
        document(
            &conn,
            "processes",
            "boot:1:11",
            2,
            json!({"id":"boot:1:11","identity":{"pid":1,"start_ns":11,"boot_id":"boot"}}),
        );
        document(
            &conn,
            "processes",
            "boot:2:20",
            3,
            json!({"id":"boot:2:20","identity":{"pid":2,"start_ns":20,"boot_id":"boot"},"parent":{"pid":1,"start_ns":10,"boot_id":"boot"}}),
        );
        let rows = client.process_documents("boot:1:11", true, 100).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter().find(|p| p["id"] == "boot:2:20").unwrap()["parent"]["start_ns"],
            11
        );
    }
    #[test]
    fn documents_are_written_in_batches() {
        let mut conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let dropped = AtomicU64::new(0);
        let mut documents: Vec<_> = (0..200)
            .map(|i| {
                (
                    "test".to_string(),
                    format!("key-{i}"),
                    i,
                    json!({"id": i}).to_string(),
                )
            })
            .collect();
        flush_documents(&mut conn, &mut documents, &dropped).unwrap();
        assert!(documents.is_empty());
        assert_eq!(scalar(&conn, "SELECT COUNT(*) FROM documents"), 200);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn restarted_observer_does_not_claim_old_flows_are_still_connected() {
        let (dir, conn, _) = fixture();
        document(
            &conn,
            "flows",
            "old",
            1,
            json!({"id":"old","state":"established","closed_ms":null,"sent":9}),
        );
        drop(conn);
        let store = Store::open(&dir.path().join("history.db")).unwrap();
        let flow = &store.client().documents("flows", 10).unwrap()[0];
        assert_eq!(flow["state"], "observation_ended");
        assert_eq!(flow["last_known_state"], "established");
        assert!(flow["closed_ms"].is_null());
        assert_eq!(flow["sent"], 9);
        store.shutdown();
    }
}

#[cfg(test)]
mod privacy_regressions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn database_directory_and_sidecars_are_private_without_a_service_umask() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state/eye.db");
        let store = Store::open(&path).unwrap();
        store.client().compact().unwrap();
        for name in [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")] {
            let mode = std::fs::metadata(&name).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", name.display());
        }
        assert_eq!(
            std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        store.shutdown();
    }
    #[test]
    fn refuses_insecure_existing_files_links_and_shared_directories_without_modifying_them() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("unrelated");
        std::fs::write(&target, b"keep").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(prepare_database(&target).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o777, 0o644);
        let link = temp.path().join("symlink.db");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(prepare_database(&link).is_err());
        let hard = temp.path().join("hardlink.db");
        std::fs::hard_link(&target, &hard).unwrap();
        assert!(prepare_database(&hard).is_err());
        let shared = temp.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_database(&shared.join("eye.db")).is_err());
        assert!(!shared.join("eye.db").exists());
        assert_eq!(std::fs::metadata(&shared).unwrap().mode() & 0o777, 0o777);
        let database = temp.path().join("safe.db");
        let wal = sidecar(&database, "-wal");
        std::os::unix::fs::symlink(&target, &wal).unwrap();
        assert!(prepare_database(&database).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }
}
