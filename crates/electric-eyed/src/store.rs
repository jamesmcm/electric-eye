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

pub const RAW_RETENTION_MS: i64 = 5 * 60 * 1000;
pub const ACTIVITY_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
pub const ACTIVITY_BUCKET_MS: i64 = 5 * 60 * 1000;

const CHANNEL_CAPACITY: usize = 8192;
const BATCH_SIZE: usize = 128;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
const MAX_QUERY_LIMIT: usize = 1000;

enum StoreMsg {
    Event(Box<StoreEvent>),
    Incident(IncidentRow),
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct IncidentRow {
    pub ts_ms: i64,
    pub severity: String,
    pub title: String,
    pub details: String,
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
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating state directory {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening SQLite database {}", path.display()))?;
        configure(&conn)?;
        init_schema(&conn)?;
        drop(conn);

        let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let path_owned = path.to_path_buf();
        let dropped_writer = Arc::clone(&dropped);
        let join = std::thread::Builder::new()
            .name("electric-eye-store".into())
            .spawn(move || writer_loop(path_owned, rx, dropped_writer))
            .context("spawning SQLite writer thread")?;

        Ok(Self {
            tx: tx.clone(),
            join: Some(join),
            client: StoreClient {
                tx,
                path: path.to_path_buf(),
                dropped,
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

impl StoreClient {
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

    pub fn baseline(&self) -> Result<BaselineData> {
        let conn = self.read_connection()?;
        let mut paths = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT COALESCE(exe, nix, comm), subject FROM events WHERE kind LIKE 'file.%'
             UNION
             SELECT COALESCE(exe, nix, app), subject FROM activities WHERE kind LIKE 'file.%'",
        )?;
        let rows = stmt.query_map([], |row| {
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
             WHERE kind LIKE 'net.%' AND kind NOT IN ('net.traffic', 'net.listen')",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            network.push(row?);
        }
        Ok(BaselineData::from_pairs(paths, network))
    }

    pub fn recent_activities(&self, limit: usize) -> Result<Value> {
        let conn = self.read_connection()?;
        let limit = limit.clamp(1, MAX_QUERY_LIMIT);
        let mut stmt = conn.prepare(
            "SELECT bucket_ms, kind, app, subject, count, bytes, unit, nix
             FROM activities ORDER BY bucket_ms DESC, count DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], activity_row)?;
        Ok(json!({ "activities": collect(rows)? }))
    }

    pub fn app_activities(&self, app: &str, limit: usize) -> Result<Value> {
        let conn = self.read_connection()?;
        let limit = limit.clamp(1, MAX_QUERY_LIMIT);
        let mut stmt = conn.prepare(
            "SELECT bucket_ms, kind, app, subject, count, bytes, unit, nix
             FROM activities WHERE app = ?1 ORDER BY bucket_ms DESC, count DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![app, limit as i64], activity_row)?;
        let activities = collect(rows)?;

        let mut stmt = conn.prepare(
            "SELECT ts_ms, kind, comm, subject, path, from_path, to_path,
                    addr, local_port, remote_port, bytes, count
             FROM events WHERE comm = ?1 ORDER BY ts_ms DESC LIMIT ?2",
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
        let limit = limit.clamp(1, MAX_QUERY_LIMIT);
        let mut stmt = conn.prepare(
            "SELECT bucket_ms, kind, app, subject, count, bytes, unit, nix
             FROM activities WHERE kind LIKE 'net.%'
             ORDER BY bucket_ms DESC, bytes DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], activity_row)?;
        let activities = collect(rows)?;

        let mut stmt = conn.prepare(
            "SELECT ts_ms, kind, comm, subject, path, from_path, to_path,
                    addr, local_port, remote_port, bytes, count
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
        let limit = limit.clamp(1, MAX_QUERY_LIMIT);
        let mut stmt = conn.prepare(
            "SELECT bucket_ms, kind, app, subject, count, bytes, unit, nix
             FROM activities WHERE subject = ?1 ORDER BY bucket_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![path, limit as i64], activity_row)?;
        let activities = collect(rows)?;

        let mut stmt = conn.prepare(
            "SELECT ts_ms, kind, comm, subject, path, from_path, to_path,
                    addr, local_port, remote_port, bytes, count
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
        let conn = self.read_connection()?;
        let limit = limit.clamp(1, MAX_QUERY_LIMIT);
        let mut stmt = conn.prepare(
            "SELECT ts_ms, severity, title, details
             FROM incidents ORDER BY ts_ms DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let details: String = row.get(3)?;
            Ok(json!({
                "ts_ms": row.get::<_, i64>(0)?,
                "severity": row.get::<_, String>(1)?,
                "title": row.get::<_, String>(2)?,
                "details": serde_json::from_str::<Value>(&details).unwrap_or(Value::String(details)),
            }))
        })?;
        Ok(json!({ "incidents": collect(rows)? }))
    }

    fn read_connection(&self) -> Result<Connection> {
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening database {} read-only", self.path.display()))?;
        conn.busy_timeout(Duration::from_millis(2000))?;
        Ok(conn)
    }
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
    }))
}

fn raw_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
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
            ObservedEvent::Exec(event) => {
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
        Some(row)
    }
}

fn identity(event: &ObservedEvent) -> (String, u32, u32, String) {
    match event {
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
        "CREATE TABLE IF NOT EXISTS events (
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
            exe TEXT
        );
        CREATE INDEX IF NOT EXISTS activities_bucket ON activities(bucket_ms);
        CREATE INDEX IF NOT EXISTS activities_app ON activities(app, bucket_ms);
        CREATE INDEX IF NOT EXISTS activities_subject ON activities(subject, bucket_ms);

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY,
            ts_ms INTEGER NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS incidents_ts ON incidents(ts_ms);",
    )?;
    let _ = conn.execute("ALTER TABLE events ADD COLUMN exe TEXT", []);
    let _ = conn.execute("ALTER TABLE activities ADD COLUMN exe TEXT", []);
    Ok(())
}

fn writer_loop(path: PathBuf, rx: Receiver<StoreMsg>, dropped: Arc<AtomicU64>) {
    let mut conn = match Connection::open(&path).context("opening writer connection") {
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
    let mut last_maintenance = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(StoreMsg::Event(event)) => {
                batch.push(*event);
                if batch.len() >= BATCH_SIZE
                    && let Err(err) = flush_events(&mut conn, &mut batch)
                {
                    log::error!("store event flush failed: {err:#}");
                }
            }
            Ok(StoreMsg::Incident(incident)) => {
                if let Err(err) = flush_events(&mut conn, &mut batch) {
                    log::error!("store event flush failed: {err:#}");
                }
                if let Err(err) = insert_incident(&conn, &incident) {
                    log::error!("store incident insert failed: {err:#}");
                }
            }
            Ok(StoreMsg::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                if let Err(err) = flush_events(&mut conn, &mut batch) {
                    log::error!("store final flush failed: {err:#}");
                }
                break;
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Err(err) = flush_events(&mut conn, &mut batch) {
                    log::error!("store timed flush failed: {err:#}");
                }
            }
        }

        if last_maintenance.elapsed() >= MAINTENANCE_INTERVAL {
            last_maintenance = Instant::now();
            if let Err(err) = maintain(&mut conn) {
                log::error!("store maintenance failed: {err:#}");
            }
        }
    }
    let _ = dropped;
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
        "INSERT INTO incidents (ts_ms, severity, title, details)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            incident.ts_ms,
            incident.severity,
            incident.title,
            incident.details
        ],
    )?;
    Ok(())
}

fn maintain(conn: &mut Connection) -> Result<()> {
    let now = now_ms();
    let raw_cutoff = now - RAW_RETENTION_MS;
    let activity_cutoff = now - ACTIVITY_RETENTION_MS;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO activities (bucket_ms, kind, app, subject, count, bytes, unit, nix, exe)
         SELECT (ts_ms / ?1) * ?1, kind, comm, subject, SUM(COALESCE(count, 1)),
                COALESCE(SUM(bytes), 0), MAX(unit), MAX(nix), exe
         FROM events WHERE ts_ms < ?2
         GROUP BY (ts_ms / ?1) * ?1, kind, comm, subject, exe",
        params![ACTIVITY_BUCKET_MS, raw_cutoff],
    )?;
    tx.execute("DELETE FROM events WHERE ts_ms < ?1", params![raw_cutoff])?;
    tx.execute(
        "DELETE FROM activities WHERE bucket_ms < ?1",
        params![activity_cutoff],
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
            ts_ms: now_ms() as u64,
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
