use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::{Frame, Terminal};
use serde_json::{Value, json};

use crate::ack;
use crate::client;

const TABS: [&str; 5] = ["Overview", "Incidents", "Activity", "Apps & Flows", "Noise"];
const REFRESH: Duration = Duration::from_secs(2);
const FULL_REFRESH: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Snapshot {
    status: Value,
    incidents: Value,
    activity: Value,
    apps: Value,
    flows: Value,
    summaries: Value,
    db: Value,
    noise: Value,
    error: Option<String>,
}

impl Snapshot {
    fn empty() -> Self {
        Self {
            status: json!({}),
            incidents: json!({}),
            activity: json!({}),
            apps: json!({}),
            flows: json!({}),
            summaries: json!({}),
            db: json!({}),
            noise: json!({}),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    List,
    Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkScope {
    All,
    SameMachine,
    LocalNetwork,
    Remote,
}

impl NetworkScope {
    fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::SameMachine => "Same machine",
            Self::LocalNetwork => "Local network",
            Self::Remote => "Remote",
        }
    }
    fn next(self) -> Self {
        match self {
            Self::All => Self::SameMachine,
            Self::SameMachine => Self::LocalNetwork,
            Self::LocalNetwork => Self::Remote,
            Self::Remote => Self::All,
        }
    }
    fn matches(self, flow: &Value) -> bool {
        if self == Self::All {
            return true;
        }
        let Some(remote) = endpoint_ip(flow["remote"].as_str().unwrap_or_default()) else {
            return false;
        };
        let loopback = is_loopback(remote);
        let local = is_private(remote);
        match self {
            Self::SameMachine => loopback,
            Self::LocalNetwork => !loopback && local,
            Self::Remote => !loopback && !local && !remote.is_unspecified(),
            Self::All => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextFilter {
    All,
    Host,
    Vopono,
    Container,
}

impl ContextFilter {
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Host => "host",
            Self::Vopono => "vopono",
            Self::Container => "container/ns",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::All => Self::Host,
            Self::Host => Self::Vopono,
            Self::Vopono => Self::Container,
            Self::Container => Self::All,
        }
    }

    fn matches(self, flow: &Value) -> bool {
        let kind = flow["network_context"]["kind"]
            .as_str()
            .unwrap_or("unknown");
        match self {
            Self::All => true,
            Self::Host => kind == "host",
            Self::Vopono => kind == "vopono",
            Self::Container => !matches!(kind, "host" | "vopono"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoleFilter {
    All,
    Listener,
    Inbound,
    Outbound,
    UdpPeer,
    Dns,
    Tracker,
}

impl RoleFilter {
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Listener => "listener",
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::UdpPeer => "udp_peer",
            Self::Dns => "dns",
            Self::Tracker => "tracker",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::All => Self::Listener,
            Self::Listener => Self::Inbound,
            Self::Inbound => Self::Outbound,
            Self::Outbound => Self::UdpPeer,
            Self::UdpPeer => Self::Dns,
            Self::Dns => Self::Tracker,
            Self::Tracker => Self::All,
        }
    }

    fn matches(self, flow: &Value) -> bool {
        let role = flow["role"].as_str().unwrap_or("unknown");
        match self {
            Self::All => true,
            Self::Listener => {
                role == "listener"
                    || (flow["direction"].as_str() == Some("inbound")
                        && flow["exposure"].as_str() == Some("published"))
            }
            Self::Inbound => role == "inbound",
            Self::Outbound => role == "outbound",
            Self::UdpPeer => role == "udp_peer",
            Self::Dns => role == "dns",
            Self::Tracker => role == "tracker",
        }
    }
}

fn endpoint_ip(endpoint: &str) -> Option<IpAddr> {
    let endpoint = endpoint.trim();
    if let Some(rest) = endpoint.strip_prefix('[') {
        let end = rest.find("]:")?;
        rest[..end].parse().ok()
    } else {
        let (host, _) = endpoint.rsplit_once(':')?;
        host.parse().ok()
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

struct App {
    socket: std::path::PathBuf,
    tab: usize,
    selected: [usize; 5],
    list_offset: [usize; 5],
    list_height: [usize; 5],
    detail_scroll: [u16; 5],
    focus: Focus,
    freeze: bool,
    follow: bool,
    network_scope: NetworkScope,
    context_filter: ContextFilter,
    role_filter: RoleFilter,
    help: bool,
    snapshot: Snapshot,
    review: ack::Store,
    tab_area: Rect,
    list_area: Rect,
    detail_area: Rect,
    scope_area: Rect,
    last_refresh: Instant,
    last_full: Instant,
}

impl App {
    fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
            tab: 0,
            selected: [0; 5],
            list_offset: [0; 5],
            list_height: [1; 5],
            detail_scroll: [0; 5],
            focus: Focus::List,
            freeze: false,
            follow: true,
            network_scope: NetworkScope::All,
            context_filter: ContextFilter::All,
            role_filter: RoleFilter::All,
            help: false,
            snapshot: Snapshot::empty(),
            review: ack::Store::load(),
            tab_area: Rect::default(),
            list_area: Rect::default(),
            detail_area: Rect::default(),
            scope_area: Rect::default(),
            last_refresh: Instant::now() - REFRESH,
            last_full: Instant::now() - FULL_REFRESH,
        }
    }

    fn refresh(&mut self, full: bool) {
        let mut snapshot = Snapshot::empty();
        let status = client::request(&self.socket, &json!({ "op": "status" }));
        let status = match status {
            Ok(value) => value,
            Err(err) => {
                snapshot.error = Some(format!("{err:#}"));
                self.snapshot = snapshot;
                self.last_refresh = Instant::now();
                return;
            }
        };
        if status.get("error").is_some() {
            snapshot.error = Some(status["error"].as_str().unwrap_or("daemon error").into());
            self.snapshot = snapshot;
            self.last_refresh = Instant::now();
            return;
        }
        snapshot.status = status;
        let get = |op: &str, limit: usize| {
            client::request(&self.socket, &json!({ "op": op, "limit": limit }))
                .unwrap_or_else(|_| json!({}))
        };
        snapshot.incidents = get("incidents", 300);
        snapshot.activity = get("activity", 500);
        snapshot.apps = get("apps", 100);
        snapshot.flows = get("flows", 500);
        if full {
            snapshot.summaries = get("summaries", 100);
            snapshot.db = get("db", 1);
            snapshot.noise = get("noise", 500);
            self.last_full = Instant::now();
        } else {
            snapshot.summaries = std::mem::take(&mut self.snapshot.summaries);
            snapshot.db = std::mem::take(&mut self.snapshot.db);
            snapshot.noise = std::mem::take(&mut self.snapshot.noise);
        }
        self.snapshot = snapshot;
        self.last_refresh = Instant::now();
    }

    fn rows<'a>(&'a self, key: &str) -> &'a [Value] {
        let value = match key {
            "incidents" => &self.snapshot.incidents["incidents"],
            "activity" => &self.snapshot.activity["activity"],
            "apps" => &self.snapshot.apps["apps"],
            "flows" => &self.snapshot.flows["flows"],
            _ => return &[],
        };
        value.as_array().map(Vec::as_slice).unwrap_or(&[])
    }

    fn ensure_visible(&mut self, tab: usize) {
        let key = match tab {
            1 => "incidents",
            2 => "activity",
            3 => "apps",
            _ => return,
        };
        let len = self.rows(key).len();
        if len == 0 {
            self.selected[tab] = 0;
            self.list_offset[tab] = 0;
            return;
        }
        self.selected[tab] = self.selected[tab].min(len - 1);
        let height = self.list_height[tab].max(1);
        if self.selected[tab] < self.list_offset[tab] {
            self.list_offset[tab] = self.selected[tab];
        } else if self.selected[tab] >= self.list_offset[tab] + height {
            self.list_offset[tab] = self.selected[tab] + 1 - height;
        }
        let max_offset = len.saturating_sub(height);
        self.list_offset[tab] = self.list_offset[tab].min(max_offset);
    }

    fn move_selection(&mut self, delta: isize) {
        let tab = self.tab;
        let key = match tab {
            1 => "incidents",
            2 => "activity",
            3 => "apps",
            _ => return,
        };
        let len = self.rows(key).len();
        if len == 0 {
            return;
        }
        let current = self.selected[tab].min(len - 1) as isize;
        let next = (current + delta).rem_euclid(len as isize) as usize;
        if next != self.selected[tab] {
            self.selected[tab] = next;
            self.detail_scroll[tab] = 0;
        }
        self.ensure_visible(tab);
    }

    fn cycle_focus(&mut self) {
        if !matches!(self.tab, 1..=3) {
            return;
        }
        self.focus = match self.focus {
            Focus::List => Focus::Detail,
            Focus::Detail => Focus::List,
        };
    }

    fn handle_click(&mut self, column: u16, row: u16) {
        if contains(self.tab_area, column, row)
            && let Some(index) = label_index_at(self.tab_area.x, column, &TABS, 1)
        {
            self.tab = index;
            self.focus = Focus::List;
            return;
        }
        if self.tab == 3
            && contains(self.scope_area, column, row)
            && let Some(index) = label_index_at(
                self.scope_area.x,
                column,
                &["All", "Same machine", "Local network", "Remote"],
                3,
            )
        {
            self.network_scope = match index {
                0 => NetworkScope::All,
                1 => NetworkScope::SameMachine,
                2 => NetworkScope::LocalNetwork,
                _ => NetworkScope::Remote,
            };
            return;
        }
        if contains(self.list_area, column, row) {
            self.focus = Focus::List;
            let key = match self.tab {
                1 => "incidents",
                2 => "activity",
                3 => "apps",
                _ => return,
            };
            let len = self.rows(key).len();
            if len == 0 {
                return;
            }
            let inner_row = row.saturating_sub(self.list_area.y + 2) as usize;
            let selected = self.list_offset[self.tab] + inner_row;
            if selected < len {
                self.selected[self.tab] = selected;
                self.detail_scroll[self.tab] = 0;
                self.ensure_visible(self.tab);
            }
            return;
        }
        if contains(self.detail_area, column, row) && matches!(self.tab, 1..=3) {
            self.focus = Focus::Detail;
        }
    }

    fn page(&mut self, direction: isize) {
        let height = self.list_height[self.tab].max(1) as isize;
        if self.focus == Focus::Detail && matches!(self.tab, 1 | 2) {
            self.scroll_detail(direction * height);
        } else {
            self.move_selection(direction * height);
        }
    }

    fn half_page(&mut self, direction: isize) {
        let amount = (self.list_height[self.tab].max(1) / 2).max(1) as isize;
        if self.focus == Focus::Detail && matches!(self.tab, 1 | 2) {
            self.scroll_detail(direction * amount);
        } else {
            self.move_selection(direction * amount);
        }
    }

    fn scroll_detail(&mut self, delta: isize) {
        let current = self.detail_scroll[self.tab];
        self.detail_scroll[self.tab] = if delta < 0 {
            current.saturating_sub((-delta) as u16)
        } else {
            current.saturating_add(delta as u16)
        };
    }

    fn review_action(&mut self, key: char) {
        if self.tab != 1 {
            return;
        }
        let Some(row) = self.snapshot.incidents["incidents"]
            .as_array()
            .and_then(|rows| rows.get(self.selected[1]))
        else {
            return;
        };
        let id = row["id"].as_str().unwrap_or_default().to_string();
        let app = incident_app(row);
        let rule = row["details"]["rule"]
            .as_str()
            .or_else(|| row["title"].as_str())
            .unwrap_or_default()
            .to_string();
        match key {
            'a' => {
                let _ = self.review.ack(&id, None);
            }
            'A' => {
                let _ = self.review.unack(&id);
            }
            'm' => {
                let _ = self
                    .review
                    .mute(&app, &rule, now_ms().saturating_add(3_600_000));
            }
            'u' => {
                let _ = self.review.unmute(&app, &rule);
            }
            _ => {}
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn when(ts: Option<u64>) -> String {
    let Some(ts) = ts else {
        return "?".into();
    };
    let now = now_ms();
    if ts > now {
        return format!("+{}s", (ts - now) / 1000);
    }
    let seconds = (now - ts) / 1000;
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}

fn truncate(text: &str, width: usize) -> String {
    let text = text.replace(['\n', '\r'], " ");
    if text.chars().count() <= width {
        text
    } else {
        let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn string(value: &Value) -> String {
    value.as_str().map(str::to_string).unwrap_or_else(|| {
        if value.is_null() {
            "?".into()
        } else {
            value.to_string()
        }
    })
}

fn incident_app(row: &Value) -> String {
    row["details"]["actor"]["application"]["name"]
        .as_str()
        .or_else(|| row["comm"].as_str())
        .unwrap_or("?")
        .to_string()
}

fn flow_app(flow: &Value) -> String {
    flow["application"]["name"]
        .as_str()
        .unwrap_or("unknown application")
        .to_string()
}

fn flow_context(flow: &Value) -> String {
    flow["network_context"]["label"]
        .as_str()
        .or_else(|| flow["network_context"]["name"].as_str())
        .or_else(|| flow["network_context"]["id"].as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn incident_detail(row: &Value) -> String {
    let mut lines = vec![
        format!("{} [{}]", string(&row["title"]), string(&row["severity"])),
        format!("Application: {}", incident_app(row)),
        format!(
            "PID: {}   Unit: {}",
            string(&row["pid"]),
            string(&row["unit"])
        ),
    ];
    if let Some(path) = row["path"].as_str() {
        lines.push(format!("Path: {path}"));
    }
    if let Some(scope) = row["details"]["source_scope"].as_str() {
        lines.push(format!("Source scope: {scope}"));
    }
    if let Some(trust) = row["details"]["package_trust"].as_object() {
        lines.push(format!(
            "Binary trust: {} ({}; hash_match={})",
            trust
                .get("status")
                .map(string)
                .unwrap_or_else(|| "?".into()),
            trust
                .get("source")
                .map(string)
                .unwrap_or_else(|| "?".into()),
            trust
                .get("hash_match")
                .map(string)
                .unwrap_or_else(|| "?".into())
        ));
    }
    if let Some(argv) = row["details"]["actor"]["argv"].as_array() {
        lines.push(format!(
            "Ran: {}",
            argv.iter().map(string).collect::<Vec<_>>().join(" ")
        ));
    }
    if row["details"]["rule"] == "bulk_mutation" {
        lines.push(format!(
            "Changed files: {}",
            string(&row["details"]["files_in_window"])
        ));
        if let Some(files) = row["details"]["files"].as_array() {
            for file in files.iter().take(32) {
                lines.push(format!("  - {}", string(file)));
            }
            if row["details"]["files_truncated"] == true {
                lines.push("  … additional files not shown".into());
            }
        }
    }
    lines.push(String::new());
    lines.push(serde_json::to_string_pretty(row).unwrap_or_default());
    lines.join("\n")
}

fn severity_color(severity: &str) -> Color {
    match severity {
        "high" => Color::Red,
        "medium" => Color::Yellow,
        "low" => Color::Green,
        _ => Color::Cyan,
    }
}

/// Map a click column to a tab label. `Tabs` renders one space of padding on
/// each side of every title, so hit testing must use the label widths rather
/// than dividing the bar evenly.
fn label_index_at(area_x: u16, column: u16, titles: &[&str], divider_width: u16) -> Option<usize> {
    let mut cursor = area_x.saturating_add(1);
    for (index, title) in titles.iter().enumerate() {
        if index > 0 {
            cursor = cursor.saturating_add(divider_width);
        }
        let width = title.chars().count() as u16 + 2;
        if column >= cursor && column < cursor.saturating_add(width) {
            return Some(index);
        }
        cursor = cursor.saturating_add(width);
    }
    None
}

fn contains(rect: Rect, column: u16, row: u16) -> bool {
    rect.width > 0
        && rect.height > 0
        && column >= rect.x
        && column < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}

fn block(title: impl Into<String>, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(title.into())
        .border_style(if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        })
}

fn header(app: &App) -> Vec<Line<'static>> {
    if let Some(error) = &app.snapshot.error {
        return vec![
            Line::from(vec![
                Span::styled(
                    " electric-eye ",
                    Style::default().fg(Color::Black).bg(Color::Red),
                ),
                Span::raw(" "),
                Span::styled(error.clone(), Style::default().fg(Color::Red)),
            ]),
            Line::from(" press r to retry, q to quit"),
        ];
    }
    let status = &app.snapshot.status;
    let counts: Vec<u64> = status["capture_loss"]
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    // The fourth counter is unresolved-path uncertainty, not event loss.
    let loss = counts
        .get(..3)
        .map(|values| {
            values
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_else(|| "?".into());
    let uncertain = counts.get(3).copied().unwrap_or(0);
    let store = &status["store"];
    let db = &app.snapshot.db;
    let free = db["disk_free_bytes"].as_u64();
    let disk = free
        .map(electric_eye_core::humanize_bytes)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".into());
    let loss_style = if loss.split(',').any(|value| value.trim() != "0") {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    let mut first = vec![
        Span::styled(
            " electric-eye ",
            Style::default().fg(Color::Black).bg(Color::Cyan),
        ),
        Span::raw(format!(
            " {}  up {}s  events {}  ",
            string(&status["daemon"]),
            string(&status["uptime_secs"]),
            string(&status["events_total"]),
        )),
        Span::styled(format!("loss [{loss}]"), loss_style),
    ];
    if uncertain > 0 {
        first.push(Span::styled(
            format!(" path? {uncertain}"),
            Style::default().fg(Color::Yellow),
        ));
    }
    first.push(Span::raw(format!(
        "  store drops {}  DB {}  free {}",
        string(&store["dropped"]),
        electric_eye_core::humanize_bytes(store["db_bytes"].as_u64().unwrap_or(0)),
        disk,
    )));
    if app.freeze {
        first.push(Span::styled(
            "  FROZEN",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    vec![
        Line::from(first),
        Line::from(vec![
            Span::styled(
                format!(" {} ", TABS[app.tab]),
                Style::default().fg(Color::Black).bg(Color::Cyan),
            ),
            Span::raw(format!(
                " focus: {}  {}  q quit  ? help  j/k select  PgUp/PgDn scroll  Ctrl+D/U half-page  Space freeze",
                match app.focus {
                    Focus::List => "list",
                    Focus::Detail => "detail",
                },
                if app.follow {
                    "following"
                } else {
                    "not following"
                }
            )),
        ]),
    ]
}

fn visible_window(values: &[Value], offset: usize, height: usize) -> (usize, &[Value]) {
    let start = offset.min(values.len());
    let end = (start + height.max(1)).min(values.len());
    (start, &values[start..end])
}

fn render_overview(frame: &mut Frame, app: &App, area: Rect) {
    let status = &app.snapshot.status;
    let db = &app.snapshot.db;
    let noise = app.snapshot.noise["candidates"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    let summaries = app.snapshot.summaries["summaries"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    let lines = vec![
        Line::from(format!("Kernel: {}", string(&status["kernel"]))),
        Line::from(format!(
            "Attached probes: {}   skipped: {}",
            status["attached_probes"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0),
            status["skipped_probes"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0),
        )),
        Line::from(format!(
            "Storage: {} raw events, {} activities, {} incidents, {} documents",
            string(&db["raw_events"]),
            string(&db["activities"]),
            string(&db["incidents"]),
            string(&db["documents_total"]),
        )),
        Line::from(format!(
            "Database: {} main, {} WAL, {} free",
            electric_eye_core::humanize_bytes(db["db_bytes"].as_u64().unwrap_or(0)),
            electric_eye_core::humanize_bytes(db["wal_bytes"].as_u64().unwrap_or(0)),
            db["disk_free_bytes"]
                .as_u64()
                .map(electric_eye_core::humanize_bytes)
                .unwrap_or_else(|| "?".into()),
        )),
        Line::from(format!(
            "Recent summaries: {summaries}   noise candidates: {noise}"
        )),
        Line::from(""),
        Line::from("Use the tabs to inspect incidents, activity, applications and flows."),
        Line::from("Capture is read-only; ack/mute affects only your local review state."),
        Line::from("Use `electric-eye noise` to tune capture filters."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(block("Overview", true))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_incidents(frame: &mut Frame, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);
    app.list_area = layout[0];
    app.detail_area = layout[1];
    app.list_height[1] = layout[0].height.saturating_sub(3) as usize;
    app.ensure_visible(1);
    let values = app.snapshot.incidents["incidents"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let (start, visible) = visible_window(values, app.list_offset[1], app.list_height[1]);
    let selected = app.selected[1].saturating_sub(start);
    let rows = visible
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let severity = row["severity"].as_str().unwrap_or("low");
            let style = if index == selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default().fg(severity_color(severity))
            };
            Row::new(vec![
                Cell::from(app.review.state(row).unwrap_or("-").to_string())
                    .style(Style::default().fg(Color::Magenta)),
                Cell::from(when(row["ts_ms"].as_u64())).style(Style::default().fg(Color::Gray)),
                Cell::from(severity).style(Style::default().fg(severity_color(severity))),
                Cell::from(truncate(row["title"].as_str().unwrap_or_default(), 60)),
                Cell::from(truncate(&incident_app(row), 20)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(20),
            Constraint::Length(20),
        ],
    )
    .header(
        Row::new(vec!["STATE", "TIME", "SEV", "TITLE", "APP"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(block(
        format!(
            "Incidents ({}) offset {}/{}",
            values.len(),
            app.list_offset[1],
            values.len().saturating_sub(app.list_height[1])
        ),
        app.focus == Focus::List,
    ));
    frame.render_widget(table, layout[0]);
    let detail = values
        .get(app.selected[1])
        .map(incident_detail)
        .unwrap_or_else(|| "No incidents recorded.".into());
    frame.render_widget(
        Paragraph::new(detail)
            .block(block("Incident detail", app.focus == Focus::Detail))
            .scroll((app.detail_scroll[1], 0))
            .wrap(Wrap { trim: true }),
        layout[1],
    );
}

fn render_activity(frame: &mut Frame, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);
    app.list_area = layout[0];
    app.detail_area = layout[1];
    app.list_height[2] = layout[0].height.saturating_sub(3) as usize;
    app.ensure_visible(2);
    let values = app.snapshot.activity["activity"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let (start, visible) = visible_window(values, app.list_offset[2], app.list_height[2]);
    let selected = app.selected[2].saturating_sub(start);
    let rows = visible
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let event = &row["event"];
            let action = event["event"].as_str().unwrap_or("?");
            let subject = event["path"]
                .as_str()
                .or_else(|| event["from_path"].as_str())
                .or_else(|| event["to_path"].as_str())
                .unwrap_or_default();
            let color = match action {
                "exec" | "fork" | "exit" => Color::Magenta,
                "connect" | "accept" | "listen" | "traffic" => Color::Blue,
                "file_write" | "file_open" | "file_unlink" | "file_rename" => Color::Green,
                _ => Color::Gray,
            };
            let style = if index == selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default().fg(color)
            };
            Row::new(vec![
                Cell::from(when(row["ts_ms"].as_u64())).style(Style::default().fg(Color::Gray)),
                Cell::from(truncate(action, 14)).style(Style::default().fg(color)),
                Cell::from(truncate(
                    row["application"]["name"]
                        .as_str()
                        .unwrap_or(event["comm"].as_str().unwrap_or("?")),
                    18,
                )),
                Cell::from(truncate(subject, 90)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(18),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["TIME", "EVENT", "APP", "SUBJECT"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(block(
        format!(
            "Activity ({}) offset {}/{}",
            values.len(),
            app.list_offset[2],
            values.len().saturating_sub(app.list_height[2])
        ),
        app.focus == Focus::List,
    ));
    frame.render_widget(table, layout[0]);
    let detail = values
        .get(app.selected[2])
        .map(|row| serde_json::to_string_pretty(row).unwrap_or_default())
        .unwrap_or_else(|| "No activity recorded.".into());
    frame.render_widget(
        Paragraph::new(detail)
            .block(block("Event detail", app.focus == Focus::Detail))
            .scroll((app.detail_scroll[2], 0))
            .wrap(Wrap { trim: true }),
        layout[1],
    );
}

fn render_apps(frame: &mut Frame, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(48),
            Constraint::Length(3),
            Constraint::Percentage(49),
        ])
        .split(area);
    app.list_area = layout[0];
    app.scope_area = layout[1];
    app.detail_area = layout[2];
    app.list_height[3] = layout[0].height.saturating_sub(3) as usize;
    app.ensure_visible(3);
    let all_flows = app.snapshot.flows["flows"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let flows: Vec<&Value> = all_flows
        .iter()
        .filter(|flow| {
            app.network_scope.matches(flow)
                && app.context_filter.matches(flow)
                && app.role_filter.matches(flow)
        })
        .collect();
    let mut contexts_by_app: HashMap<String, BTreeSet<String>> = HashMap::new();
    for flow in &flows {
        contexts_by_app
            .entry(flow_app(flow))
            .or_default()
            .insert(flow_context(flow));
    }
    let mut totals: HashMap<String, (u64, u64, u64)> = HashMap::new();
    let mut sent_total = 0_u64;
    let mut recv_total = 0_u64;
    for flow in &flows {
        let sent = flow["sent"].as_u64().unwrap_or(0);
        let received = flow["received"].as_u64().unwrap_or(0);
        sent_total = sent_total.saturating_add(sent);
        recv_total = recv_total.saturating_add(received);
        let entry = totals.entry(flow_app(flow)).or_default();
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(sent);
        entry.2 = entry.2.saturating_add(received);
    }
    let all_apps = app.snapshot.apps["apps"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let filtered = app.network_scope != NetworkScope::All
        || app.context_filter != ContextFilter::All
        || app.role_filter != RoleFilter::All;
    let apps: Vec<Value> = all_apps
        .into_iter()
        .filter(|row| {
            !filtered
                || row["name"]
                    .as_str()
                    .is_some_and(|name| contexts_by_app.contains_key(name))
        })
        .collect();
    let (start, visible) = visible_window(&apps, app.list_offset[3], app.list_height[3]);
    let selected = app.selected[3].saturating_sub(start);
    let rows = visible
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let name = row["name"].as_str().unwrap_or_default();
            let net = totals.get(name).copied().unwrap_or((0, 0, 0));
            let style = if index == selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            let contexts = contexts_by_app
                .get(name)
                .map(|values| values.iter().cloned().collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            Row::new(vec![
                Cell::from(truncate(name, 24)),
                Cell::from(truncate(&contexts, 18)).style(Style::default().fg(Color::Magenta)),
                Cell::from(string(&row["events"])).style(Style::default().fg(Color::Gray)),
                Cell::from(net.0.to_string()).style(Style::default().fg(Color::Blue)),
                Cell::from(electric_eye_core::humanize_bytes(net.1).to_string())
                    .style(Style::default().fg(Color::Green)),
                Cell::from(electric_eye_core::humanize_bytes(net.2).to_string())
                    .style(Style::default().fg(Color::Magenta)),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(24),
                Constraint::Length(18),
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Length(12),
            ],
        )
        .header(
            Row::new(vec![
                "APPLICATION",
                "CONTEXT",
                "EVENTS",
                "FLOWS",
                "SENT",
                "RECEIVED",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(block(
            format!(
                "Applications — {} scope, context {}, role {}, {} events",
                app.network_scope.label(),
                app.context_filter.label(),
                app.role_filter.label(),
                apps.len()
            ),
            app.focus == Focus::List,
        )),
        layout[0],
    );
    frame.render_widget(
        Tabs::new(vec!["All", "Same machine", "Local network", "Remote"])
            .select(match app.network_scope {
                NetworkScope::All => 0,
                NetworkScope::SameMachine => 1,
                NetworkScope::LocalNetwork => 2,
                NetworkScope::Remote => 3,
            })
            .block(block("Network scope — s cycles", true))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(" | "),
        layout[1],
    );
    let flow_rows = flows
        .iter()
        .map(|flow| {
            Row::new(vec![
                Cell::from(truncate(&flow_app(flow), 18)),
                Cell::from(truncate(&flow_context(flow), 18))
                    .style(Style::default().fg(Color::Magenta)),
                Cell::from(truncate(
                    &format!("{}/{}", string(&flow["role"]), string(&flow["protocol"])),
                    12,
                )),
                Cell::from(truncate(
                    &format!("{} -> {}", string(&flow["local"]), string(&flow["remote"])),
                    46,
                )),
                Cell::from(format!(
                    "{} / {}",
                    electric_eye_core::humanize_bytes(flow["sent"].as_u64().unwrap_or(0)),
                    electric_eye_core::humanize_bytes(flow["received"].as_u64().unwrap_or(0))
                )),
            ])
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Table::new(
            flow_rows,
            [
                Constraint::Length(18),
                Constraint::Length(18),
                Constraint::Length(12),
                Constraint::Min(32),
                Constraint::Length(18),
            ],
        )
        .header(
            Row::new(vec!["APP", "CONTEXT", "ROLE", "ENDPOINTS", "SENT / RECV"]).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(block(
            format!(
                "Flows ({}) — sent {}, received {}",
                flows.len(),
                electric_eye_core::humanize_bytes(sent_total),
                electric_eye_core::humanize_bytes(recv_total)
            ),
            app.focus == Focus::Detail,
        )),
        layout[2],
    );
}

fn render_noise(frame: &mut Frame, app: &App, area: Rect) {
    let candidates = app.snapshot.noise["candidates"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut lines = Vec::new();
    for candidate in candidates {
        let kind = candidate["kind"].as_str().unwrap_or("?");
        let value = candidate["value"].as_str().unwrap_or("?");
        let count = match kind {
            "path" => format!("{} events", string(&candidate["events"])),
            "application" => format!("{} incidents", string(&candidate["incidents"])),
            "correlation" => format!("{} summaries", string(&candidate["summaries"])),
            _ => String::new(),
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{kind:12} "),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{value}  {count}")),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from("No obvious noise candidates."));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Suggested configuration:",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    for line in app.snapshot.noise["suggested_config"]
        .as_str()
        .unwrap_or_default()
        .lines()
    {
        lines.push(Line::from(line.to_string()));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block("Noise suggestions", true))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_help(frame: &mut Frame) {
    let area = centered_rect(70, 70, frame.area());
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("Electric Eye TUI — capture is read-only"),
        Line::from(""),
        Line::from("1..5 / Tab   switch tab"),
        Line::from("h/[ , l/]    cycle focus panes (wraps)"),
        Line::from("j / k        next / previous row (wraps)"),
        Line::from("PgUp/PgDn    page list or detail"),
        Line::from("Ctrl+U/D     half-page list or detail"),
        Line::from("mouse        click tabs, rows, panes, scope; wheel scrolls"),
        Line::from("Space / p    freeze/unfreeze screen"),
        Line::from("f            toggle activity follow"),
        Line::from("a / A        acknowledge / unacknowledge incident"),
        Line::from("m / u        mute / unmute incident app+rule for 1h"),
        Line::from("s            cycle network scope"),
        Line::from("c / v        cycle context / role filter"),
        Line::from("r            refresh now"),
        Line::from("?            help"),
        Line::from("Esc          close help (does not quit)"),
        Line::from("q            quit"),
        Line::from(""),
        Line::from("Ack/mute is local state; the daemon remains read-only."),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(block("Help", true))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn ui(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(frame.area());
    app.tab_area = chunks[1];
    frame.render_widget(Paragraph::new(header(app)), chunks[0]);
    frame.render_widget(
        Tabs::new(TABS.to_vec())
            .select(app.tab)
            .block(block("Views", true))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        chunks[1],
    );
    match app.tab {
        0 => render_overview(frame, app, chunks[2]),
        1 => render_incidents(frame, app, chunks[2]),
        2 => render_activity(frame, app, chunks[2]),
        3 => render_apps(frame, app, chunks[2]),
        4 => render_noise(frame, app, chunks[2]),
        _ => {}
    }
    frame.render_widget(
        Paragraph::new(
            "1-5/Tab views  h/[ l/] focus  j/k select  PgUp/PgDn  Ctrl+U/D  Space freeze  s scope  c context  v role  a/A ack  m/u mute  ? help  Esc close help  q quit",
        )
        .style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );
    if app.help {
        render_help(frame);
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, DisableMouseCapture, LeaveAlternateScreen);
}

pub fn run(socket: &Path) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        original_hook(info);
    }));
    let mut app = App::new(socket);
    app.refresh(true);

    let result = (|| -> anyhow::Result<()> {
        loop {
            terminal.draw(|frame| ui(frame, &mut app))?;
            if event::poll(Duration::from_millis(150))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Esc => app.help = false,
                        KeyCode::Char('?') => app.help = !app.help,
                        KeyCode::Char('r') => app.refresh(true),
                        KeyCode::Char('f') => app.follow = !app.follow,
                        KeyCode::Char(' ') | KeyCode::Char('p') => app.freeze = !app.freeze,
                        KeyCode::Char('s') => app.network_scope = app.network_scope.next(),
                        KeyCode::Char('c') => app.context_filter = app.context_filter.next(),
                        KeyCode::Char('v') => app.role_filter = app.role_filter.next(),
                        KeyCode::Char('h') | KeyCode::Char('[') => app.cycle_focus(),
                        KeyCode::Char('l') | KeyCode::Char(']') => app.cycle_focus(),
                        KeyCode::Char('1') => {
                            app.tab = 0;
                            app.focus = Focus::List;
                        }
                        KeyCode::Char('2') => {
                            app.tab = 1;
                            app.focus = Focus::List;
                        }
                        KeyCode::Char('3') => {
                            app.tab = 2;
                            app.focus = Focus::List;
                        }
                        KeyCode::Char('4') => {
                            app.tab = 3;
                            app.focus = Focus::List;
                        }
                        KeyCode::Char('5') => {
                            app.tab = 4;
                            app.focus = Focus::List;
                        }
                        KeyCode::Tab => {
                            app.tab = (app.tab + 1) % TABS.len();
                            app.focus = Focus::List;
                        }
                        KeyCode::BackTab => {
                            app.tab = (app.tab + TABS.len() - 1) % TABS.len();
                            app.focus = Focus::List;
                        }
                        KeyCode::PageUp => app.page(-1),
                        KeyCode::PageDown => app.page(1),
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.half_page(-1)
                        }
                        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.half_page(1)
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            if app.focus == Focus::Detail && matches!(app.tab, 1 | 2) {
                                app.scroll_detail(1);
                            } else {
                                app.move_selection(1);
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            if app.focus == Focus::Detail && matches!(app.tab, 1 | 2) {
                                app.scroll_detail(-1);
                            } else {
                                app.move_selection(-1);
                            }
                        }
                        KeyCode::Char('g') => {
                            app.selected[app.tab] = 0;
                            app.list_offset[app.tab] = 0;
                            app.detail_scroll[app.tab] = 0;
                        }
                        KeyCode::Char('G') => {
                            let key = match app.tab {
                                1 => "incidents",
                                2 => "activity",
                                3 => "apps",
                                _ => "",
                            };
                            app.selected[app.tab] = app.rows(key).len().saturating_sub(1);
                            app.detail_scroll[app.tab] = 0;
                            app.ensure_visible(app.tab);
                        }
                        KeyCode::Char('a')
                        | KeyCode::Char('A')
                        | KeyCode::Char('m')
                        | KeyCode::Char('u') => {
                            if let KeyCode::Char(key) = key.code {
                                app.review_action(key);
                            }
                        }
                        _ => {}
                    },
                    Event::Mouse(mouse) => match mouse.kind {
                        MouseEventKind::Down(MouseButton::Left) => {
                            app.handle_click(mouse.column, mouse.row)
                        }
                        MouseEventKind::ScrollUp => {
                            if app.focus == Focus::Detail && matches!(app.tab, 1 | 2) {
                                app.scroll_detail(-3);
                            } else {
                                app.move_selection(-3);
                            }
                        }
                        MouseEventKind::ScrollDown => {
                            if app.focus == Focus::Detail && matches!(app.tab, 1 | 2) {
                                app.scroll_detail(3);
                            } else {
                                app.move_selection(3);
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            if !app.freeze && app.last_refresh.elapsed() >= REFRESH {
                let full = app.last_full.elapsed() >= FULL_REFRESH;
                app.refresh(full);
            }
        }
        Ok(())
    })();
    restore_terminal();
    let _ = std::panic::take_hook();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_is_character_safe() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello w…");
    }

    #[test]
    fn time_formatting_handles_unknown() {
        assert_eq!(when(None), "?");
    }

    #[test]
    fn network_scope_classifies_loopback_private_and_public() {
        let flow = |remote: &str| json!({"local": "10.0.0.1:1234", "remote": remote});
        assert!(NetworkScope::SameMachine.matches(&flow("127.0.0.1:80")));
        assert!(NetworkScope::SameMachine.matches(&flow("[::1]:80")));
        assert!(NetworkScope::LocalNetwork.matches(&flow("192.168.1.2:80")));
        assert!(NetworkScope::Remote.matches(&flow("1.1.1.1:80")));
        assert!(!NetworkScope::Remote.matches(&flow("192.168.1.2:80")));
        assert!(!NetworkScope::LocalNetwork.matches(&flow("1.1.1.1:80")));
    }

    #[test]
    fn context_and_role_filters_cover_inferred_listeners() {
        let flow = json!({
            "network_context": {"kind": "vopono"},
            "role": "inbound",
            "direction": "inbound",
            "exposure": "published"
        });
        assert!(ContextFilter::Vopono.matches(&flow));
        assert!(!ContextFilter::Host.matches(&flow));
        assert!(RoleFilter::Listener.matches(&flow));
        assert!(RoleFilter::Inbound.matches(&flow));
        assert!(!RoleFilter::Tracker.matches(&flow));
        assert_eq!(ContextFilter::All.next(), ContextFilter::Host);
        assert_eq!(RoleFilter::Tracker.next(), RoleFilter::All);
    }

    #[test]
    fn focus_cycles_between_panes() {
        let mut app = App::new(Path::new("/tmp/unused.sock"));
        app.tab = 1;
        app.focus = Focus::List;
        app.cycle_focus();
        assert_eq!(app.focus, Focus::Detail);
        app.cycle_focus();
        assert_eq!(app.focus, Focus::List);
        app.tab = 0;
        app.focus = Focus::List;
        app.cycle_focus();
        assert_eq!(app.focus, Focus::List);
    }

    #[test]
    fn clicks_select_rows_focus_panes_and_change_scope() {
        let mut app = App::new(Path::new("/tmp/unused.sock"));
        app.tab = 1;
        app.list_area = Rect::new(0, 5, 80, 10);
        app.detail_area = Rect::new(0, 15, 80, 10);
        app.list_height[1] = 5;
        app.snapshot.incidents = json!({"incidents": [
            {"id":"a"},{"id":"b"},{"id":"c"}
        ]});
        app.handle_click(2, 8);
        assert_eq!(app.selected[1], 1);
        assert_eq!(app.focus, Focus::List);
        app.handle_click(2, 16);
        assert_eq!(app.focus, Focus::Detail);

        app.tab_area = Rect::new(0, 0, 100, 3);
        app.handle_click(5, 1);
        assert_eq!(app.tab, 0);
        app.handle_click(28, 1);
        assert_eq!(app.tab, 2);
        app.handle_click(40, 1);
        assert_eq!(app.tab, 3);
        app.handle_click(52, 1);
        assert_eq!(app.tab, 4);
        app.handle_click(11, 1);
        assert_eq!(app.tab, 4, "clicking a divider must not change tabs");

        app.tab = 3;
        app.scope_area = Rect::new(0, 5, 80, 3);
        app.handle_click(3, 6);
        assert_eq!(app.network_scope, NetworkScope::All);
        app.handle_click(15, 6);
        assert_eq!(app.network_scope, NetworkScope::SameMachine);
        app.handle_click(30, 6);
        assert_eq!(app.network_scope, NetworkScope::LocalNetwork);
        app.handle_click(48, 6);
        assert_eq!(app.network_scope, NetworkScope::Remote);
    }

    #[test]
    fn endpoint_parsing_handles_ipv4_and_ipv6() {
        assert_eq!(
            endpoint_ip("10.0.0.1:443"),
            Some("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            endpoint_ip("[2001:db8::1]:443"),
            Some("2001:db8::1".parse().unwrap())
        );
    }
}
