mod ack;
mod client;
mod doctor;
mod network_report;
mod render;
mod tui;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_signal: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn restore_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            request_shutdown as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            request_shutdown as *const () as libc::sighandler_t,
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Process(String),
    Tree(String),
    Flows,
    Summaries,
    Status,
    Activity,
    Apps,
    Incidents,
    Focus,
    Investigate(String),
    File(String),
    App(String),
    Network,
    Netns,
    ExplainNetwork(String),
    Why(String),
    Noise,
    Tui,
    Doctor,
    DbStatus,
    DbCompact,
    ConfigShow,
    ConfigValidate(String),
    Export(String),
    Completions(String),
    Ack(String),
    Unack(String),
    Mute { app: String, rule: String },
    Unmute { app: String, rule: String },
}

impl Command {
    pub fn parse(args: &[String]) -> Option<Command> {
        match args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["process", p] => Some(Command::Process((*p).into())),
            ["tree"] => Some(Command::Tree(String::new())),
            ["tree", p] => Some(Command::Tree((*p).into())),
            ["flows"] => Some(Command::Flows),
            ["summaries"] => Some(Command::Summaries),
            ["status"] => Some(Command::Status),
            ["activity"] => Some(Command::Activity),
            ["apps"] => Some(Command::Apps),
            ["incidents"] => Some(Command::Incidents),
            ["focus"] => Some(Command::Focus),
            ["investigate", id] => Some(Command::Investigate((*id).into())),
            ["file", path] => Some(Command::File((*path).into())),
            ["app", app] => Some(Command::App((*app).into())),
            ["network"] => Some(Command::Network),
            ["netns"] => Some(Command::Netns),
            ["explain", "network", app] => Some(Command::ExplainNetwork((*app).into())),
            ["why", path] => Some(Command::Why((*path).into())),
            ["noise"] => Some(Command::Noise),
            ["tui"] => Some(Command::Tui),
            ["doctor"] => Some(Command::Doctor),
            ["db", "status"] => Some(Command::DbStatus),
            ["db", "compact"] => Some(Command::DbCompact),
            ["config", "show"] => Some(Command::ConfigShow),
            ["config", "validate", path] => Some(Command::ConfigValidate((*path).into())),
            ["export", kind] => Some(Command::Export((*kind).into())),
            ["completions", shell] => Some(Command::Completions((*shell).into())),
            ["ack", id] => Some(Command::Ack((*id).into())),
            ["unack", id] => Some(Command::Unack((*id).into())),
            ["mute", app, rule] => Some(Command::Mute {
                app: (*app).into(),
                rule: (*rule).into(),
            }),
            ["unmute", app, rule] => Some(Command::Unmute {
                app: (*app).into(),
                rule: (*rule).into(),
            }),
            _ => None,
        }
    }

    pub fn request(&self) -> String {
        let value = match self {
            Command::Process(p) => serde_json::json!({"op":"process","process":p}),
            Command::Tree(p) => serde_json::json!({"op":"tree","process":p}),
            Command::Flows => serde_json::json!({"op":"flows","limit":100}),
            Command::Summaries => serde_json::json!({"op":"summaries","limit":100}),
            Command::Status => serde_json::json!({ "op": "status" }),
            Command::Activity => serde_json::json!({ "op": "activity", "limit": 100 }),
            Command::Apps => serde_json::json!({ "op": "apps" }),
            Command::Incidents => serde_json::json!({ "op": "incidents" }),
            Command::Focus => serde_json::json!({ "op": "focus", "limit": 1000 }),
            Command::Investigate(id) => serde_json::json!({ "op": "investigate", "id": id }),
            Command::File(path) => serde_json::json!({ "op": "file", "path": path }),
            Command::App(app) => serde_json::json!({ "op": "app", "app": app }),
            Command::Network => serde_json::json!({ "op": "network" }),
            Command::Netns => serde_json::json!({ "op": "flows", "limit": 1000 }),
            Command::ExplainNetwork(_) => serde_json::json!({ "op": "flows", "limit": 1000 }),
            Command::Why(path) => serde_json::json!({ "op": "why", "path": path }),
            Command::Noise => serde_json::json!({ "op": "noise", "limit": 1000 }),
            Command::Tui => serde_json::json!({ "op": "status" }),
            Command::Doctor => serde_json::json!({ "op": "status" }),
            Command::DbStatus => serde_json::json!({ "op": "db" }),
            Command::DbCompact => serde_json::json!({ "op": "db_compact" }),
            Command::ConfigShow => serde_json::json!({ "op": "config" }),
            Command::ConfigValidate(path) => {
                serde_json::json!({ "op": "config", "path": path })
            }
            Command::Export(kind) => export_request(kind),
            Command::Completions(_) => serde_json::json!({ "op": "status" }),
            Command::Ack(_) | Command::Unack(_) | Command::Mute { .. } | Command::Unmute { .. } => {
                serde_json::json!({ "op": "status" })
            }
        };
        value.to_string()
    }
}

fn export_request(kind: &str) -> serde_json::Value {
    let op = match kind {
        "activity" => "activity",
        "incidents" => "incidents",
        "flows" => "flows",
        "summaries" => "summaries",
        "apps" => "apps",
        "noise" => "noise",
        _ => "",
    };
    if op.is_empty() {
        serde_json::json!({ "op": "", "error": format!("unknown export kind {kind}") })
    } else {
        serde_json::json!({ "op": op, "limit": 1000 })
    }
}

#[derive(Debug)]
struct Options {
    socket: PathBuf,
    mcp_socket: PathBuf,
    json: bool,
    jsonl: bool,
    follow: bool,
    limit: Option<usize>,
    since: Option<u64>,
    before: Option<u64>,
    cursor: Option<String>,
    severity: Option<String>,
    rule: Option<String>,
    app: Option<String>,
    netns: Option<String>,
    role: Option<String>,
    for_ms: Option<u64>,
    unacked: bool,
    args: Vec<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_time(value: &str) -> anyhow::Result<u64> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix('s') {
        (number, 1_000_u64)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000_u64)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600_000_u64)
    } else if let Some(number) = value.strip_suffix('d') {
        (number, 86_400_000_u64)
    } else if let Some(number) = value.strip_suffix('w') {
        (number, 604_800_000_u64)
    } else {
        let number: u64 = value.parse()?;
        return Ok(if number < 10_000_000_000 {
            // A short number is treated as epoch seconds; larger values are ms.
            number * 1000
        } else {
            number
        });
    };
    let number: u64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid time value {value}"))?;
    Ok(now_ms().saturating_sub(number.saturating_mul(multiplier)))
}

fn parse_duration(value: &str) -> anyhow::Result<u64> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix('s') {
        (number, 1_000_u64)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000_u64)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600_000_u64)
    } else if let Some(number) = value.strip_suffix('d') {
        (number, 86_400_000_u64)
    } else {
        (value, 1_000_u64)
    };
    let number: u64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration {value}"))?;
    Ok(number.saturating_mul(multiplier))
}

fn parse_options(args: Vec<String>) -> anyhow::Result<Options> {
    let mut options = Options {
        socket: client::socket_from_env(),
        mcp_socket: client::mcp_socket_from_env(),
        json: false,
        jsonl: false,
        follow: false,
        limit: None,
        since: None,
        before: None,
        cursor: None,
        severity: None,
        rule: None,
        app: None,
        netns: None,
        role: None,
        for_ms: None,
        unacked: false,
        args: Vec::new(),
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => options.json = true,
            "--jsonl" => options.jsonl = true,
            "--follow" => options.follow = true,
            "--socket" => {
                options.socket = args
                    .next()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("--socket requires a path"))?
                    .into()
            }
            "--mcp-socket" => {
                options.mcp_socket = args
                    .next()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("--mcp-socket requires a path"))?
                    .into()
            }
            "--limit" => {
                let limit: usize = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--limit requires a number"))?
                    .parse()?;
                anyhow::ensure!((1..=1000).contains(&limit), "--limit must be 1..1000");
                options.limit = Some(limit);
            }
            "--since" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--since requires a time"))?;
                options.since = Some(parse_time(&value)?);
            }
            "--before" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--before requires a time"))?;
                options.before = Some(parse_time(&value)?);
            }
            "--cursor" => {
                options.cursor = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--cursor requires a value"))?,
                )
            }
            "--severity" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--severity requires a value"))?;
                let value = value.to_ascii_lowercase();
                anyhow::ensure!(
                    matches!(value.as_str(), "low" | "medium" | "high"),
                    "--severity must be low, medium, or high"
                );
                options.severity = Some(value);
            }
            "--rule" => {
                options.rule = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--rule requires a value"))?,
                )
            }
            "--app" => {
                options.app = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--app requires a value"))?,
                )
            }
            "--netns" => {
                options.netns = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--netns requires a value"))?,
                )
            }
            "--role" => {
                options.role = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--role requires a value"))?,
                )
            }
            "--for" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--for requires a duration"))?;
                options.for_ms = Some(parse_duration(&value)?);
            }
            "--unacked" => options.unacked = true,
            "--" => {
                options.args.extend(args);
                break;
            }
            a if a.starts_with('-') => anyhow::bail!("unknown option {a}"),
            _ => options.args.push(arg),
        }
    }
    Ok(options)
}

/// Bridge MCP's stdio transport to the daemon's Unix-socket MCP endpoint.
/// MCP messages are newline-delimited JSON, so a byte-for-byte relay is enough.
fn run_mcp_bridge(socket: &PathBuf) -> anyhow::Result<i32> {
    let mut stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("electric-eye MCP socket not found at {}", socket.display());
            eprintln!("is electric-eye.service running with MCP enabled (not --no-mcp)?");
            return Ok(1);
        }
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
            eprintln!(
                "electric-eye MCP socket exists but nothing is listening at {}",
                socket.display()
            );
            return Ok(1);
        }
        Err(err) => {
            eprintln!("failed to reach {}: {err}", socket.display());
            return Ok(1);
        }
    };

    let mut writer = stream.try_clone()?;
    std::thread::Builder::new()
        .name("electric-eye-mcp-stdin".into())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            let mut buffer = [0u8; 8192];
            loop {
                match input.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if writer.write_all(&buffer[..n]).is_err() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = writer.shutdown(Shutdown::Write);
        })?;

    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let mut buffer = [0u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                output.write_all(&buffer[..n])?;
                output.flush()?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(0)
}

fn filter_incidents(value: &mut serde_json::Value, options: &Options) {
    let Some(rows) = value["incidents"].as_array_mut() else {
        return;
    };
    rows.retain(|row| {
        if let Some(severity) = &options.severity
            && row["severity"].as_str() != Some(severity.as_str())
        {
            return false;
        }
        if let Some(rule) = &options.rule {
            let rule = rule.to_ascii_lowercase();
            let title = row["title"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let detail = row["details"]["rule"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !title.contains(&rule) && !detail.contains(&rule) {
                return false;
            }
        }
        if let Some(app) = &options.app {
            let app = app.to_ascii_lowercase();
            let comm = row["comm"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let actor = row["details"]["actor"]["application"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !comm.contains(&app) && !actor.contains(&app) {
                return false;
            }
        }
        true
    });
}

fn jsonl_rows(value: &serde_json::Value, command: &Command) -> Vec<serde_json::Value> {
    let key = match command {
        Command::Activity => Some("activity"),
        Command::Incidents => Some("incidents"),
        Command::Flows => Some("flows"),
        Command::Netns => Some("contexts"),
        Command::Summaries => Some("summaries"),
        Command::Apps => Some("apps"),
        Command::Noise => Some("candidates"),
        Command::Export(kind) => match kind.as_str() {
            "activity" => Some("activity"),
            "incidents" => Some("incidents"),
            "flows" => Some("flows"),
            "summaries" => Some("summaries"),
            "apps" => Some("apps"),
            "noise" => Some("candidates"),
            _ => None,
        },
        _ => None,
    };
    match key {
        Some(key) => value[key].as_array().cloned().unwrap_or_default(),
        None => vec![value.clone()],
    }
}

fn print_value(
    value: &serde_json::Value,
    command: &Command,
    options: &Options,
) -> anyhow::Result<()> {
    if options.jsonl {
        for row in jsonl_rows(value, command) {
            println!("{}", serde_json::to_string(&row)?);
        }
        return Ok(());
    }
    if options.json {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }
    print!(
        "{}",
        match command {
            Command::Tree(_) => render::tree(value),
            Command::Focus => render::focus(value),
            Command::Investigate(_) => render::investigate(value),
            Command::Noise => render::noise(value),
            Command::DbStatus | Command::DbCompact => render::db(value),
            Command::ConfigShow => value["toml"].as_str().unwrap_or_default().to_string(),
            Command::Export(_) => {
                for row in jsonl_rows(value, command) {
                    println!("{}", serde_json::to_string(&row)?);
                }
                String::new()
            }
            _ => render::render(value),
        }
    );
    Ok(())
}

fn run(command: &Command, options: &Options) -> anyhow::Result<i32> {
    if matches!(command, Command::Export(kind) if kind.is_empty()) {
        anyhow::bail!(
            "unknown export kind; use activity, incidents, flows, summaries, apps, or noise"
        );
    }
    let mut request: serde_json::Value = serde_json::from_str(&command.request())?;
    if let Some(limit) = options.limit {
        request["limit"] = limit.into();
    } else if matches!(command, Command::Flows)
        && (options.netns.is_some() || options.role.is_some())
    {
        // Client-side semantic filters need the full recent window, not just
        // the default top-100 rows.
        request["limit"] = 1000.into();
    }
    if let Some(since) = options.since {
        request["since_ms"] = since.into();
    }
    if let Some(before) = options.before {
        request["before_ms"] = before.into();
    }
    if let Some(cursor) = &options.cursor {
        request["before_cursor"] = cursor.clone().into();
    }
    let timeout = match command {
        Command::DbCompact => Duration::from_secs(600),
        Command::DbStatus | Command::Investigate(_) | Command::Export(_) => {
            Duration::from_secs(120)
        }
        _ => Duration::from_secs(10),
    };
    let value = client::request_with_timeout(&options.socket, &request, timeout)?;
    let mut value = value;
    if matches!(command, Command::Incidents)
        || matches!(command, Command::Export(kind) if kind == "incidents")
    {
        filter_incidents(&mut value, options);
        let mut review = ack::Store::load();
        review.prune();
        review.annotate(&mut value);
        if options.unacked
            && let Some(rows) = value["incidents"].as_array_mut()
        {
            rows.retain(|row| row["review_state"].is_null());
        }
    }
    if value.get("error").is_some() {
        eprintln!(
            "error: {}",
            value["error"].as_str().unwrap_or("request failed")
        );
        return Ok(1);
    }
    if matches!(
        command,
        Command::Flows | Command::Netns | Command::ExplainNetwork(_)
    ) || matches!(command, Command::Export(kind) if kind == "flows")
    {
        network_report::filter_flows(
            &mut value,
            options.netns.as_deref(),
            options.role.as_deref(),
        );
    }
    if matches!(command, Command::Netns) {
        let flows = value["flows"].as_array().cloned().unwrap_or_default();
        let report = network_report::contexts(&flows);
        return print_report(&report, command, options);
    }
    if let Command::ExplainNetwork(selector) = command {
        let flow_rows = value["flows"].as_array().cloned().unwrap_or_default();
        let activity = client::request(
            &options.socket,
            &serde_json::json!({"op": "app", "app": selector, "limit": 1000}),
        )?;
        let report = network_report::explain(&flow_rows, Some(&activity), selector);
        return print_report(&report, command, options);
    }
    print_value(&value, command, options)?;
    Ok(0)
}

fn print_report(
    value: &serde_json::Value,
    command: &Command,
    options: &Options,
) -> anyhow::Result<i32> {
    if options.jsonl {
        for row in jsonl_rows(value, command) {
            println!("{}", serde_json::to_string(&row)?);
        }
        return Ok(0);
    }
    if options.json {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(0);
    }
    print!(
        "{}",
        match command {
            Command::Netns => render::netns(value),
            Command::ExplainNetwork(_) => render::explain_network(value),
            _ => render::render(value),
        }
    );
    Ok(0)
}

fn follow(options: &Options) -> anyhow::Result<i32> {
    install_signal_handlers();
    let mut since = now_ms();
    let mut seen = HashSet::new();
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
        let request = serde_json::json!({
            "op": "activity",
            "limit": options.limit.unwrap_or(200),
            "since_ms": since,
        });
        match client::request(&options.socket, &request) {
            Ok(value) => {
                let mut rows = value["activity"].as_array().cloned().unwrap_or_default();
                rows.reverse();
                for row in rows {
                    let id = row["event_id"]
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| row.to_string());
                    if !seen.insert(id) {
                        continue;
                    }
                    if options.json || options.jsonl {
                        println!("{}", serde_json::to_string(&row)?);
                    } else {
                        print!(
                            "{}",
                            render::render(&serde_json::json!({ "activity": [row] }))
                        );
                    }
                    if let Some(ts) = row["ts_ms"].as_u64() {
                        since = since.max(ts.saturating_add(1));
                    }
                }
            }
            Err(err) => {
                eprintln!("follow: {err:#}");
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(0)
}

fn config_validate(path: &str) -> anyhow::Result<i32> {
    let daemon = std::env::var_os("ELECTRIC_EYED")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("electric-eyed"));
    let output = ProcessCommand::new(&daemon)
        .args(["--check-config", "--config", path])
        .output()
        .map_err(|err| anyhow::anyhow!("failed to run {}: {err}", daemon.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    Ok(if output.status.success() { 0 } else { 1 })
}

fn completions(shell: &str) -> anyhow::Result<i32> {
    let commands = "status activity apps app process tree file network flows netns explain summaries why incidents focus investigate noise tui doctor db config export ack unack mute unmute completions";
    match shell {
        "bash" => println!(
            r#"_electric_eye() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "{commands}" -- "$cur") )
    fi
}}
complete -F _electric_eye electric-eye"#
        ),
        "zsh" => println!(
            r#"#compdef electric-eye
_electric_eye() {{
  _arguments '1:command:({commands})' '*::arg:->args'
}}
compdef _electric_eye electric-eye"#
        ),
        "fish" => {
            for command in commands.split_whitespace() {
                println!("complete -c electric-eye -n '__fish_use_subcommand' -a {command}");
            }
        }
        other => anyhow::bail!("unknown shell {other}; use bash, zsh, or fish"),
    }
    Ok(0)
}

fn usage() -> &'static str {
    "electric-eye — query and inspect the electric-eyed monitor

USAGE: electric-eye [OPTIONS] <COMMAND>

OPTIONS:
  --json                 pretty JSON output
  --jsonl                one JSON object per line
  --socket <path>        daemon socket
  --mcp-socket <path>    MCP bridge socket
  --limit <1..1000>      result limit
  --since <time>         only results since a relative time (15m, 1h, 24h) or epoch
  --before <time>        only results before a relative time or epoch
  --cursor <cursor>      resume after a next_cursor value
  --severity <level>     incidents: low, medium, or high
  --rule <text>          incidents: title/rule substring
  --app <text>           incidents: application substring
  --netns <text>         flows/netns/explain: namespace, container, unit or label substring
  --role <text>          flows/netns/explain: flow role substring
  --unacked              incidents: hide locally acked/muted entries
  --for <duration>       review acknowledgement/mute duration (default 1h)
  --follow               follow new activity (activity only)

COMMANDS:
  tui                  interactive terminal dashboard
  doctor               check service, permissions, capture, storage and noise
  status               daemon status
  activity             recent activity
  apps                 applications and tasks
  app <name-or-id>      application activity
  process <pid-or-id>  metadata and exec history
  tree [pid-or-id]      process descendants
  file <path>          file activity
  why <path>           who touched a file
  network              network activity
  flows                connection lifecycles and traffic
  netns                network namespaces, containers and published ports
  explain network <app>  semantic network verdict for an application
  summaries            evidence-backed activity summaries
  incidents            recorded incidents
  focus                configured process/project focus sessions and matches
  investigate <id>     render a complete investigation prompt/bundle for a harness
  noise                suggest likely capture filters and rule allowlists
  db status            database size, tables, retention and disk headroom
  db compact           checkpoint/WAL truncate and VACUUM
  config show          effective TOML configuration
  config validate <path>  validate a TOML configuration file
  export <kind>        JSONL export: activity, incidents, flows, summaries, apps, noise
  ack <incident-id>    locally acknowledge an incident [--for 1h]
  unack <incident-id>  remove a local acknowledgement
  mute <app> <rule>    locally mute matching incidents [--for 1h]
  unmute <app> <rule>  remove a local mute
  completions <shell>  bash, zsh, or fish

MCP bridge: electric-eye mcp
"
}

fn main() -> ExitCode {
    restore_sigpipe();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("electric-eye {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args == ["--help"] || args == ["-h"] {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }
    let options = match parse_options(args) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("error: {err}; see electric-eye --help");
            return ExitCode::from(2);
        }
    };
    if options.args.first().map(String::as_str) == Some("mcp") {
        if options.args.len() != 1 {
            eprint!("{}", usage());
            return ExitCode::from(2);
        }
        return match run_mcp_bridge(&options.mcp_socket) {
            Ok(code) => ExitCode::from(code as u8),
            Err(err) => {
                eprintln!("error: {err:#}");
                ExitCode::FAILURE
            }
        };
    }
    let Some(command) = Command::parse(&options.args) else {
        eprint!("{}", usage());
        return ExitCode::from(2);
    };
    if options.follow && !matches!(command, Command::Activity) {
        eprintln!("error: --follow is only supported with activity");
        return ExitCode::from(2);
    }
    let result = match &command {
        Command::Tui => tui::run(&options.socket).map(|_| 0),
        Command::Doctor => doctor::run(&options.socket, options.json),
        Command::ConfigValidate(path) => config_validate(path),
        Command::Completions(shell) => completions(shell),
        Command::Ack(id) => {
            let mut store = ack::Store::load();
            let path = store.path().to_path_buf();
            let until = options
                .for_ms
                .map(|duration| now_ms().saturating_add(duration));
            store.ack(id, until).map(|_| {
                println!("acknowledged {id}; review state: {}", path.display());
                0
            })
        }
        Command::Unack(id) => {
            let mut store = ack::Store::load();
            let path = store.path().to_path_buf();
            store.unack(id).map(|_| {
                println!("unacknowledged {id}; review state: {}", path.display());
                0
            })
        }
        Command::Mute { app, rule } => {
            let mut store = ack::Store::load();
            let path = store.path().to_path_buf();
            store
                .mute(
                    app,
                    rule,
                    now_ms().saturating_add(options.for_ms.unwrap_or(3_600_000)),
                )
                .map(|_| {
                    println!("muted {app}/{rule}; review state: {}", path.display());
                    0
                })
        }
        Command::Unmute { app, rule } => {
            let mut store = ack::Store::load();
            let path = store.path().to_path_buf();
            store.unmute(app, rule).map(|_| {
                println!("unmuted {app}/{rule}; review state: {}", path.display());
                0
            })
        }
        Command::Activity if options.follow => follow(&options),
        _ => run(&command, &options),
    };
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_known_commands() {
        assert_eq!(Command::parse(&args(&["status"])), Some(Command::Status));
        assert_eq!(
            Command::parse(&args(&["activity"])),
            Some(Command::Activity)
        );
        assert_eq!(Command::parse(&args(&["apps"])), Some(Command::Apps));
        assert_eq!(
            Command::parse(&args(&["incidents"])),
            Some(Command::Incidents)
        );
        assert_eq!(Command::parse(&args(&["noise"])), Some(Command::Noise));
        assert_eq!(Command::parse(&args(&["netns"])), Some(Command::Netns));
        assert_eq!(
            Command::parse(&args(&["explain", "network", "Transmission"])),
            Some(Command::ExplainNetwork("Transmission".into()))
        );
        assert_eq!(Command::parse(&args(&["focus"])), Some(Command::Focus));
        assert_eq!(
            Command::parse(&args(&["investigate", "incident-1"])),
            Some(Command::Investigate("incident-1".into()))
        );
        assert_eq!(Command::parse(&args(&["tui"])), Some(Command::Tui));
        assert_eq!(Command::parse(&args(&["doctor"])), Some(Command::Doctor));
        assert_eq!(
            Command::parse(&args(&["db", "status"])),
            Some(Command::DbStatus)
        );
        assert_eq!(
            Command::parse(&args(&["config", "show"])),
            Some(Command::ConfigShow)
        );
        assert_eq!(
            Command::parse(&args(&["completions", "bash"])),
            Some(Command::Completions("bash".into()))
        );
        assert_eq!(
            Command::parse(&args(&["ack", "id"])),
            Some(Command::Ack("id".into()))
        );
        assert_eq!(
            Command::parse(&args(&["mute", "curl", "novel_network"])),
            Some(Command::Mute {
                app: "curl".into(),
                rule: "novel_network".into()
            })
        );
    }

    #[test]
    fn parses_path_and_app_commands() {
        assert_eq!(
            Command::parse(&args(&["file", "/tmp/x"])),
            Some(Command::File("/tmp/x".into()))
        );
        assert_eq!(
            Command::parse(&args(&["app", "firefox"])),
            Some(Command::App("firefox".into()))
        );
        assert_eq!(
            Command::parse(&args(&["why", "/tmp/x"])),
            Some(Command::Why("/tmp/x".into()))
        );
        assert_eq!(Command::parse(&args(&["network"])), Some(Command::Network));
    }

    #[test]
    fn rejects_unknown_commands() {
        assert_eq!(Command::parse(&args(&[])), None);
        assert_eq!(Command::parse(&args(&["frobnicate"])), None);
        assert_eq!(Command::parse(&args(&["file"])), None);
    }

    #[test]
    fn extracts_socket_override() {
        let options = parse_options(args(&[
            "--socket",
            "/tmp/ee.sock",
            "status",
            "--limit",
            "20",
        ]))
        .unwrap();
        assert_eq!(options.socket, PathBuf::from("/tmp/ee.sock"));
        assert_eq!(options.args, args(&["status"]));
        assert_eq!(options.limit, Some(20));
        assert!(parse_options(args(&["--socket"])).is_err());
        assert!(parse_options(args(&["--limit", "0"])).is_err());
        assert!(parse_options(args(&["--typo"])).is_err());
        assert!(Command::parse(&args(&["status", "extra"])).is_none());
        assert!(Command::parse(&args(&["file", "/a", "/b"])).is_none());
    }

    #[test]
    fn extracts_mcp_socket_override() {
        let options = parse_options(args(&["--mcp-socket", "/tmp/mcp.sock", "mcp"])).unwrap();
        assert_eq!(options.mcp_socket, PathBuf::from("/tmp/mcp.sock"));
        assert_eq!(options.args, args(&["mcp"]));
        assert!(parse_options(args(&["--mcp-socket"])).is_err());
    }

    #[test]
    fn parses_filters_and_times() {
        let options = parse_options(args(&[
            "--since",
            "1h",
            "--severity",
            "high",
            "--rule",
            "egress",
            "--app",
            "curl",
            "--netns",
            "vopono",
            "--role",
            "listener",
            "--cursor",
            "123|event",
            "--for",
            "1h",
            "incidents",
        ]))
        .unwrap();
        assert!(options.since.is_some());
        assert_eq!(options.cursor.as_deref(), Some("123|event"));
        assert_eq!(options.for_ms, Some(3_600_000));
        assert_eq!(options.severity.as_deref(), Some("high"));
        assert_eq!(options.rule.as_deref(), Some("egress"));
        assert_eq!(options.app.as_deref(), Some("curl"));
        assert_eq!(options.netns.as_deref(), Some("vopono"));
        assert_eq!(options.role.as_deref(), Some("listener"));
        assert!(parse_options(args(&["--severity", "critical", "incidents"])).is_err());
    }
}
