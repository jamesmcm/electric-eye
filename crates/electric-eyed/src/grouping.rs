use crate::{
    api::ProcessIdentity,
    config::Config,
    process::{ProcessRecord, key},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attribution {
    pub id: String,
    pub name: String,
    pub task_id: String,
    pub root: ProcessIdentity,
    pub reason: String,
    pub confidence: String,
    pub desktop_id: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Application {
    pub attribution: Attribution,
    pub root_executable: Option<String>,
    pub processes: BTreeSet<String>,
    pub processes_truncated: bool,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}
pub struct Groups {
    pub applications: crate::cache::Recent<Application>,
    desktops: HashMap<String, (String, String)>,
    member_limit: usize,
    desktop_rx: Option<std::sync::mpsc::Receiver<HashMap<String, (String, String)>>>,
}
impl Default for Groups {
    fn default() -> Self {
        Self::with_limits(&crate::config::Limits::default())
    }
}
impl Groups {
    fn with_limits(limits: &crate::config::Limits) -> Self {
        Self {
            applications: crate::cache::Recent::new(limits.application_entries),
            desktops: HashMap::new(),
            member_limit: limits.application_members,
            desktop_rx: None,
        }
    }
}
fn desktop_command(line: &str) -> Option<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            word.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(c, '\'' | '"') {
            if quote == Some(c) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(c);
            } else {
                word.push(c);
            }
            continue;
        }
        if c.is_whitespace() && quote.is_none() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if !word.is_empty() {
        words.push(word);
    }
    let mut i = 0;
    if words.first().is_some_and(|s| basename(s) == "env") {
        i = 1;
        while i < words.len() {
            if words[i] == "--" {
                i += 1;
                break;
            }
            if words[i].contains('=') {
                i += 1;
            } else {
                break;
            }
        }
    }
    words.get(i).cloned()
}
fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}
fn launcher(exe: &str) -> bool {
    matches!(
        basename(exe),
        "bash"
            | "sh"
            | "dash"
            | "zsh"
            | "fish"
            | "nu"
            | "i3"
            | "sway"
            | "Hyprland"
            | "systemd"
            | "alacritty"
            | "kitty"
            | "foot"
            | "wezterm-gui"
            | "konsole"
            | "gnome-terminal-server"
            | "xterm"
    )
}
fn interpreted_program(p: &ProcessRecord, exe: &str) -> Option<String> {
    let (name, args) = unwrap_launchers(basename(exe), p.argv.get(1..).unwrap_or_default());
    if let Some(label) = name.strip_prefix("package:") {
        return Some(format!("package:{label}"));
    }
    let base = basename(&name);
    let python = base == "python"
        || base
            .strip_prefix("python")
            .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    let scripted = matches!(
        base,
        "node" | "ruby" | "perl" | "bash" | "sh" | "tsx" | "ts-node" | "babel-node"
    );
    if !python && !scripted {
        return is_script_path(base).then(|| program_path(p, &name));
    }
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if python && arg == "-m" {
            return args
                .next()
                .filter(|s| !s.is_empty())
                .map(|module| format!("module:{module}"));
        }
        if arg == "-c" || arg == "-e" {
            return Some("inline command".into());
        }
        if arg == "-" || arg == "-s" && !python {
            return Some("stdin script".into());
        }
        if (python && matches!(arg.as_str(), "-W" | "-X"))
            || (!python && matches!(arg.as_str(), "--require" | "-r" | "--loader"))
        {
            args.next();
            continue;
        }
        if arg == "--" {
            return args.next().map(|script| program_path(p, script));
        }
        if arg.starts_with('-') {
            continue;
        }
        if !arg.is_empty() {
            return Some(program_path(p, arg));
        }
    }
    None
}

fn is_script_path(name: &str) -> bool {
    [
        ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".rb", ".pl", ".sh", ".bash", ".lua",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
}

/// Peel common command wrappers so the application identity reflects the
/// program the user asked to run rather than `uv`, `poetry`, `env`, or `sudo`.
fn unwrap_launchers(name: &str, args: &[String]) -> (String, Vec<String>) {
    let mut name = name.to_string();
    let mut args = args.to_vec();
    for _ in 0..8 {
        let Some((next, rest)) = unwrap_one(&name, &args) else {
            break;
        };
        name = next;
        args = rest;
    }
    (name, args)
}

fn unwrap_one(name: &str, args: &[String]) -> Option<(String, Vec<String>)> {
    match name {
        "env" => {
            let mut index = 0;
            while index < args.len() {
                let arg = &args[index];
                if arg == "--" {
                    index += 1;
                    break;
                }
                if arg.starts_with('-') || arg.contains('=') {
                    index += 1;
                    continue;
                }
                break;
            }
            command_at(args, index)
        }
        "sudo" | "doas" => {
            let mut index = 0;
            while index < args.len() {
                let arg = &args[index];
                if arg == "--" {
                    index += 1;
                    break;
                }
                if arg.starts_with('-') {
                    index += if option_takes_value(arg) { 2 } else { 1 };
                    continue;
                }
                break;
            }
            command_at(args, index)
        }
        "uv" | "uvx" | "poetry" | "pipx" | "bun" | "bunx" | "deno" | "pnpm" | "yarn" => {
            let mut index = 0;
            while index < args.len() {
                match args[index].as_str() {
                    "run" | "exec" | "dlx" | "tool" => {
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
            while index < args.len() {
                let arg = &args[index];
                if arg == "--" {
                    index += 1;
                    continue;
                }
                if option_takes_value(arg) {
                    index += 2;
                    continue;
                }
                if arg.starts_with('-') {
                    index += 1;
                    continue;
                }
                let candidate = basename(arg);
                if is_interpreter(candidate) || is_script_path(candidate) {
                    return command_at(args, index);
                }
                // `uvx ruff`, `pipx run ruff`, `npx prettier` and friends run
                // a package entrypoint rather than a script path.
                if matches!(name, "uvx" | "pipx" | "npx" | "pnpx" | "bunx") {
                    return Some((format!("package:{candidate}"), Vec::new()));
                }
                return command_at(args, index);
            }
            None
        }
        "npx" | "pnpx" => {
            let mut index = 0;
            while index < args.len() {
                let arg = &args[index];
                if arg == "--" {
                    return command_at(args, index + 1);
                }
                if option_takes_value(arg) {
                    index += 2;
                    continue;
                }
                if arg.starts_with('-') {
                    index += 1;
                    continue;
                }
                let candidate = basename(arg);
                if is_interpreter(candidate) || is_script_path(candidate) {
                    return command_at(args, index);
                }
                return Some((format!("package:{candidate}"), Vec::new()));
            }
            None
        }
        _ => None,
    }
}

fn command_at(args: &[String], index: usize) -> Option<(String, Vec<String>)> {
    let command = args.get(index)?;
    Some((command.clone(), args[index + 1..].to_vec()))
}

fn is_interpreter(name: &str) -> bool {
    let python = name == "python"
        || name
            .strip_prefix("python")
            .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    python
        || matches!(
            name,
            "node" | "ruby" | "perl" | "bash" | "sh" | "tsx" | "ts-node" | "babel-node"
        )
}

fn option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "-u" | "-g"
            | "-C"
            | "-h"
            | "-p"
            | "-r"
            | "-t"
            | "-U"
            | "--python"
            | "--with"
            | "--extra"
            | "--group"
            | "--index"
            | "--from"
            | "--project"
            | "--directory"
            | "--env-file"
            | "--package"
    )
}
fn program_path(p: &ProcessRecord, script: &str) -> String {
    if script.starts_with('/') {
        script.into()
    } else {
        format!("{}/{}", p.cwd.as_deref().unwrap_or("?"), script)
    }
}
impl Groups {
    pub fn load(limits: &crate::config::Limits) -> Self {
        let mut groups = Self::with_limits(limits);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("electric-eye-desktops".into())
            .spawn(move || {
                let mut loaded = Self::default();
                loaded.read_desktops(std::path::Path::new("/usr/share/applications"));
                if let Ok(passwd) =
                    crate::metadata::read_text(std::path::Path::new("/etc/passwd"), 1024 * 1024)
                {
                    for line in passwd.lines().take(4096) {
                        let fields: Vec<_> = line.split(':').collect();
                        if fields.len() >= 7 && loaded.desktops.len() < 4096 {
                            loaded.read_desktops(
                                &std::path::Path::new(fields[5]).join(".local/share/applications"),
                            );
                        }
                    }
                }
                let _ = tx.send(loaded.desktops);
            });
        if worker.is_ok() {
            // Preserve desktop labels in the initial inventory when discovery
            // is quick. A slow filesystem must not prevent capture startup.
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(desktops) => groups.desktops = desktops,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => groups.desktop_rx = Some(rx),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
            }
        }
        groups
    }
    fn read_desktops(&mut self, root: &std::path::Path) {
        if let Ok(entries) = std::fs::read_dir(root) {
            for e in entries.flatten().take(4096) {
                if self.desktops.len() >= 4096 {
                    break;
                }
                if e.path().extension().is_some_and(|x| x == "desktop")
                    && let Ok(s) = crate::metadata::read_text(&e.path(), 256 * 1024)
                {
                    let mut active = false;
                    let mut name = None;
                    let mut executable = None;
                    let mut hidden = false;
                    for line in s.lines() {
                        if line.starts_with('[') {
                            active = line == "[Desktop Entry]";
                        }
                        if !active {
                            continue;
                        }
                        if let Some(value) = line.strip_prefix("Name=") {
                            name = Some(value.chars().take(256).collect::<String>());
                        }
                        if let Some(value) = line.strip_prefix("Exec=") {
                            executable = desktop_command(value);
                        }
                        if line == "Hidden=true" {
                            hidden = true;
                        }
                    }
                    if !hidden
                        && let (Some(name), Some(exe)) = (name, executable)
                        && exe.len() <= 4096
                    {
                        self.desktops
                            .insert(exe, (e.file_name().to_string_lossy().into_owned(), name));
                    }
                }
            }
        }
    }
    pub fn assign(
        &mut self,
        p: &ProcessRecord,
        parent: Option<&ProcessRecord>,
        config: &Config,
    ) -> Attribution {
        if let Some(rx) = &self.desktop_rx {
            match rx.try_recv() {
                Ok(desktops) => {
                    self.desktops = desktops;
                    self.desktop_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.desktop_rx = None,
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        let exe = p.executable.as_deref().unwrap_or(&p.comm);
        let own = key(&p.identity);
        let override_name = config
            .grouping
            .iter()
            .find(|r| r.executable == exe)
            .map(|r| r.application.clone());
        let parent_group =
            parent.and_then(|parent| parent.application.as_ref().map(|a| (parent, a)));
        let inherited = if override_name.is_none() {
            parent_group
                .filter(|(parent, _)| !launcher(parent.executable.as_deref().unwrap_or_default()))
                .map(|(_, a)| a.clone())
        } else {
            None
        };
        let inherited_task = inherited
            .as_ref()
            .is_some_and(|a| !a.task_id.starts_with("cgroup:"));
        let launched_task = parent
            .is_some_and(|p| launcher(p.executable.as_deref().unwrap_or_default()))
            && !launcher(exe);
        let mut a = if let Some(mut a) = inherited {
            a.reason = "process ancestry within application task".into();
            a
        } else {
            let desktop = self.desktops.get(exe).or_else(|| {
                (exe.starts_with("/usr/bin/")
                    && p.package.as_ref().is_some_and(|p| p.package.is_some()))
                .then(|| self.desktops.get(basename(exe)))
                .flatten()
            });
            let script = interpreted_program(p, exe);
            let name = override_name
                .clone()
                .or_else(|| desktop.map(|(_, n)| n.clone()))
                .or_else(|| script.as_ref().map(|s| basename(s).into()))
                .unwrap_or_else(|| basename(exe).into());
            let id = if override_name.is_some() {
                format!("configured:{name}")
            } else if let Some((id, _)) = desktop {
                format!("desktop:{id}")
            } else {
                format!(
                    "executable:{exe}{}",
                    script.as_ref().map(|s| format!(":{s}")).unwrap_or_default()
                )
            };
            Attribution {
                id,
                name,
                task_id: format!("task:{own}:exec:{}", p.exec_id),
                root: p.identity.clone(),
                reason: if override_name.is_some() {
                    "user override"
                } else if desktop.is_some() {
                    "desktop executable match"
                } else if script.is_some() {
                    "interpreter and program"
                } else {
                    "executable identity"
                }
                .into(),
                confidence: if override_name.is_some() {
                    "explicit"
                } else {
                    "heuristic"
                }
                .into(),
                desktop_id: desktop.map(|(id, _)| id.clone()),
            }
        };
        // Only application-specific cgroups are strong grouping evidence;
        // broad terminal/session/container scopes never merge unrelated tasks.
        if override_name.is_none()
            && !inherited_task
            && !launched_task
            && let Some(group) = p.cgroup.as_ref().filter(|g| {
                g.split('/').any(|s| {
                    s.starts_with("app-") && (s.ends_with(".scope") || s.ends_with(".service"))
                })
            })
        {
            let task = format!("cgroup:{}:{}:{group}", p.identity.boot_id, p.uid);
            let existing = self.applications.get(&task);
            // Terminal scopes contain unrelated commands and their helpers.
            if !existing.is_some_and(|g| launcher(g.root_executable.as_deref().unwrap_or_default()))
                || existing.is_some_and(|g| g.attribution.root == p.identity)
            {
                if let Some(existing) = existing {
                    a = existing.attribution.clone();
                }
                a.task_id = task;
                a.reason = "application cgroup".into();
                a.confidence = "strong".into();
            }
        }
        let mut app = self
            .applications
            .get(&a.task_id)
            .cloned()
            .unwrap_or_else(|| Application {
                attribution: a.clone(),
                root_executable: p.executable.clone(),
                processes: BTreeSet::new(),
                processes_truncated: false,
                first_seen_ms: p.first_seen_ms,
                last_seen_ms: p.last_seen_ms,
            });
        app.last_seen_ms = p.last_seen_ms;
        if app.processes.len() < self.member_limit {
            app.processes.insert(own);
        } else if !app.processes.contains(&own) {
            app.processes_truncated = true;
        }
        self.applications
            .insert(a.task_id.clone(), p.last_seen_ms, app);
        a
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p(pid: u32, exe: &str) -> ProcessRecord {
        let mut raw = crate::wire::Record::ZERO;
        raw.pid = pid;
        raw.start_ns = pid as u64;
        raw.exe[..exe.len()].copy_from_slice(exe.as_bytes());
        crate::process::Registry::default().observe(&raw, "boot", 1, &Config::default())
    }
    #[test]
    fn separate_terminal_tasks_and_group_ide_helpers() {
        let mut g = Groups::default();
        let shell = p(1, "/bin/bash");
        g.assign(&shell, None, &Config::default());
        let a = p(2, "/usr/bin/cargo");
        let b = p(3, "/usr/bin/cargo");
        let aa = g.assign(&a, Some(&shell), &Config::default());
        let bb = g.assign(&b, Some(&shell), &Config::default());
        assert_eq!(aa.id, bb.id);
        assert_ne!(aa.task_id, bb.task_id);
        let mut code = p(4, "/usr/bin/code");
        let ca = g.assign(&code, None, &Config::default());
        code.application = Some(ca.clone());
        let compiler = p(5, "/usr/bin/rustc");
        assert_eq!(
            g.assign(&compiler, Some(&code), &Config::default()).task_id,
            ca.task_id
        );
    }
    #[test]
    fn terminal_application_scope_does_not_merge_commands_or_their_helpers() {
        let mut groups = Groups::default();
        let config = Config::default();
        let mut terminal = p(10, "/usr/bin/kitty");
        terminal.cgroup = Some("/user.slice/app-kitty.scope".into());
        terminal.application = Some(groups.assign(&terminal, None, &config));
        let mut shell = p(11, "/usr/bin/bash");
        shell.cgroup = terminal.cgroup.clone();
        shell.application = Some(groups.assign(&shell, Some(&terminal), &config));
        let mut a = p(12, "/usr/bin/cargo");
        a.cgroup = shell.cgroup.clone();
        a.application = Some(groups.assign(&a, Some(&shell), &config));
        let mut b = p(13, "/usr/bin/cargo");
        b.cgroup = shell.cgroup.clone();
        b.application = Some(groups.assign(&b, Some(&shell), &config));
        assert_ne!(
            a.application.as_ref().unwrap().task_id,
            b.application.as_ref().unwrap().task_id
        );
        let mut helper = p(14, "/usr/bin/rustc");
        helper.cgroup = shell.cgroup.clone();
        assert_eq!(
            groups.assign(&helper, Some(&a), &config).task_id,
            a.application.unwrap().task_id
        );
    }
    #[test]
    fn python_modules_and_scripts_with_flags_have_distinct_application_identity() {
        let mut groups = Groups::default();
        let mut a = p(20, "/usr/bin/python3.15");
        a.argv = vec![
            "python".into(),
            "-u".into(),
            "-m".into(),
            "http.server".into(),
        ];
        let first = groups.assign(&a, None, &Config::default());
        a.argv = vec!["python".into(), "-X".into(), "dev".into(), "tool.py".into()];
        a.cwd = Some("/work".into());
        let second = groups.assign(&a, None, &Config::default());
        assert_ne!(first.id, second.id);
        assert_eq!(first.name, "module:http.server");
        assert_eq!(second.name, "tool.py");
    }
    #[test]
    fn stdin_and_launcher_wrapped_programs_keep_semantic_identity() {
        let mut groups = Groups::default();
        let config = Config::default();

        let mut stdin = p(30, "/usr/bin/python3.14");
        stdin.argv = vec!["python3".into(), "-".into()];
        assert_eq!(groups.assign(&stdin, None, &config).name, "stdin script");

        let mut uv = p(31, "/usr/bin/uv");
        uv.argv = vec![
            "uv".into(),
            "run".into(),
            "--python".into(),
            "3.13".into(),
            "python".into(),
            "tool.py".into(),
        ];
        uv.cwd = Some("/work".into());
        let app = groups.assign(&uv, None, &config);
        assert_eq!(app.name, "tool.py");
        assert_eq!(app.reason, "interpreter and program");

        let mut npx = p(32, "/usr/bin/npx");
        npx.argv = vec!["npx".into(), "prettier".into()];
        assert_eq!(groups.assign(&npx, None, &config).name, "package:prettier");

        let mut env = p(33, "/usr/bin/env");
        env.argv = vec![
            "env".into(),
            "MODE=test".into(),
            "python".into(),
            "tool.py".into(),
        ];
        env.cwd = Some("/work".into());
        assert_eq!(groups.assign(&env, None, &config).name, "tool.py");
    }

    #[test]
    fn desktop_exec_quoting_and_explicit_overrides() {
        assert_eq!(
            desktop_command("env MODE=test \"/opt/My App/app\" %U"),
            Some("/opt/My App/app".into())
        );
        assert!(desktop_command("\"unfinished").is_none());
        let mut groups = Groups::default();
        let mut process = p(42, "/opt/app");
        process.cgroup = Some("/user.slice/app-original.scope".into());
        let config = Config {
            grouping: vec![crate::config::GroupOverride {
                executable: "/opt/app".into(),
                application: "Chosen name".into(),
            }],
            ..Default::default()
        };
        let app = groups.assign(&process, None, &config);
        assert_eq!(app.name, "Chosen name");
        assert_eq!(app.reason, "user override");
    }
}

#[cfg(test)]
mod metadata_regressions {
    use super::*;
    #[test]
    fn desktop_discovery_skips_links_and_oversized_files() {
        let temp = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/zero", temp.path().join("device.desktop")).unwrap();
        let huge = temp.path().join("huge.desktop");
        let file = std::fs::File::create(huge).unwrap();
        file.set_len(256 * 1024 + 1).unwrap();
        std::fs::write(
            temp.path().join("valid.desktop"),
            "[Desktop Entry]\nName=Fixture\nExec=/usr/bin/fixture\n",
        )
        .unwrap();
        let mut groups = Groups::default();
        groups.read_desktops(temp.path());
        assert_eq!(groups.desktops.len(), 1);
        assert_eq!(groups.desktops["/usr/bin/fixture"].1, "Fixture");
    }
}
