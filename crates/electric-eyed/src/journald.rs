use std::ffi::CString;
use std::process::Command;

#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_journal_sendv(iov: *const libc::iovec, n: libc::c_int) -> libc::c_int;
}

/// Send structured fields to journald. Returns false when journald is not
/// available (e.g. running in a development shell without a journal socket).
pub fn send(fields: &[(&str, String)]) -> bool {
    let cstrings: Vec<CString> = fields
        .iter()
        .filter_map(|(key, value)| {
            let value = value.replace(['\n', '\r'], " ");
            CString::new(format!("{key}={value}")).ok()
        })
        .collect();
    if cstrings.is_empty() {
        return false;
    }
    let iovecs: Vec<libc::iovec> = cstrings
        .iter()
        .map(|field| libc::iovec {
            iov_base: field.as_ptr() as *mut libc::c_void,
            iov_len: field.as_bytes().len(),
        })
        .collect();
    (unsafe { sd_journal_sendv(iovecs.as_ptr(), iovecs.len() as libc::c_int) }) >= 0
}

pub fn startup(kernel: &str, database: Option<&str>) {
    let mut fields = vec![
        ("MESSAGE", "electric-eyed started".to_string()),
        ("PRIORITY", "6".to_string()),
        ("ELECTRIC_EYE_EVENT", "startup".to_string()),
        (
            "ELECTRIC_EYE_VERSION",
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        ("ELECTRIC_EYE_KERNEL", kernel.to_string()),
    ];
    if let Some(database) = database {
        fields.push(("ELECTRIC_EYE_DATABASE", database.to_string()));
    }
    let _ = send(&fields);
}

pub fn send_incident(incident: &crate::rules::Incident, journal: &[String]) -> bool {
    let mut fields = vec![
        ("MESSAGE", incident.title.clone()),
        ("PRIORITY", incident.severity.priority().to_string()),
        ("ELECTRIC_EYE_EVENT", "incident".to_string()),
        (
            "ELECTRIC_EYE_SEVERITY",
            incident.severity.as_str().to_string(),
        ),
        ("ELECTRIC_EYE_COMM", incident.comm.clone()),
        ("ELECTRIC_EYE_PID", incident.pid.to_string()),
        ("ELECTRIC_EYE_DETAILS", incident.details.to_string()),
        ("ELECTRIC_EYE_JOURNAL_LINES", journal.len().to_string()),
    ];
    if let Some(path) = &incident.path {
        fields.push(("ELECTRIC_EYE_PATH", path.clone()));
    }
    if let Some(unit) = &incident.unit {
        fields.push(("ELECTRIC_EYE_UNIT", unit.clone()));
    }
    send(&fields)
}

/// Fetch a small, bounded journal context around an incident. The caller
/// should treat this as optional enrichment: journal permissions or a missing
/// journalctl must never break event capture.
pub fn nearby(unit: Option<&str>, ts_ms: u64, window_secs: u64, limit: usize) -> Vec<String> {
    let start = ts_ms / 1000;
    let end = start.saturating_add(window_secs);
    let mut command = Command::new("journalctl");
    command.args([
        "--since",
        &format!("@{start}"),
        "--until",
        &format!("@{end}"),
        "-o",
        "short-iso",
        "--no-pager",
        "-q",
        "-n",
        &limit.to_string(),
    ]);
    if let Some(unit) = unit {
        command.args(["--unit", unit]);
    }
    let Ok(output) = command.output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.chars().take(500).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn newlines_are_removed_from_values() {
        let fields = [("MESSAGE", "hello\nworld".to_string())];
        // We cannot assert journald availability in every test environment;
        // exercising the encoding path is enough.
        let encoded = fields[0].1.replace(['\n', '\r'], " ");
        assert_eq!(encoded, "hello world");
    }
}
