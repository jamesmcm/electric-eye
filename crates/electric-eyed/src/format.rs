use std::collections::BTreeMap;

const TRACEFS_CANDIDATES: &[&str] = &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldLoc {
    pub offset: usize,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceFormat {
    fields: BTreeMap<String, FieldLoc>,
}

impl TraceFormat {
    pub fn parse(text: &str) -> Option<TraceFormat> {
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("field:") {
                continue;
            }
            let mut segments = line.split(';');
            let decl = segments.next()?.trim().strip_prefix("field:")?.trim();
            let raw_name = decl.split_whitespace().last()?;
            let name = raw_name.split('[').next()?.to_string();

            let mut offset = None;
            let mut size = None;
            for segment in segments {
                let segment = segment.trim();
                if let Some(value) = segment.strip_prefix("offset:") {
                    offset = value.trim().parse::<usize>().ok();
                } else if let Some(value) = segment.strip_prefix("size:") {
                    size = value.trim().parse::<usize>().ok();
                }
            }
            fields.insert(
                name,
                FieldLoc {
                    offset: offset?,
                    size: size?,
                },
            );
        }
        if fields.is_empty() {
            None
        } else {
            Some(TraceFormat { fields })
        }
    }

    pub fn load(category: &str, event: &str) -> std::io::Result<TraceFormat> {
        let mut last_err = None;
        for root in TRACEFS_CANDIDATES {
            let path = format!("{root}/events/{category}/{event}/format");
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    return TraceFormat::parse(&text).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("unparsable tracepoint format at {path}"),
                        )
                    });
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| std::io::Error::other("tracefs not found")))
    }

    pub fn offset(&self, field: &str) -> Option<usize> {
        self.fields.get(field).map(|loc| loc.offset)
    }
}

/// Reads the numeric tracepoint id used by `perf_event_open`.
pub fn event_id(category: &str, event: &str) -> std::io::Result<u64> {
    let mut last_err = None;
    for root in TRACEFS_CANDIDATES {
        let path = format!("{root}/events/{category}/{event}/id");
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                return text.trim().parse::<u64>().map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid tracepoint id at {path}: {err}"),
                    )
                });
            }
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("tracefs not found")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOCK_FORMAT: &str = "name: inet_sock_set_state\n\
ID: 1858\n\
format:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
\n\
\tfield:const void * skaddr;\toffset:8;\tsize:8;\tsigned:0;\n\
\tfield:int oldstate;\toffset:16;\tsize:4;\tsigned:1;\n\
\tfield:int newstate;\toffset:20;\tsize:4;\tsigned:1;\n\
\tfield:__u16 sport;\toffset:24;\tsize:2;\tsigned:0;\n\
\tfield:__u16 dport;\toffset:26;\tsize:2;\tsigned:0;\n\
\tfield:__u16 family;\toffset:28;\tsize:2;\tsigned:0;\n\
\tfield:__u16 protocol;\toffset:30;\tsize:2;\tsigned:0;\n\
\tfield:__u8 saddr[4];\toffset:32;\tsize:4;\tsigned:0;\n\
\tfield:__u8 daddr[4];\toffset:36;\tsize:4;\tsigned:0;\n\
\tfield:__u8 saddr_v6[16];\toffset:40;\tsize:16;\tsigned:0;\n\
\tfield:__u8 daddr_v6[16];\toffset:56;\tsize:16;\tsigned:0;\n\
\n\
print fmt: \"family=%s protocol=%s sport=%hu\", __print_symbolic(REC->family, { 2, \"AF_INET\" }), REC->sport, REC->dport\n";

    #[test]
    fn parses_sock_format_fields() {
        let fmt = TraceFormat::parse(SOCK_FORMAT).expect("fixture must parse");
        assert_eq!(fmt.offset("oldstate"), Some(16));
        assert_eq!(fmt.offset("newstate"), Some(20));
        assert_eq!(fmt.offset("sport"), Some(24));
        assert_eq!(fmt.offset("protocol"), Some(30));
        assert_eq!(fmt.offset("saddr"), Some(32));
        assert_eq!(fmt.offset("daddr_v6"), Some(56));
    }

    #[test]
    fn array_and_pointer_names_are_normalized() {
        let fmt = TraceFormat::parse(SOCK_FORMAT).expect("fixture must parse");
        let names: Vec<String> = ["skaddr", "saddr_v6"]
            .iter()
            .filter(|n| fmt.offset(n).is_some())
            .map(|n| n.to_string())
            .collect();
        assert_eq!(names, vec!["skaddr", "saddr_v6"]);
    }

    #[test]
    fn missing_field_yields_none() {
        let fmt = TraceFormat::parse(SOCK_FORMAT).expect("fixture must parse");
        assert_eq!(fmt.offset("nonexistent"), None);
    }

    #[test]
    fn garbage_input_yields_none() {
        assert!(TraceFormat::parse("").is_none());
        assert!(TraceFormat::parse("format:\nnothing here\n").is_none());
    }

    #[test]
    fn syscall_format_with_data_loc_parses() {
        let text = "format:\n\
\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n\
\tfield:const char * filename;\toffset:24;\tsize:8;\tsigned:0;\n\
\tfield:int flags;\toffset:32;\tsize:8;\tsigned:0;\n\
\tfield:__data_loc char[] __filename_val;\toffset:48;\tsize:4;\tsigned:0;\n";
        let fmt = TraceFormat::parse(text).expect("fixture must parse");
        assert_eq!(fmt.offset("filename"), Some(24));
        assert_eq!(fmt.offset("flags"), Some(32));
        assert_eq!(fmt.offset("__filename_val"), Some(48));
    }
}
