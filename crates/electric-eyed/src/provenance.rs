//! Read-only libalpm ownership snapshots; no package transactions are opened.
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char, c_void},
    io::Read,
    path::Path,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub description: String,
    pub installed_at: i64,
    #[serde(default)]
    pub validation: Option<String>,
    #[serde(default)]
    pub packager: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageTrust {
    pub executable: String,
    pub package: Option<Package>,
    pub validation: Option<String>,
    pub source: String,
    pub hash_match: Option<bool>,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub status: String,
    pub checked_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Provenance {
    pub provider: String,
    pub package: Option<Package>,
    pub executable: String,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub observed_ms: u64,
    pub status: String,
}
#[derive(Default)]
struct Index {
    files: HashMap<String, Arc<Package>>,
    error: Option<String>,
}
pub struct Provider {
    index: Arc<RwLock<Index>>,
    trust_cache: Mutex<HashMap<String, PackageTrust>>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl Provider {
    pub fn start() -> Self {
        let index = Arc::new(RwLock::new(load().unwrap_or_else(|e| {
            log::warn!("ALPM unavailable: {e:#}");
            Index {
                error: Some(e.to_string()),
                ..Index::default()
            }
        })));
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let shared = Arc::clone(&index);
        let join = std::thread::spawn(move || {
            let mut fingerprint = fingerprint();
            while !stopping.load(Ordering::Relaxed) {
                for _ in 0..20 {
                    if stopping.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                let next = fingerprint_fn();
                if (next != fingerprint || shared.read().unwrap().error.is_some())
                    && !Path::new("/var/lib/pacman/db.lck").exists()
                {
                    match load() {
                        Ok(new) => {
                            *shared.write().unwrap() = new;
                            fingerprint = next;
                        }
                        Err(e) => log::warn!("ALPM refresh deferred: {e}"),
                    }
                }
            }
        });
        Self {
            index,
            trust_cache: Mutex::new(HashMap::new()),
            stop,
            join: Some(join),
        }
    }
    pub fn identify_record(&self, path: &str, raw: &crate::wire::Record) -> Provenance {
        let mut p = self.identify(path);
        if raw.exe_inode != 0 {
            let device = libc::makedev(raw.exe_dev >> 20, raw.exe_dev & 0xfffff);
            if p.inode != Some(raw.exe_inode) || p.device != Some(device) {
                p.package = None;
                p.status = "file_replaced_deleted_or_other_mount_namespace".into();
            }
            p.inode = Some(raw.exe_inode);
            p.device = Some(device);
        }
        p
    }
    pub fn trust(&self, path: &str) -> PackageTrust {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).ok();
        let cache_key = metadata
            .as_ref()
            .map(|m| {
                format!(
                    "{}:{}:{}:{}",
                    path,
                    m.dev(),
                    m.ino(),
                    m.mtime_nsec() ^ m.size() as i64
                )
            })
            .unwrap_or_else(|| path.to_string());
        if let Some(trust) = self.trust_cache.lock().unwrap().get(&cache_key) {
            return trust.clone();
        }
        let index = self.index.read().unwrap();
        let package = index.files.get(path).map(|package| (**package).clone());
        let validation = package
            .as_ref()
            .and_then(|package| package.validation.clone());
        let hash = package
            .as_ref()
            .and_then(|package| package_hash(path, package));
        let source = match validation.as_deref() {
            Some("pgp") => "arch_repo_signed",
            Some("none") | None => "unsigned_or_foreign",
            Some(_) => "other_validation",
        }
        .to_string();
        let status = match (&package, validation.as_deref(), hash.as_ref().map(|h| h.0)) {
            (None, _, _) => "unowned",
            (Some(_), Some("pgp"), Some(true)) => "arch_signed_unmodified",
            (Some(_), Some("pgp"), Some(false)) => "arch_signed_modified",
            (Some(_), _, Some(true)) => "unsigned_or_foreign_unmodified",
            (Some(_), _, Some(false)) => "unsigned_or_foreign_modified",
            (Some(_), _, None) => "unverified",
        }
        .to_string();
        let trust = PackageTrust {
            executable: path.into(),
            package,
            validation,
            source,
            hash_match: hash.as_ref().map(|h| h.0),
            expected_sha256: hash.as_ref().and_then(|h| h.1.clone()),
            actual_sha256: hash.as_ref().and_then(|h| h.2.clone()),
            status,
            checked_ms: crate::api::now_ms(),
        };
        self.trust_cache
            .lock()
            .unwrap()
            .insert(cache_key, trust.clone());
        trust
    }

    pub fn identify(&self, path: &str) -> Provenance {
        use std::os::unix::fs::MetadataExt;
        let stat = std::fs::metadata(path).ok();
        let index = self.index.read().unwrap();
        Provenance {
            provider: if index.error.is_none() {
                "alpm"
            } else {
                "filesystem"
            }
            .into(),
            package: index.files.get(path).map(|p| (**p).clone()),
            executable: path.into(),
            device: stat.as_ref().map(|s| s.dev()),
            inode: stat.as_ref().map(|s| s.ino()),
            observed_ms: crate::api::now_ms(),
            status: index.error.clone().unwrap_or_else(|| {
                if index.files.contains_key(path) {
                    "installed_database_ownership".into()
                } else {
                    "unowned".into()
                }
            }),
        }
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}
fn fingerprint() -> u128 {
    fingerprint_fn()
}
fn fingerprint_fn() -> u128 {
    std::fs::metadata("/var/lib/pacman/local")
        .and_then(|s| s.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|t| t.as_nanos())
        .unwrap_or(0)
}
#[repr(C)]
struct List {
    data: *mut c_void,
    prev: *mut List,
    next: *mut List,
}
#[repr(C)]
struct File {
    name: *const c_char,
    size: libc::off_t,
    mode: libc::mode_t,
}
#[repr(C)]
struct Files {
    count: usize,
    files: *const File,
}
struct Library(*mut c_void);
impl Drop for Library {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                libc::dlclose(self.0);
            }
        }
    }
}
fn text(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}
fn dl_error() -> String {
    let message = unsafe { libc::dlerror() };
    if message.is_null() {
        "unknown dynamic-loader error".into()
    } else {
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    }
}
fn load() -> anyhow::Result<Index> {
    let handle = unsafe { libc::dlopen(c"libalpm.so".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    anyhow::ensure!(
        !handle.is_null(),
        "libalpm unavailable ({}); package ownership is unknown",
        dl_error()
    );
    let lib = Library(handle);
    macro_rules! function {
        ($name:literal,$ty:ty) => {{
            let p = unsafe { libc::dlsym(lib.0, concat!($name, "\0").as_ptr().cast()) };
            anyhow::ensure!(!p.is_null(), "missing libalpm symbol {}", $name);
            unsafe { std::mem::transmute::<*mut c_void, $ty>(p) }
        }};
    }
    let init = function!(
        "alpm_initialize",
        unsafe extern "C" fn(*const c_char, *const c_char, *mut i32) -> *mut c_void
    );
    let release = function!("alpm_release", unsafe extern "C" fn(*mut c_void) -> i32);
    let local = function!(
        "alpm_get_localdb",
        unsafe extern "C" fn(*mut c_void) -> *mut c_void
    );
    let cache = function!(
        "alpm_db_get_pkgcache",
        unsafe extern "C" fn(*mut c_void) -> *mut List
    );
    let name = function!(
        "alpm_pkg_get_name",
        unsafe extern "C" fn(*mut c_void) -> *const c_char
    );
    let version = function!(
        "alpm_pkg_get_version",
        unsafe extern "C" fn(*mut c_void) -> *const c_char
    );
    let desc = function!(
        "alpm_pkg_get_desc",
        unsafe extern "C" fn(*mut c_void) -> *const c_char
    );
    let installed = function!(
        "alpm_pkg_get_installdate",
        unsafe extern "C" fn(*mut c_void) -> i64
    );
    let files = function!(
        "alpm_pkg_get_files",
        unsafe extern "C" fn(*mut c_void) -> *const Files
    );
    let root = CString::new("/")?;
    let db = CString::new("/var/lib/pacman")?;
    let mut error = 0;
    let handle = unsafe { init(root.as_ptr(), db.as_ptr(), &mut error) };
    anyhow::ensure!(!handle.is_null(), "libalpm initialization failed: {error}");
    struct Handle {
        ptr: *mut c_void,
        release: unsafe extern "C" fn(*mut c_void) -> i32,
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                (self.release)(self.ptr);
            }
        }
    }
    let handle = Handle {
        ptr: handle,
        release,
    };
    let database = unsafe { local(handle.ptr) };
    anyhow::ensure!(!database.is_null(), "local ALPM database missing");
    let mut result = Index::default();
    let mut node = unsafe { cache(database) };
    while !node.is_null() {
        unsafe {
            let pkg = (*node).data;
            let package_name = text(name(pkg));
            let package_version = text(version(pkg));
            let (validation, packager) = local_package_fields(&package_name, &package_version);
            let metadata = Arc::new(Package {
                name: package_name,
                version: package_version,
                description: text(desc(pkg)),
                installed_at: installed(pkg),
                validation,
                packager,
            });
            let list = files(pkg);
            if !list.is_null() {
                for i in 0..(*list).count {
                    let file = &*(*list).files.add(i);
                    let path = text(file.name);
                    if !path.ends_with('/') {
                        result
                            .files
                            .insert(format!("/{path}"), Arc::clone(&metadata));
                    }
                }
            }
            node = (*node).next;
        }
    }
    Ok(result)
}
fn local_package_fields(name: &str, version: &str) -> (Option<String>, Option<String>) {
    let path = Path::new("/var/lib/pacman/local")
        .join(format!("{name}-{version}"))
        .join("desc");
    let Ok(text) = std::fs::read_to_string(path) else {
        return (None, None);
    };
    (
        desc_field(&text, "%VALIDATION%"),
        desc_field(&text, "%PACKAGER%"),
    )
}

fn desc_field(text: &str, field: &str) -> Option<String> {
    let rest = text.split_once(field)?.1;
    rest.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .filter(|line| !line.starts_with('%'))
        .map(str::to_string)
}

fn package_hash(path: &str, package: &Package) -> Option<(bool, Option<String>, Option<String>)> {
    let mtree = Path::new("/var/lib/pacman/local")
        .join(format!("{}-{}", package.name, package.version))
        .join("mtree");
    let file = std::fs::File::open(mtree).ok()?;
    let mut text = String::new();
    GzDecoder::new(file).read_to_string(&mut text).ok()?;
    let relative = format!("./{}", path.trim_start_matches('/'));
    let expected = text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        if name != relative {
            return None;
        }
        fields.find_map(|field| field.strip_prefix("sha256digest=").map(str::to_string))
    })?;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    Some((expected == actual, Some(expected), Some(actual)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queries_installed_package_read_only() {
        if !Path::new("/var/lib/pacman/local").is_dir() {
            return;
        }
        let index = load().unwrap();
        assert_eq!(index.files.get("/usr/bin/pacman").unwrap().name, "pacman");
        let p = Provider::start().identify("/usr/bin/pacman");
        assert!(p.package.is_some());
        assert!(p.inode.is_some());
        let trust = Provider::start().trust("/usr/bin/pacman");
        assert!(trust.validation.is_some(), "{trust:?}");
        assert_eq!(trust.hash_match, Some(true), "{trust:?}");
    }
}
