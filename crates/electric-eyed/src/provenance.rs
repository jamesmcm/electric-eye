//! Read-only libalpm ownership snapshots; no package transactions are opened.
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}
impl FileIdentity {
    pub fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    pub fn from_record(raw: &crate::wire::Record) -> Option<Self> {
        (raw.exe_inode != 0).then(|| Self {
            device: libc::makedev(raw.exe_dev >> 20, raw.exe_dev & 0xfffff),
            inode: raw.exe_inode,
        })
    }
}
impl Provenance {
    pub fn identity(&self) -> Option<FileIdentity> {
        Some(FileIdentity {
            device: self.device?,
            inode: self.inode?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TrustKey {
    path: String,
    identity: FileIdentity,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    generation: u64,
}
impl TrustKey {
    fn new(path: &str, metadata: &std::fs::Metadata, generation: u64) -> Self {
        Self {
            path: path.into(),
            identity: FileIdentity::from_metadata(metadata),
            size: metadata.size(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            generation,
        }
    }
}
#[derive(Default)]
struct Index {
    files: HashMap<String, Arc<Package>>,
    error: Option<String>,
    generation: u64,
}
pub struct Provider {
    index: Arc<RwLock<Index>>,
    trust_cache: Mutex<HashMap<TrustKey, PackageTrust>>,
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
                        Ok(mut new) => {
                            let mut index = shared.write().unwrap();
                            new.generation = index.generation.wrapping_add(1);
                            *index = new;
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
        let Some(observed) = FileIdentity::from_record(raw) else {
            p.package = None;
            p.device = None;
            p.inode = None;
            p.status = "executable_identity_unavailable".into();
            return p;
        };
        if p.identity() != Some(observed) {
            p.package = None;
            p.status = "file_replaced_deleted_or_other_mount_namespace".into();
        }
        p.inode = Some(observed.inode);
        p.device = Some(observed.device);
        p
    }
    #[cfg(test)]
    pub fn trust(&self, path: &str) -> PackageTrust {
        let observed = std::fs::metadata(path)
            .ok()
            .map(|m| FileIdentity::from_metadata(&m));
        self.trust_observed(path, observed)
    }
    pub fn trust_observed(&self, path: &str, observed: Option<FileIdentity>) -> PackageTrust {
        let unknown = |status: &str| PackageTrust {
            executable: path.into(),
            package: None,
            validation: None,
            source: "unknown".into(),
            hash_match: None,
            expected_sha256: None,
            actual_sha256: None,
            status: status.into(),
            checked_ms: crate::api::now_ms(),
        };
        let Some(observed) = observed else {
            return unknown("executable_identity_unavailable");
        };
        let Ok(mut file) = crate::metadata::open_regular(Path::new(path), 512 * 1024 * 1024) else {
            return unknown("file_replaced_deleted_or_other_mount_namespace");
        };
        let Ok(metadata) = file.metadata() else {
            return unknown("unverified");
        };
        if FileIdentity::from_metadata(&metadata) != observed {
            return unknown("file_replaced_deleted_or_other_mount_namespace");
        }
        let index = self.index.read().unwrap();
        let cache_key = TrustKey::new(path, &metadata, index.generation);
        if let Some(trust) = self.trust_cache.lock().unwrap().get(&cache_key) {
            return trust.clone();
        }
        let package = index.files.get(path).map(|package| (**package).clone());
        let validation = package
            .as_ref()
            .and_then(|package| package.validation.clone());
        let hash = package
            .as_ref()
            .and_then(|package| package_hash(path, package, &mut file));
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
        if file
            .metadata()
            .ok()
            .as_ref()
            .map(|m| TrustKey::new(path, m, index.generation))
            != Some(cache_key.clone())
        {
            return unknown("file_changed_during_verification");
        }
        let mut cache = self.trust_cache.lock().unwrap();
        cache.retain(|key, _| key.generation == index.generation && key.path != path);
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(cache_key, trust.clone());
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

fn package_hash(
    path: &str,
    package: &Package,
    executable: &mut std::fs::File,
) -> Option<(bool, Option<String>, Option<String>)> {
    let mtree = Path::new("/var/lib/pacman/local")
        .join(format!("{}-{}", package.name, package.version))
        .join("mtree");
    let file = std::fs::File::open(mtree).ok()?;
    let mut text = String::new();
    GzDecoder::new(file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() > 16 * 1024 * 1024 {
        return None;
    }
    let relative = format!("./{}", path.trim_start_matches('/'));
    let expected = text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        if name != relative {
            return None;
        }
        fields.find_map(|field| field.strip_prefix("sha256digest=").map(str::to_string))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = executable.read(&mut buffer).ok()?;
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

#[cfg(test)]
mod trust_regressions {
    use super::*;
    fn provider() -> Provider {
        Provider {
            index: Arc::new(RwLock::new(Index::default())),
            trust_cache: Mutex::new(HashMap::new()),
            stop: Arc::new(AtomicBool::new(false)),
            join: None,
        }
    }
    #[test]
    fn a_matching_path_cannot_verify_a_different_inode_or_missing_identity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("executable");
        std::fs::write(&path, b"first").unwrap();
        let identity = FileIdentity::from_metadata(&std::fs::metadata(&path).unwrap());
        let other = temp.path().join("replacement");
        std::fs::write(&other, b"replacement").unwrap();
        std::fs::rename(&other, &path).unwrap();
        let provider = provider();
        let trust = provider.trust_observed(path.to_str().unwrap(), Some(identity));
        assert_eq!(
            trust.status,
            "file_replaced_deleted_or_other_mount_namespace"
        );
        assert!(trust.package.is_none());
        assert!(trust.hash_match.is_none());
        assert_eq!(
            provider.trust_observed(path.to_str().unwrap(), None).status,
            "executable_identity_unavailable"
        );
    }
    #[test]
    fn missing_kernel_identity_cannot_inherit_the_host_path_identity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("executable");
        std::fs::write(&path, b"fixture").unwrap();
        let provider = provider();
        let record = provider.identify_record(path.to_str().unwrap(), &crate::wire::Record::ZERO);
        assert!(record.identity().is_none());
        assert!(record.package.is_none());
        assert_eq!(record.status, "executable_identity_unavailable");
        assert!(
            provider
                .trust_observed(path.to_str().unwrap(), record.identity())
                .hash_match
                .is_none()
        );
    }

    #[test]
    fn cache_tracks_full_timestamps_ctime_and_package_generation() {
        use std::fs::FileTimes;
        use std::time::UNIX_EPOCH;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("executable");
        std::fs::write(&path, b"AAAA").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let original = UNIX_EPOCH + Duration::new(1_700_000_000, 0);
        file.set_times(FileTimes::new().set_modified(original))
            .unwrap();
        let provider = provider();
        let name = path.to_str().unwrap();
        assert_eq!(provider.trust(name).status, "unowned");
        let first = provider
            .trust_cache
            .lock()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        std::fs::write(&path, b"BBBB").unwrap();
        file.set_times(FileTimes::new().set_modified(original + Duration::from_secs(60)))
            .unwrap();
        provider.trust(name);
        let second = provider
            .trust_cache
            .lock()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        assert_ne!(first, second);
        assert_eq!(second.modified, (1_700_000_060, 0));
        assert_eq!(provider.trust_cache.lock().unwrap().len(), 1);
        // ctime must invalidate even if size and mtime are restored.
        let mut simulated = std::fs::metadata(&path).unwrap();
        let before = TrustKey::new(name, &simulated, 0);
        file.set_permissions(std::fs::Permissions::from_mode(0o700))
            .unwrap();
        simulated = std::fs::metadata(&path).unwrap();
        let after = TrustKey::new(name, &simulated, 0);
        assert_ne!(before.changed, after.changed);
        {
            let mut index = provider.index.write().unwrap();
            index.files.insert(
                name.into(),
                Arc::new(Package {
                    name: "fixture".into(),
                    version: "2".into(),
                    description: String::new(),
                    installed_at: 0,
                    validation: Some("pgp".into()),
                    packager: None,
                }),
            );
            index.generation += 1;
        }
        let refreshed = provider.trust(name);
        assert_eq!(refreshed.package.unwrap().version, "2");
        assert_eq!(refreshed.validation.as_deref(), Some("pgp"));
        assert!(
            provider
                .trust_cache
                .lock()
                .unwrap()
                .keys()
                .all(|key| key.generation == 1)
        );
    }
    use std::os::unix::fs::PermissionsExt;
}
