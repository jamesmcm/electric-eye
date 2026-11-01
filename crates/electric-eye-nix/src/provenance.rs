use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const NIX_STORE_ROOT: &str = "/nix/store";
const HASH_LEN: usize = 32;

const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableProvenance {
    pub store_path: PathBuf,
    pub hash: String,
    pub name: String,
    pub version: Option<String>,
}

impl fmt::Display for ExecutableProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(version) => write!(f, "{}-{}", self.name, version),
            None => write!(f, "{}", self.name),
        }
    }
}

#[derive(Debug)]
pub enum ProvenanceError {
    Io(std::io::Error),
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvenanceError::Io(err) => write!(f, "provenance lookup failed: {}", err),
        }
    }
}

impl std::error::Error for ProvenanceError {}

impl From<std::io::Error> for ProvenanceError {
    fn from(value: std::io::Error) -> Self {
        ProvenanceError::Io(value)
    }
}

type Result<T> = std::result::Result<T, ProvenanceError>;

pub trait ProvenanceProvider {
    fn identify(&self, executable: &Path) -> Result<Option<ExecutableProvenance>>;
}

pub struct NixProvider {
    store_root: PathBuf,
    cache: Mutex<Vec<(PathBuf, Option<ExecutableProvenance>)>>,
}

impl NixProvider {
    pub fn new() -> Self {
        Self::with_store_root(PathBuf::from(NIX_STORE_ROOT))
    }

    pub fn with_store_root(store_root: PathBuf) -> Self {
        Self {
            store_root,
            cache: Mutex::new(Vec::new()),
        }
    }

    pub fn identify_uncached(&self, executable: &Path) -> Option<ExecutableProvenance> {
        parse_store_path(executable, &self.store_root)
    }

    pub fn cache_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }
}

impl Default for NixProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvenanceProvider for NixProvider {
    fn identify(&self, executable: &Path) -> Result<Option<ExecutableProvenance>> {
        let key = executable.to_path_buf();
        if let Some((_, cached)) = self.cache.lock().unwrap().iter().find(|(p, _)| *p == key) {
            return Ok(cached.clone());
        }

        let identified = self.identify_uncached(executable);
        self.cache.lock().unwrap().push((key, identified.clone()));
        Ok(identified)
    }
}

pub fn parse_store_component(component: &str) -> Option<ExecutableProvenance> {
    let (hash, rest) = component.split_once('-')?;
    if hash.len() != HASH_LEN || !hash.bytes().all(|b| NIX_BASE32.contains(&b)) {
        return None;
    }
    if rest.is_empty() {
        return None;
    }

    let (name, version) = match rest.rsplit_once('-') {
        Some((name, version)) if !name.is_empty() && looks_like_version(version) => {
            (name.to_string(), Some(version.to_string()))
        }
        _ => (rest.to_string(), None),
    };

    Some(ExecutableProvenance {
        store_path: PathBuf::from(NIX_STORE_ROOT).join(component),
        hash: hash.to_string(),
        name,
        version,
    })
}

fn looks_like_version(candidate: &str) -> bool {
    candidate.chars().any(|c| c.is_ascii_digit())
}

fn parse_store_path(executable: &Path, store_root: &Path) -> Option<ExecutableProvenance> {
    let stripped = executable.strip_prefix(store_root).ok()?;
    let component = stripped.components().next()?.as_os_str();
    if stripped.components().count() == 0 {
        return None;
    }
    parse_store_component(&component.to_string_lossy())
}

#[derive(Default)]
pub struct ProvenanceRegistry {
    providers: Vec<Box<dyn ProvenanceProvider>>,
}

impl ProvenanceRegistry {
    pub fn new() -> Self {
        let mut registry = Self::empty();
        registry.providers.push(Box::new(NixProvider::new()));
        registry
    }

    pub fn empty() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn push(&mut self, provider: Box<dyn ProvenanceProvider>) {
        self.providers.push(provider);
    }

    pub fn identify(&self, executable: &Path) -> Result<Option<ExecutableProvenance>> {
        for provider in &self.providers {
            if let Some(provenance) = provider.identify(executable)? {
                return Ok(Some(provenance));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance(path: &str) -> Option<ExecutableProvenance> {
        NixProvider::new().identify_uncached(Path::new(path))
    }

    #[test]
    fn rejects_non_store_paths() {
        assert!(provenance("/usr/bin/firefox").is_none());
        assert!(provenance("/home/user/.cargo/bin/cargo").is_none());
    }

    #[test]
    fn rejects_lookalike_roots() {
        assert!(provenance("/nix/store-not/abc-firefox").is_none());
    }

    #[test]
    fn parses_name_and_version() {
        let p = provenance("/nix/store/0q2m8v1f4x9k3n7j5d6c1b2a9z8y7x6w-firefox-145.0/bin/firefox")
            .unwrap();
        assert_eq!(p.name, "firefox");
        assert_eq!(p.version.as_deref(), Some("145.0"));
        assert_eq!(p.hash.len(), 32);
        assert_eq!(p.to_string(), "firefox-145.0");
        assert_eq!(
            p.store_path,
            PathBuf::from("/nix/store/0q2m8v1f4x9k3n7j5d6c1b2a9z8y7x6w-firefox-145.0")
        );
    }

    #[test]
    fn keeps_multi_dash_names_intact() {
        let p = provenance(
            "/nix/store/0q2m8v1f4x9k3n7j5d6c1b2a9z8y7x6w-python3.12-requests-2.31.0/bin/foo",
        )
        .unwrap();
        assert_eq!(p.name, "python3.12-requests");
        assert_eq!(p.version.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn tolerates_versionless_derivations() {
        let p = provenance("/nix/store/0q2m8v1f4x9k3n7j5d6c1b2a9z8y7x6w-hello/bin/hello").unwrap();
        assert_eq!(p.name, "hello");
        assert_eq!(p.version, None);
    }

    #[test]
    fn rejects_bad_hash() {
        assert!(provenance("/nix/store/not-a-hash-firefox-145.0/bin/firefox").is_none());
        assert!(
            provenance("/nix/store/eoaut123456789012345678901234567-firefox-145.0/bin/firefox")
                .is_none()
        );
    }

    #[test]
    fn rejects_bare_store_root() {
        let root = PathBuf::from(NIX_STORE_ROOT);
        assert!(parse_store_path(&root, &root).is_none());
    }

    #[test]
    fn provider_caches_repeated_queries() {
        let provider = NixProvider::with_store_root(PathBuf::from(NIX_STORE_ROOT));
        let path = Path::new("/nix/store/0q2m8v1f4x9k3n7j5d6c1b2a9z8y7x6w-hello/bin/hello");
        let first = provider.identify(path).unwrap();
        let second = provider.identify(path).unwrap();
        assert_eq!(first, second);
        assert_eq!(provider.cache_len(), 1);
    }

    #[test]
    fn registry_falls_through_to_none() {
        let registry = ProvenanceRegistry::new();
        assert!(
            registry
                .identify(Path::new("/usr/bin/firefox"))
                .unwrap()
                .is_none()
        );

        let found = registry
            .identify(Path::new(
                "/nix/store/0q2m8v1f4x9k3n7j5d6c1b2a9z8y7x6w-hello/bin/hello",
            ))
            .unwrap()
            .unwrap();
        assert_eq!(found.name, "hello");
    }
}
