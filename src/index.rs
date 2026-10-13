//! Index of secret names and metadata; never holds values.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::vault::Meta;

const INDEX_VERSION: u32 = 1;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexFile {
    version: u32,
    secrets: BTreeMap<SecretName, Meta>,
}

impl IndexFile {
    fn empty() -> Self {
        Self {
            version: INDEX_VERSION,
            secrets: BTreeMap::new(),
        }
    }
}

/// Metadata index persisted as JSON, or kept in memory when `path` is `None`.
///
/// Every mutation re-reads the file from disk, applies the change to that fresh
/// copy and writes it back atomically, so updates from other processes are kept.
/// There is no file locking (`std::fs::File::lock` needs a newer Rust than the
/// crate's 1.85), so concurrent writers in different processes can still race
/// in the small read-modify-write window.
#[derive(Debug)]
pub(crate) struct Index {
    path: Option<PathBuf>,
    state: Mutex<IndexFile>,
}

fn index_err(why: String) -> Error {
    Error::new(ErrorKind::Index(why))
}

impl Index {
    pub(crate) fn in_memory() -> Self {
        Self {
            path: None,
            state: Mutex::new(IndexFile::empty()),
        }
    }

    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = Self::read_file(&path)?.unwrap_or_else(IndexFile::empty);
        Ok(Self {
            path: Some(path),
            state: Mutex::new(file),
        })
    }

    /// Reads and parses the index file, or returns `None` if it does not exist.
    fn read_file(path: &Path) -> Result<Option<IndexFile>> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| index_err(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(index_err(format!("{}: {e}", path.display()))),
        }
    }

    pub(crate) fn default_path() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|dir| dir.join("llm-secret-vault").join("index.json"))
            .ok_or_else(|| index_err("this platform has no config directory".to_owned()))
    }

    fn state(&self) -> MutexGuard<'_, IndexFile> {
        self.state.lock().expect("index mutex poisoned")
    }

    /// Locks the state after refreshing it from disk when file-backed.
    ///
    /// A missing file means empty. If the file cannot be read or parsed, the
    /// last known state is kept.
    fn fresh_state(&self) -> MutexGuard<'_, IndexFile> {
        let mut state = self.state();
        if let Some(path) = &self.path {
            if let Ok(file) = Self::read_file(path) {
                *state = file.unwrap_or_else(IndexFile::empty);
            }
        }
        state
    }

    pub(crate) fn get(&self, name: &SecretName) -> Option<Meta> {
        self.fresh_state().secrets.get(name).cloned()
    }

    pub(crate) fn list(&self, prefix: Option<&str>) -> Vec<Meta> {
        self.fresh_state()
            .secrets
            .values()
            .filter(|m| prefix.is_none_or(|p| m.name.as_str().starts_with(p)))
            .cloned()
            .collect()
    }

    pub(crate) fn upsert(&self, meta: Meta) -> Result<()> {
        self.mutate(|file| {
            file.secrets.insert(meta.name.clone(), meta);
            true
        })
        .map(|_| ())
    }

    pub(crate) fn remove(&self, name: &SecretName) -> Result<bool> {
        self.mutate(|file| file.secrets.remove(name).is_some())
    }

    /// Applies `change` to a fresh copy of the index and persists it.
    ///
    /// `change` returns whether it modified anything; if not, nothing is written.
    /// Memory is replaced only after the write succeeded.
    fn mutate(&self, change: impl FnOnce(&mut IndexFile) -> bool) -> Result<bool> {
        let mut state = self.state();
        let mut next = match &self.path {
            Some(path) => Self::read_file(path)?.unwrap_or_else(IndexFile::empty),
            None => state.clone(),
        };
        let changed = change(&mut next);
        if changed {
            self.persist(&next)?;
        }
        *state = next;
        Ok(changed)
    }

    fn persist(&self, file: &IndexFile) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let io = |e: std::io::Error| index_err(format!("{}: {e}", path.display()));
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(io)?;
        }
        let bytes = serde_json::to_vec_pretty(file).map_err(|e| index_err(e.to_string()))?;
        let tmp = path.with_extension(format!(
            "json.{}.{}.tmp",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        if let Err(e) = fs::write(&tmp, bytes) {
            let _ = fs::remove_file(&tmp);
            return Err(io(e));
        }
        fs::rename(&tmp, path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            io(e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Source;

    fn meta(name: &str) -> Meta {
        Meta {
            name: SecretName::new(name).unwrap(),
            len: 12,
            fingerprint: "deadbeef".to_owned(),
            source: Source::Generated,
            created: 1,
            rotated: None,
        }
    }

    #[test]
    fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("index.json");
        let index = Index::load(&path).unwrap();
        index.upsert(meta("a")).unwrap();
        index.upsert(meta("b")).unwrap();
        assert!(index.remove(&SecretName::new("b").unwrap()).unwrap());
        let reloaded = Index::load(&path).unwrap();
        assert_eq!(reloaded.list(None), vec![meta("a")]);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\": 1"));
    }

    #[test]
    fn corrupt_file_is_an_index_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        fs::write(&path, "not json").unwrap();
        assert!(matches!(
            Index::load(&path).unwrap_err().kind(),
            ErrorKind::Index(_)
        ));
    }

    #[test]
    fn remove_of_absent_name_does_not_write_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let index = Index::load(&path).unwrap();
        assert!(!index.remove(&SecretName::new("nope").unwrap()).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn concurrent_handles_do_not_lose_updates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let one = Index::load(&path).unwrap();
        let two = Index::load(&path).unwrap();
        one.upsert(meta("a")).unwrap();
        two.upsert(meta("b")).unwrap();
        let fresh = Index::load(&path).unwrap();
        assert_eq!(fresh.list(None), vec![meta("a"), meta("b")]);
    }

    #[test]
    fn reads_see_writes_from_another_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let a = Index::load(&path).unwrap();
        let b = Index::load(&path).unwrap();
        a.upsert(meta("a")).unwrap();
        assert_eq!(b.get(&SecretName::new("a").unwrap()), Some(meta("a")));
        assert_eq!(b.list(None), vec![meta("a")]);
    }

    #[cfg(unix)]
    #[test]
    fn failed_persist_leaves_memory_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let index = Index::load(&path).unwrap();
        index.upsert(meta("a")).unwrap();
        // Read and traverse only: the temp file cannot be created.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let result = index.upsert(meta("b"));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        if result.is_ok() {
            eprintln!("skipping: permissions are not enforced (running as root?)");
            return;
        }
        assert_eq!(index.list(None), vec![meta("a")]);
        assert_eq!(Index::load(&path).unwrap().list(None), vec![meta("a")]);
    }
}
