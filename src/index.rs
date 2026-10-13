//! Index of secret names and metadata; never holds values.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::vault::Meta;

const INDEX_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
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
        let file = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| index_err(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => IndexFile::empty(),
            Err(e) => return Err(index_err(format!("{}: {e}", path.display()))),
        };
        Ok(Self {
            path: Some(path),
            state: Mutex::new(file),
        })
    }

    pub(crate) fn default_path() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|dir| dir.join("llm-secret-vault").join("index.json"))
            .ok_or_else(|| index_err("this platform has no config directory".to_owned()))
    }

    fn state(&self) -> MutexGuard<'_, IndexFile> {
        self.state.lock().expect("index mutex poisoned")
    }

    pub(crate) fn get(&self, name: &SecretName) -> Option<Meta> {
        self.state().secrets.get(name).cloned()
    }

    pub(crate) fn list(&self, prefix: Option<&str>) -> Vec<Meta> {
        self.state()
            .secrets
            .values()
            .filter(|m| prefix.is_none_or(|p| m.name.as_str().starts_with(p)))
            .cloned()
            .collect()
    }

    pub(crate) fn upsert(&self, meta: Meta) -> Result<()> {
        let mut state = self.state();
        state.secrets.insert(meta.name.clone(), meta);
        self.persist(&state)
    }

    pub(crate) fn remove(&self, name: &SecretName) -> Result<bool> {
        let mut state = self.state();
        let existed = state.secrets.remove(name).is_some();
        self.persist(&state)?;
        Ok(existed)
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
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, bytes).map_err(io)?;
        fs::rename(&tmp, path).map_err(io)
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
}
