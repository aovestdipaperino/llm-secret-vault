//! In-memory backend used by tests and `Vault::in_memory`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::Backend;
use crate::error::Result;

/// Backend that keeps values in process memory.
#[derive(Default)]
pub(crate) struct MemoryBackend {
    entries: Mutex<HashMap<String, Zeroizing<String>>>,
}

impl MemoryBackend {
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Zeroizing<String>>> {
        self.entries.lock().expect("memory backend mutex poisoned")
    }
}

impl fmt::Debug for MemoryBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryBackend {{ entries: {} }}", self.entries().len())
    }
}

impl Backend for MemoryBackend {
    fn put(&self, account: &str, value: &str) -> Result<()> {
        self.entries()
            .insert(account.to_owned(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn resolve(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        Ok(self.entries().get(account).cloned())
    }

    fn delete(&self, account: &str) -> Result<bool> {
        Ok(self.entries().remove(account).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;

    #[test]
    fn put_resolve_delete() {
        let backend = MemoryBackend::default();
        assert!(backend.resolve("a").unwrap().is_none());
        backend.put("a", "value-1").unwrap();
        assert_eq!(backend.resolve("a").unwrap().unwrap().as_str(), "value-1");
        backend.put("a", "value-2").unwrap();
        assert_eq!(backend.resolve("a").unwrap().unwrap().as_str(), "value-2");
        assert!(backend.delete("a").unwrap());
        assert!(!backend.delete("a").unwrap());
    }

    #[test]
    fn debug_does_not_print_values() {
        let backend = MemoryBackend::default();
        backend.put("a", "super-secret-value").unwrap();
        let debug = format!("{backend:?}");
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("entries: 1"));
    }
}
