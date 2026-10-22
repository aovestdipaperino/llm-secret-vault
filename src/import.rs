//! Typing an existing secret into the vault at a hidden terminal prompt.

use std::io::IsTerminal;

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::vault::{Meta, Source, Vault};

fn prompt(label: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(label)
        .map(Zeroizing::new)
        .map_err(|e| {
            Error::new(ErrorKind::Usage(format!(
                "could not read from terminal: {e}"
            )))
        })
}

/// Prompts twice for a value (hidden) and stores it as `name`.
///
/// Refuses to run without a terminal, so a value can never arrive through a
/// pipe, a file or an agent.
///
/// # Errors
///
/// Returns [`ErrorKind::NoTty`] without a terminal, [`ErrorKind::NameExists`]
/// if the name exists without `overwrite`, [`ErrorKind::InvalidValue`] if the
/// two entries differ, and storage errors from [`Vault::store`].
pub fn import(vault: &Vault, name: &SecretName, overwrite: bool) -> Result<Meta> {
    if !std::io::stdin().is_terminal() {
        return Err(Error::new(ErrorKind::NoTty));
    }
    if vault.exists(name) && !overwrite {
        return Err(Error::new(ErrorKind::NameExists(name.to_string())));
    }
    let first = prompt(&format!("Value for `{name}`: "))?;
    let second = prompt("Repeat: ")?;
    if first != second {
        return Err(Error::new(ErrorKind::InvalidValue(
            "the two entries differ".to_owned(),
        )));
    }
    vault.store(name, &first, Source::Imported, overwrite, None)
}
