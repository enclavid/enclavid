//! What the host decides about a role at launch, outside its measurement: how
//! many, how much, how long.
//!
//! A setting belongs here only if the host choosing it touches neither the
//! terms between applicant, consumer and policy nor anything the host may not
//! see — so the worst a host does with one is run its own guest badly. Every
//! role has defaults for all of them, and a host that names none gets those.
//!
//! In the attested build they arrive through QEMU's fw_cfg as one entry,
//! `opt/com.enclavid/settings`: `key=value` pairs, each ended by `;` or a
//! newline. One entry rather than one per setting, because fw_cfg has few file
//! slots and QEMU's own entries take most of them. A role's ports arrive beside
//! it the same way, each its own entry. Nothing read here reaches the
//! environment.
//!
//! In the developer's build each key is read from the environment instead, as
//! `ENCLAVID_<ROLE>_<KEY>` in capitals with `_` for `-` — the same key under
//! the name a shell gives it.

#[cfg(any(feature = "vsock", test))]
use std::collections::BTreeMap;
use std::fmt;

/// The longest a role's settings may be. A few dozen short pairs fit many
/// times over; one byte more is read, so a longer entry is seen to be longer
/// rather than cut to fit.
const MAX_SETTINGS_BYTES: usize = 4096;

/// The longest a key may be.
#[cfg(any(feature = "vsock", test))]
const MAX_KEY_LEN: usize = 64;

/// Where the kernel's fw_cfg driver shows this project's entries, by name.
#[cfg(feature = "vsock")]
const FW_CFG: &str = "/sys/firmware/qemu_fw_cfg/by_name/opt/com.enclavid";

/// A setting's name: lowercase ASCII letters, digits and `-`, at most 64 of
/// them. Bounded so an error can carry one into a log line — it is the one
/// thing about the host's entry worth saying back, and it can say nothing else.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key(String);

impl Key {
    #[cfg(any(feature = "vsock", test))]
    fn parse(raw: &str) -> Option<Key> {
        let shaped = !raw.is_empty()
            && raw.len() <= MAX_KEY_LEN
            && raw
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        shaped.then(|| Key(raw.to_owned()))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// Lowercase ASCII, digits and `-`, and at most 64 of them: there is nothing in
// one a log line could be made to say.
impl safe_logger::SafeToLog for Key {}

/// Why a role's settings could not be read. Like [`crate::LegFailure`], no field
/// holds text a foreign `Display` chose; a [`Key`] holds only its own shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchError {
    /// The launch's entries could not be read — in the attested build, a kernel
    /// without the fw_cfg driver, which would take every setting silently to
    /// its default.
    Unreadable,
    /// The entry is past the bound.
    TooLong,
    /// A pair is not `key=value` with a well-shaped key and a value.
    Malformed,
    /// A key is given twice, and which one is meant is not this side's to pick.
    Repeated(Key),
    /// A key the role never asked for: a misspelt setting, refused rather than
    /// left to its default.
    Unknown(Key),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchError::Unreadable => f.write_str("the launch's settings cannot be read"),
            LaunchError::TooLong => write!(f, "the settings run past {MAX_SETTINGS_BYTES} bytes"),
            LaunchError::Malformed => f.write_str("a setting is not key=value"),
            LaunchError::Repeated(key) => write!(f, "the setting {key} is given twice"),
            LaunchError::Unknown(key) => write!(f, "this role has no setting {key}"),
        }
    }
}

impl std::error::Error for LaunchError {}

// Every variant is a constant or a `Key`.
impl safe_logger::SafeToLog for LaunchError {}

/// One role's settings, as the host gave them.
pub struct Settings {
    #[cfg(feature = "vsock")]
    given: BTreeMap<Key, String>,
    #[cfg(not(feature = "vsock"))]
    role: &'static str,
}

impl Settings {
    /// The settings the host gave `role` — none, if it gave no entry.
    #[cfg(feature = "vsock")]
    pub fn load(_role: &'static str) -> Result<Settings, LaunchError> {
        use std::io::Read;

        // The driver's own directory, not this project's: without it, every
        // setting would quietly be its default.
        if !std::path::Path::new("/sys/firmware/qemu_fw_cfg/by_name").is_dir() {
            return Err(LaunchError::Unreadable);
        }
        let raw = match std::fs::File::open(format!("{FW_CFG}/settings/raw")) {
            Ok(file) => {
                let mut raw = Vec::new();
                file.take(MAX_SETTINGS_BYTES as u64 + 1)
                    .read_to_end(&mut raw)
                    .map_err(|_| LaunchError::Unreadable)?;
                raw
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err(LaunchError::Unreadable),
        };
        Ok(Settings {
            given: parse(&raw)?,
        })
    }

    /// The settings the environment gives `role`.
    #[cfg(not(feature = "vsock"))]
    pub fn load(role: &'static str) -> Result<Settings, LaunchError> {
        Ok(Settings { role })
    }

    /// The value given for `key`, if one is — taken, so that [`finish`] can
    /// tell what was never asked for.
    ///
    /// [`finish`]: Settings::finish
    #[cfg(feature = "vsock")]
    pub fn take(&mut self, key: &'static str) -> Option<String> {
        self.given.remove(&Key(key.to_owned()))
    }

    /// The value the environment gives for `key`, if it gives one.
    #[cfg(not(feature = "vsock"))]
    pub fn take(&mut self, key: &'static str) -> Option<String> {
        std::env::var_os(env_name(self.role, key)).map(|v| v.to_string_lossy().into_owned())
    }

    /// Done asking: a key the host gave and the role never asked for is refused.
    #[cfg(feature = "vsock")]
    pub fn finish(self) -> Result<(), LaunchError> {
        match self.given.into_keys().next() {
            Some(key) => Err(LaunchError::Unknown(key)),
            None => Ok(()),
        }
    }

    /// Done asking. The environment holds other things than settings, so what
    /// it holds besides is not this side's to judge.
    #[cfg(not(feature = "vsock"))]
    pub fn finish(self) -> Result<(), LaunchError> {
        Ok(())
    }
}

/// The environment's name for `role`'s `key`.
#[cfg(any(not(feature = "vsock"), test))]
fn env_name(role: &str, key: &str) -> String {
    format!("ENCLAVID_{role}_{key}")
        .to_ascii_uppercase()
        .replace('-', "_")
}

/// The pairs in a settings entry. Empty pieces are skipped, so a trailing
/// separator or a blank line costs nothing; anything else that is not
/// `key=value` stops the whole entry.
#[cfg(any(feature = "vsock", test))]
fn parse(raw: &[u8]) -> Result<BTreeMap<Key, String>, LaunchError> {
    if raw.len() > MAX_SETTINGS_BYTES {
        return Err(LaunchError::TooLong);
    }
    let text = std::str::from_utf8(raw).map_err(|_| LaunchError::Malformed)?;
    let mut given = BTreeMap::new();
    for pair in text.split([';', '\n']).filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').ok_or(LaunchError::Malformed)?;
        let key = Key::parse(key).ok_or(LaunchError::Malformed)?;
        if value.is_empty() {
            return Err(LaunchError::Malformed);
        }
        if given.contains_key(&key) {
            return Err(LaunchError::Repeated(key));
        }
        given.insert(key, value.to_owned());
    }
    Ok(given)
}

#[cfg(test)]
mod tests {
    use super::{Key, LaunchError, MAX_SETTINGS_BYTES, env_name, parse};

    fn key(k: &str) -> Key {
        Key::parse(k).expect("a well-shaped key")
    }

    #[test]
    fn pairs_end_with_a_semicolon_or_a_newline() {
        let given = parse(b"max-children=12;round-max-bytes=402653184\ncapacity-wait-secs=10;\n")
            .expect("the entry parses");
        assert_eq!(given.len(), 3);
        assert_eq!(given[&key("max-children")], "12");
        assert_eq!(given[&key("capacity-wait-secs")], "10");
    }

    #[test]
    fn no_entry_is_no_settings() {
        assert!(parse(b"").expect("an empty entry parses").is_empty());
    }

    #[test]
    fn a_pair_that_is_not_key_equals_value_is_refused() {
        for raw in [
            &b"max-children"[..],
            b"max-children=",
            b"=12",
            b"Max-Children=12",
            b"max children=12",
            b"max_children=12",
        ] {
            assert_eq!(parse(raw).err(), Some(LaunchError::Malformed), "{raw:?}");
        }
        assert_eq!(parse(&[0xFF]).err(), Some(LaunchError::Malformed));
    }

    #[test]
    fn a_key_given_twice_is_refused() {
        assert_eq!(
            parse(b"max-children=12;max-children=4").err(),
            Some(LaunchError::Repeated(key("max-children")))
        );
    }

    #[test]
    fn an_entry_past_its_bound_is_refused() {
        let long = vec![b';'; MAX_SETTINGS_BYTES + 1];
        assert_eq!(parse(&long).err(), Some(LaunchError::TooLong));
        assert!(parse(&long[..MAX_SETTINGS_BYTES]).is_ok());
    }

    #[test]
    fn a_key_is_short_and_plain() {
        assert!(Key::parse(&"k".repeat(64)).is_some());
        assert!(Key::parse(&"k".repeat(65)).is_none());
        assert!(Key::parse("").is_none());
    }

    #[test]
    fn the_environment_names_a_key_as_a_shell_would() {
        assert_eq!(
            env_name("execution-worker", "max-children"),
            "ENCLAVID_EXECUTION_WORKER_MAX_CHILDREN"
        );
        assert_eq!(
            env_name("api", "session-ttl-secs"),
            "ENCLAVID_API_SESSION_TTL_SECS"
        );
    }
}
