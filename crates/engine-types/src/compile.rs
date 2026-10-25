//! Why a compile refused a composition, as the compile-worker answers it.
//!
//! A fixed set of faults. The only text in any of them is an interface's name,
//! held to a length and an alphabet ([`InterfaceName`]), so a refusal is a
//! bounded value and not a message. Each is decided from the pinned bytes and the
//! deployment's own limits, so the same pins meet it every time — which is what
//! lets api keep it as the session's init error, for the consumer to read whole.
//! No applicant is anywhere near a compile.

use serde::{Deserialize, Deserializer, Serialize};

/// The interfaces the execution-worker's host serves a composition, beside the
/// texts of each slot, `enclavid-ext:<slot>/i18n`, which it serves from the
/// catalog that names the slot. An import a composition still has once fused
/// must be one of these — or one that needs nothing served, an interface of
/// types alone — or no round of it can run.
///
/// Of WASI, the clocks and randomness as values of the round, and what
/// toolchains' runtimes import beside them, served empty: the environment,
/// stdio, the filesystem with nothing opened. Nothing of `wasi:sockets` or
/// `wasi:http`, so a composition importing them is refused.
pub const HOST_INTERFACES: [&str; 24] = [
    "enclavid:host/types@0.1.0",
    crate::icons::INTERFACE,
    POLICY_PROPS,
    POLICY_DISCLOSURE_FIELDS,
    "wasi:clocks/wall-clock@0.2.12",
    "wasi:clocks/monotonic-clock@0.2.12",
    "wasi:random/random@0.2.12",
    "wasi:random/insecure@0.2.12",
    "wasi:random/insecure-seed@0.2.12",
    "wasi:io/error@0.2.12",
    "wasi:io/poll@0.2.12",
    "wasi:io/streams@0.2.12",
    "wasi:filesystem/types@0.2.12",
    "wasi:filesystem/preopens@0.2.12",
    "wasi:cli/environment@0.2.12",
    "wasi:cli/exit@0.2.12",
    "wasi:cli/stdin@0.2.12",
    "wasi:cli/stdout@0.2.12",
    "wasi:cli/stderr@0.2.12",
    "wasi:cli/terminal-input@0.2.12",
    "wasi:cli/terminal-output@0.2.12",
    "wasi:cli/terminal-stdin@0.2.12",
    "wasi:cli/terminal-stdout@0.2.12",
    "wasi:cli/terminal-stderr@0.2.12",
];

/// The version the host serves the extension interfaces at, those of every
/// `enclavid-ext:<slot>` package: one number for them all, so every slot's
/// texts are served alike.
pub const EXTENSIONS_VERSION: &str = "0.1.0";

/// The interface a policy imports to read its props.
pub const POLICY_PROPS: &str = "enclavid-ext:policy/props@0.1.0";

/// The interface a policy imports its disclosure fields through: the cases of
/// its `key`, which its embedding writes out as its disclosure-fields list.
pub const POLICY_DISCLOSURE_FIELDS: &str = "enclavid-ext:policy/disclosure-fields@0.1.0";

/// The one function the host serves in [`POLICY_DISCLOSURE_FIELDS`]: a case
/// of the policy's `key` in, its `disclosure-field-ref` out.
pub const DISCLOSURE_FIELD: &str = "disclosure-field";

/// The interface of a slot its texts come through: `enclavid-ext:<slot>/i18n`.
pub const TEXTS: &str = "i18n";

/// The one function the host serves in a slot's [`TEXTS`]: a case of the
/// slot's `key` in, and its text's `localized-ref` out.
pub const LOCALIZED: &str = "localized";

/// One of the artifacts a composition is made of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedArtifact")]
pub enum Artifact {
    Policy,
    /// The plugin pinned under this package — the name a session pins it by
    /// and fusion registers it under. Held to [`is_wit_name`] where decoded.
    Plugin(String),
}

/// An [`Artifact`] as it arrives, before its package is held to the rule.
#[derive(Deserialize)]
enum UncheckedArtifact {
    Policy,
    Plugin(String),
}

impl TryFrom<UncheckedArtifact> for Artifact {
    type Error = &'static str;

    fn try_from(artifact: UncheckedArtifact) -> Result<Self, Self::Error> {
        match artifact {
            UncheckedArtifact::Policy => Ok(Artifact::Policy),
            UncheckedArtifact::Plugin(package) if is_wit_name(&package) => {
                Ok(Artifact::Plugin(package))
            }
            UncheckedArtifact::Plugin(_) => Err("not a package name"),
        }
    }
}

/// Whether `name` is spelled as a WIT package or interface name is —
/// `ns:pkg@version`, `ns:pkg/iface@version` — within [`InterfaceName::MAX_BYTES`].
/// What a refusal may carry as text, and nothing more.
pub fn is_wit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= InterfaceName::MAX_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-:/@.+".contains(&b))
}

/// Why a compile refused its composition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompileFault {
    /// The artifact's bytes are not a component.
    NotAComponent(Artifact),
    /// A plugin exports an interface only the host may serve.
    ReservedExport(Artifact),
    /// An embedded catalog in the artifact breaks the catalog format.
    CatalogInvalid(Artifact),
    /// The embedded catalogs, summed over the composition, are past their cap.
    CatalogsPastCap,
    /// Fused, the composition imports this interface, and neither a pinned
    /// plugin nor the host serves it.
    Unsatisfied(InterfaceName),
    /// What serves this import is not of the type it is imported as.
    Mismatched(InterfaceName),
    /// Fused, the composition does not validate or compile.
    Invalid,
    /// Its components, its metadata or its compiled code are past what the
    /// deployment carries.
    TooLarge,
    /// Compiling it took more memory than one compile is given.
    OutOfMemory,
}

impl CompileFault {
    /// A fault about the import `name`, or [`Invalid`](Self::Invalid) for a name
    /// no [`InterfaceName`] holds — which fusion and validation never produce.
    pub fn about(name: &str, fault: fn(InterfaceName) -> Self) -> Self {
        InterfaceName::new(name).map_or(Self::Invalid, fault)
    }
}

impl std::fmt::Display for CompileFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAComponent(a) => write!(f, "the {a:?} is not a component"),
            Self::ReservedExport(a) => write!(f, "the {a:?} exports a host interface"),
            Self::CatalogInvalid(a) => write!(f, "the {a:?}'s embedded catalog is invalid"),
            Self::CatalogsPastCap => f.write_str("the embedded catalogs are past their cap"),
            Self::Unsatisfied(i) => write!(f, "nothing serves the import `{}`", i.as_str()),
            Self::Mismatched(i) => write!(f, "the import `{}` is served another type", i.as_str()),
            Self::Invalid => f.write_str("the composition does not validate or compile"),
            Self::TooLarge => f.write_str("the composition is past what the deployment carries"),
            Self::OutOfMemory => {
                f.write_str("compiling took more memory than one compile is given")
            }
        }
    }
}
impl std::error::Error for CompileFault {}

/// An interface's name as a component imports it — `ns:pkg/iface@version` —
/// held to [`is_wit_name`]. Checked again wherever one is decoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub const MAX_BYTES: usize = 128;

    pub fn new(name: &str) -> Option<Self> {
        is_wit_name(name).then(|| Self(name.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        Self::new(&name).ok_or_else(|| serde::de::Error::custom("not an interface name"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interface_name_is_held_to_its_length_and_alphabet() {
        assert!(InterfaceName::new("enclavid:well-known/capture@0.1.0").is_some());
        assert!(InterfaceName::new("wasi:io/poll@0.2.0-rc+build.1").is_some());
        assert!(InterfaceName::new(&"a".repeat(InterfaceName::MAX_BYTES)).is_some());
        for refused in [
            String::new(),
            "a".repeat(InterfaceName::MAX_BYTES + 1),
            "enclavid:x/y z".into(),
            "enclavid:x/\"y\"".into(),
            "enclavid:x/y\n".into(),
        ] {
            assert!(InterfaceName::new(&refused).is_none(), "{refused:?}");
        }
    }

    /// The decoder holds a name to the same rule: a peer cannot hand over text.
    #[test]
    fn a_name_past_the_rule_does_not_decode() {
        let mut bytes = Vec::new();
        ciborium::into_writer(&"enclavid:x/y z", &mut bytes).unwrap();
        assert!(ciborium::from_reader::<InterfaceName, _>(&bytes[..]).is_err());
    }

    /// A plugin's package is held to the same rule where it is decoded.
    #[test]
    fn a_package_past_the_rule_does_not_decode() {
        let decode = |artifact: &Artifact| {
            let mut bytes = Vec::new();
            ciborium::into_writer(artifact, &mut bytes).unwrap();
            ciborium::from_reader::<Artifact, _>(&bytes[..])
        };
        let pinned = Artifact::Plugin("enclavid:well-known@0.1.0".into());
        assert_eq!(decode(&pinned).unwrap(), pinned);
        assert_eq!(decode(&Artifact::Policy).unwrap(), Artifact::Policy);
        assert!(decode(&Artifact::Plugin("free text, not a name".into())).is_err());
    }
}
