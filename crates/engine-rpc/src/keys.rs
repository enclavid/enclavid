//! The two strings that name a cache slot, as types that cannot hold a shape
//! nobody minted.
//!
//! Both cross the execute hop, both end up naming a cache slot, and each is CHOSEN
//! by the side that does not read it back. `composition_key` travels api → worker,
//! where the worker files bytes under it; `compat_token` travels worker → api,
//! where api joins it into an L2 cache id.
//!
//! The two seats are not symmetric, and flattening them would undo the distinction
//! the rest of this leg exists to make. On the worker, the producer is genuinely
//! UNIDENTIFIED — the listener runs `AcceptAny`. On api, the producer IS
//! identified: api dials under a pinned measurement. What is open there is not who
//! sent the token but that it is the peer's own word about its own runtime, which
//! is `Asserted`'s question and is discharged at api's call site.
//!
//! What the types give is a SHAPE that was checked, and the check is the
//! constructor rather than a call beside it. [`CompositionKey`] has no fallible
//! constructor at all on the minting side — it is built from a digest, so an
//! ill-formed one cannot be produced — and its `Deserialize` is that same
//! statement read back off the wire. [`CompatToken`] is parsed once, at the boot
//! of the role that mints it, and its `Deserialize` is the reader's own copy of
//! the same rule.
//!
//! What they do NOT give is authenticity. A well-formed `composition_key` is still
//! whichever slot the caller chose, and the thing that keeps one caller out of
//! another's is the measurement partition the worker builds the slot from, not
//! this. These types bound a name's SIZE and ALPHABET — enough that a joined id
//! cannot be read two ways, and that a peer cannot decide how much of this side's
//! memory a name occupies.

use std::fmt;

use serde::{Deserialize, Serialize, de};

/// Hex characters in a [`CompositionKey`] — a SHA-256, so 32 bytes rendered.
const COMPOSITION_KEY_HEX: usize = 64;

/// Longest [`CompatToken`] accepted. This build's own is `wt<major>-cm-fuel`,
/// around fifteen characters; the ceiling is generous room for a longer runtime
/// version string and nothing like room for a payload.
const COMPAT_TOKEN_MAX: usize = 64;

/// A malformed name, refused at the boundary it arrived on.
///
/// One variant per rule so a reader learns which rule was broken without the
/// VALUE being quoted back — the value is peer-chosen, and an error carrying it
/// would be the peer writing into this side's logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Not the fixed width the shape requires.
    Length,
    /// A character outside the permitted alphabet.
    Alphabet,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Length => write!(f, "wrong length"),
            KeyError::Alphabet => write!(f, "character outside the permitted set"),
        }
    }
}
impl std::error::Error for KeyError {}

/// Names one fused composition: 64 lowercase hex characters, always.
///
/// api computes it, from the pinned policy ref, the pinned plugin set and the
/// authority each was fetched under; the worker caches under it and NEVER names
/// one back. That direction is the L2 cache-poisoning defence and it is not this
/// type's doing — what this type adds is that the string reaching a store is a
/// digest rendering and can be nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CompositionKey(String);

impl CompositionKey {
    /// The only way to mint one, and it cannot fail: a digest has exactly the
    /// shape the type promises, so there is no error for a caller to handle and no
    /// fallible path for one to take by mistake.
    pub fn from_digest(digest: [u8; 32]) -> CompositionKey {
        // Rendered here rather than via a hex crate: this contract's dependency
        // list is every image's, and a table lookup has no failure to describe.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(COMPOSITION_KEY_HEX);
        for b in digest {
            s.push(HEX[usize::from(b >> 4)] as char);
            s.push(HEX[usize::from(b & 0xf)] as char);
        }
        CompositionKey(s)
    }

    /// The same rule [`from_digest`](Self::from_digest) states, applied to a string
    /// somebody else produced.
    ///
    /// Private, and that is what keeps `from_digest` the only MINT. `Deserialize`
    /// lives in this module and reaches it; nothing outside can, so no caller can
    /// reach for a fallible constructor when the infallible one is what it wants.
    fn parse(s: &str) -> Result<CompositionKey, KeyError> {
        if s.len() != COMPOSITION_KEY_HEX {
            return Err(KeyError::Length);
        }
        if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(KeyError::Alphabet);
        }
        Ok(CompositionKey(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CompositionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CompositionKey {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        CompositionKey::parse(&s).map_err(de::Error::custom)
    }
}

/// The worker's cwasm ABI identifier — what makes an L2 entry a cwasm THIS
/// runtime can deserialize.
///
/// It is the worker's own word about itself, and api cannot check that it names
/// the runtime it claims. Two things follow, and only the second is this type's
/// job. A LYING token costs a recompile into a slot nobody else uses, which is
/// bounded by the key space it shares with a `composition_key` api computed. An
/// UNBOUNDED token is a peer-chosen string of any length and any bytes that api
/// then joins into a cache id, keeps as AEAD associated data, and reads back — so
/// it is how much of THIS side a peer gets to size, and how many ways the joined
/// id can be read, that the shape here refuses.
///
/// Not a bound on what the store sees: `CacheStore` derives the blob name by HKDF
/// before any backend is touched, so 64 hex characters reach it whatever this
/// says.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CompatToken(String);

impl CompatToken {
    /// Parse one, which is how BOTH sides get one: the worker at boot from its own
    /// runtime, api from the wire. Same rule, written once — a mint that could
    /// produce what the reader refuses would be a contract with two meanings.
    ///
    /// The alphabet is what a version string needs and nothing more: ASCII
    /// alphanumerics plus the three separators a runtime version uses. It is not a
    /// safety property of any store, it is the statement that this field carries a
    /// version identifier and not text.
    pub fn parse(s: &str) -> Result<CompatToken, KeyError> {
        if s.is_empty() || s.len() > COMPAT_TOKEN_MAX {
            return Err(KeyError::Length);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(KeyError::Alphabet);
        }
        Ok(CompatToken(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CompatToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CompatToken {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        CompatToken::parse(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T, ()> {
        let mut b = Vec::new();
        ciborium::into_writer(&s, &mut b).expect("a string encodes");
        ciborium::from_reader(&b[..]).map_err(|_| ())
    }

    #[test]
    fn a_digest_renders_to_the_shape_the_wire_accepts() {
        let key = CompositionKey::from_digest([0xABu8; 32]);
        assert_eq!(key.as_str().len(), COMPOSITION_KEY_HEX);
        assert_eq!(&key.as_str()[..4], "abab");
        assert_eq!(CompositionKey::parse(key.as_str()).unwrap(), key);
    }

    #[test]
    fn every_byte_renders_and_reparses() {
        let mut digest = [0u8; 32];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(8);
        }
        let key = CompositionKey::from_digest(digest);
        assert_eq!(CompositionKey::parse(key.as_str()).unwrap(), key);
    }

    /// The decoder is the enforcement, so the refusals are asserted THROUGH it —
    /// a `parse` that agreed while `Deserialize` did not would be the bug.
    #[test]
    fn a_composition_key_that_is_not_a_digest_rendering_is_refused_on_decode() {
        for bad in [
            "",
            &"a".repeat(63),
            &"a".repeat(65),
            // Uppercase hex is a DIFFERENT rendering of the same digest, so
            // accepting it would make one composition two slots.
            &"A".repeat(64),
            &"g".repeat(64),
            // The character the L2 blob name is joined on: a key free to contain
            // it is a key that can be read two ways.
            &format!("{}.{}", "a".repeat(31), "b".repeat(32)),
        ] {
            assert!(
                decode::<CompositionKey>(bad).is_err(),
                "accepted {bad:?} as a composition key"
            );
        }
    }

    #[test]
    fn this_shape_of_compat_token_round_trips() {
        let t = CompatToken::parse("wt46-cm-fuel").expect("the shape this build mints");
        assert_eq!(decode::<CompatToken>(t.as_str()).unwrap(), t);
    }

    #[test]
    fn an_unbounded_or_untyped_compat_token_is_refused_on_decode() {
        for bad in [
            "".to_string(),
            "a".repeat(COMPAT_TOKEN_MAX + 1),
            // Not a version identifier: whitespace, a newline that would split a
            // line in whatever reads the name back, a path.
            "wt46 cm".to_string(),
            "wt46\ncm".to_string(),
            "wt46/../etc".to_string(),
        ] {
            assert!(
                decode::<CompatToken>(&bad).is_err(),
                "accepted {bad:?} as a compat token"
            );
        }
    }
}
