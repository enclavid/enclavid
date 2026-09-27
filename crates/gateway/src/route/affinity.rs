//! Which group a caller's session is in, in a form the caller cannot choose for
//! itself.
//!
//! ## Why a token and not a bare label
//!
//! A session's state is sealed under a key derived from the chip and the
//! measurement, so it can be opened by any api of that build on that part —
//! the group — and by nothing else. Every later request therefore has to reach
//! that group, and the label is how it finds its way.
//!
//! A caller following a link is told the label and its build by that link, and
//! that is safe: one who edits the label lands where its session is not, and one
//! who edits the build is refused unless the label runs it. A caller
//! that also CREATES sessions is different. Handed a bare label it would keep
//! using the one it liked, and every session in the fleet would pile into one
//! group. So what it is handed is signed: a label it can read but not forge,
//! with an expiry.
//!
//! ## It binds the build, not only the label
//!
//! A label is the host's to re-declare, so a token naming only a label would
//! follow that re-declaration. The caller named a BUILD once, at placement, and
//! a token carrying only the group would let that choice bind the first request
//! and no other.
//!
//! So the build travels in the token and `crate::route` compares it to what
//! the label runs now. It is compared, never trusted: a forged build only
//! agrees with the table when the table already says so, which is why the
//! signature is still worth no more than the paragraph below says.
//!
//! A token that no longer agrees is treated as absent rather than refused. The
//! caller names what it needs again and is placed again — a recovery it already
//! knows how to perform, because it is how it arrived the first time.
//!
//! ## What the signature is worth, and what it is not
//!
//! Nothing anyone's data rests on. Forging one steers a session to a group that
//! will not have it, which is a denial of service the host can cause anyway by
//! not carrying bytes. That is why the key comes from the host with the rest of
//! the configuration, why every gateway may share it, and why it is NOT derived
//! from the chip: a chip-derived key could not be shared, and would reintroduce
//! affinity one layer up.
//!
//! ## The gap this does not close, stated so it is not mistaken for closed
//!
//! This role does not know which requests CREATE a session — that is api's
//! contract, and reading it here would put api's routes in a measured image.
//! So a caller holding a valid token gets its group for any request, creations
//! included, and for as long as it keeps asking: every use hands back a fresh
//! token, so the expiry bounds only a caller that falls silent. A link's marker
//! does the same with no token at all — it names a group, and a caller that has
//! seen a label can write one. Only knowing which paths create would close
//! either.
//!
//! ## The format
//!
//! `<label>.<build>.<exp>.<tag>`: the group as a link carries it, the expiry in
//! Unix seconds, and an HMAC-SHA256 over everything before the last dot, in
//! hex. Nothing is read out of a token until its tag agrees, and the split
//! after that is unambiguous: a label holds no dot, a build is hex, an expiry
//! is digits.
//!
//! Not a JWT. The token is hop-local — nothing outside this role issues or
//! reads it — so a standard format would buy no reader. What it would cost is
//! base64 and JSON on the way in, and a header naming its own algorithm, which
//! a verifier has to pin before it can trust anything else. HMAC from `ring`,
//! because it is the code this role's TLS already runs on: checking a token
//! adds no cryptography to the image.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::hmac;

/// Where a token travels, in both directions: the caller sends back what it was
/// given. A header rather than a path, because api's paths are api's.
pub const TOKEN_HEADER: &str = "x-enclavid-group-token";

/// The group a request was placed on, in plain sight beside the token, in the
/// form a link carries it: `<label>.<build>`.
///
/// A caller that writes links for others needs exactly that to write them with.
/// The token begins with the same string, but a token is this role's own
/// bookkeeping; this header is the part of the response a caller may read.
pub const GROUP_HEADER: &str = "x-enclavid-group";

/// What a token says: the group a caller was placed on, and the build it was
/// placed for.
///
/// Both, because the group alone is a moving target. A label is the host's to
/// re-declare, so a token naming only a label would follow that re-declaration
/// and put a caller on a build it never named — silently, on the one request
/// kind where nothing else would catch it. An existing session would break
/// loudly instead, its state being sealed to the old build; a NEW session
/// created on such a token would simply land on the new one.
pub struct Placement {
    pub group: String,
    pub build: String,
}

/// What the host gave this role to sign and check affinity tokens with.
pub struct Keys {
    current: hmac::Key,
    /// Accepted but never minted with. Without it, rotating the key would
    /// refuse every token issued in the minutes before the push — a session in
    /// flight would lose its machine for a configuration change.
    previous: Option<hmac::Key>,
    ttl: Duration,
}

impl Keys {
    pub fn new(current: [u8; 32], previous: Option<[u8; 32]>, ttl: Duration) -> Keys {
        let key = |bytes: [u8; 32]| hmac::Key::new(hmac::HMAC_SHA256, &bytes);
        Keys {
            current: key(current),
            previous: previous.map(key),
            ttl,
        }
    }

    /// A token naming `group` and the `build` it was placed for, valid from now.
    ///
    /// The clock is the guest's, which the host provides — so an expiry is a
    /// number the host can move. That is consistent with what this token
    /// protects: the host's own balancing. What it does NOT protect that way is
    /// the build, which is compared against the table rather than trusted.
    pub fn mint(&self, group: &str, build: &str, now: SystemTime) -> String {
        let signed = format!(
            "{}.{}",
            super::marker(group, build),
            seconds(now + self.ttl)
        );
        let tag = hex::encode(hmac::sign(&self.current, signed.as_bytes()));
        format!("{signed}.{tag}")
    }

    /// What a token says, or nothing at all.
    ///
    /// One answer for every way a token can fail — wrong shape, wrong key,
    /// expired. The caller does the same thing in each case: place the request
    /// as if it had arrived without one.
    pub fn placement(&self, token: &str, now: SystemTime) -> Option<Placement> {
        let (signed, tag) = token.rsplit_once('.')?;
        let tag = hex::decode(tag).ok()?;
        // Constant time, through `ring`'s own comparison: a token is
        // attacker-supplied, and a byte-at-a-time comparison would say how much
        // of a forgery was right.
        let mut keys = std::iter::once(&self.current).chain(self.previous.iter());
        if !keys.any(|key| hmac::verify(key, signed.as_bytes(), &tag).is_ok()) {
            return None;
        }

        let (marked, exp) = signed.rsplit_once('.')?;
        let (group, build) = marked.split_once(super::BUILD_MARK)?;
        (exp.parse::<u64>().ok()? > seconds(now)).then(|| Placement {
            group: group.to_owned(),
            build: build.to_owned(),
        })
    }
}

fn seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys::new([7u8; 32], None, Duration::from_secs(600))
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    /// A build, spelled the way a real one is.
    const BUILD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn minted(keys: &Keys) -> String {
        keys.mint("group-7", BUILD, now())
    }

    /// Both halves come back, because the group alone would follow a
    /// re-declaration onto a build the caller never named.
    #[test]
    fn a_token_names_the_group_and_the_build_it_was_minted_for() {
        let keys = keys();
        let placed = keys.placement(&minted(&keys), now()).unwrap();
        assert_eq!(placed.group, "group-7");
        assert_eq!(placed.build, BUILD);
    }

    /// The group as a link carries it, the expiry, and a tag — readable by eye,
    /// so an operator needs no tool to see where a token points.
    #[test]
    fn the_shape_is_the_marker_an_expiry_and_a_tag() {
        let token = minted(&keys());
        let exp = seconds(now() + Duration::from_secs(600));
        let (signed, tag) = token.rsplit_once('.').unwrap();
        assert_eq!(
            signed,
            format!("{}.{exp}", super::super::marker("group-7", BUILD))
        );
        assert_eq!(tag.len(), 64);
        assert!(tag.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn another_key_does_not_pass() {
        let token = minted(&Keys::new([9u8; 32], None, Duration::from_secs(600)));
        assert!(keys().placement(&token, now()).is_none());
    }

    /// A token minted before a key rotation still works, which is what keeps a
    /// session in flight from losing its group to a configuration change.
    #[test]
    fn the_previous_key_is_accepted_but_not_minted_with() {
        let old = Keys::new([9u8; 32], None, Duration::from_secs(600));
        let rotated = Keys::new([7u8; 32], Some([9u8; 32]), Duration::from_secs(600));

        let before = minted(&old);
        assert_eq!(rotated.placement(&before, now()).unwrap().group, "group-7");

        // What it mints is signed with the current key, so a gateway that has
        // not seen the old one still accepts it.
        let after = minted(&rotated);
        assert_eq!(
            Keys::new([7u8; 32], None, Duration::from_secs(600))
                .placement(&after, now())
                .unwrap()
                .group,
            "group-7"
        );
    }

    #[test]
    fn an_expired_token_names_nothing() {
        let keys = keys();
        let token = minted(&keys);
        assert!(
            keys.placement(&token, now() + Duration::from_secs(601))
                .is_none()
        );
    }

    #[test]
    fn nonsense_names_nothing() {
        let keys = keys();
        let token = minted(&keys);
        let (signed, tag) = token.rsplit_once('.').unwrap();
        let other = keys.mint("group-8", BUILD, now());
        for bad in [
            String::new(),
            "....".to_owned(),
            token.replace('.', ""),
            // No tag at all: the expiry is then read as one, and is not it.
            signed.to_owned(),
            // A tag cut short, or lengthened.
            format!("{signed}.{}", &tag[..62]),
            format!("{signed}.{tag}00"),
            // Another token's tag on this token's parts.
            format!("{signed}.{}", other.rsplit_once('.').unwrap().1),
        ] {
            assert!(keys.placement(&bad, now()).is_none(), "accepted `{bad}`");
        }
    }

    /// Every part the tag covers is covered: edit any one without the key and
    /// the token names nothing.
    #[test]
    fn an_edited_part_does_not_pass() {
        let keys = keys();
        let token = minted(&keys);
        let (signed, tag) = token.rsplit_once('.').unwrap();
        let later = seconds(now() + Duration::from_secs(6_000));
        for edited in [
            signed.replacen("group-7", "group-8", 1),
            signed.replacen(
                &format!(".{}", seconds(now() + Duration::from_secs(600))),
                &format!(".{later}"),
                1,
            ),
        ] {
            assert_ne!(edited, signed);
            let bad = format!("{edited}.{tag}");
            assert!(keys.placement(&bad, now()).is_none(), "accepted `{bad}`");
        }
    }

    /// A build edited into another does not survive, which is what makes the
    /// comparison in `crate::route` worth making: a caller cannot hand itself a
    /// token for a build it was never placed on.
    #[test]
    fn a_rewritten_build_does_not_pass() {
        let keys = keys();
        let token = minted(&keys);
        let bad = token.replacen(BUILD, &"b".repeat(96), 1);
        assert_ne!(bad, token);
        assert!(keys.placement(&bad, now()).is_none());
    }
}
