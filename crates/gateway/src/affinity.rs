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
//! A caller following a link is told the label by that link, and that is safe:
//! one who edits it lands where its session is not, and is refused. A caller
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
//! So the build travels in the claims and `crate::proxy` compares it to what
//! the label runs now. It is compared, never trusted: a forged claim only
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
//! included, and the expiry is what bounds that. The routing schema, when it
//! lands, is what closes it: creation paths are placed by this role and ignore
//! the token.
//!
//! ## The format is a JWT, written by hand
//!
//! HS256 over the usual three base64url parts, so any tool can read one — but
//! assembled here rather than through a library, because a measured image
//! should not gain a JWT parser, PEM support and an ASN.1 decoder to check
//! thirty-two bytes of HMAC. The token is hop-local: nothing outside this role
//! issues or reads it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Where a token travels, in both directions: the caller sends back what it was
/// given. A header rather than a path, because api's paths are api's.
pub const TOKEN_HEADER: &str = "x-enclavid-group-token";

/// The group a request was placed on, in plain sight beside the token.
///
/// A caller that writes links for others needs the label to write them with, and
/// it is already inside the token — this only saves it from decoding one.
pub const GROUP_HEADER: &str = "x-enclavid-group";

/// The fixed header of every token this role mints.
const JWT_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

#[derive(Serialize, Deserialize)]
struct Claims {
    group: String,
    /// The build that group ran when the token was minted. Carried so that the
    /// caller's choice binds every later request and not only the first — see
    /// [`Placement`].
    build: String,
    exp: u64,
}

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
    current: [u8; 32],
    /// Accepted but never minted with. Without it, rotating the key would
    /// refuse every token issued in the minutes before the push — a session in
    /// flight would lose its machine for a configuration change.
    previous: Option<[u8; 32]>,
    ttl: Duration,
}

impl Keys {
    pub fn new(current: [u8; 32], previous: Option<[u8; 32]>, ttl: Duration) -> Keys {
        Keys {
            current,
            previous,
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
        let claims = Claims {
            group: group.to_owned(),
            build: build.to_owned(),
            exp: seconds(now + self.ttl),
        };
        let payload = B64.encode(serde_json::to_vec(&claims).expect("claims serialise"));
        let signed = format!("{JWT_HEADER}.{payload}");
        let signature = B64.encode(sign(&self.current, signed.as_bytes()));
        format!("{signed}.{signature}")
    }

    /// What a token says, or nothing at all.
    ///
    /// One answer for every way a token can fail — wrong shape, wrong key,
    /// expired. The caller does the same thing in each case: place the request
    /// as if it had arrived without one.
    pub fn placement(&self, token: &str, now: SystemTime) -> Option<Placement> {
        let (signed, signature) = token.rsplit_once('.')?;
        let (header, payload) = signed.split_once('.')?;
        if header != JWT_HEADER {
            return None;
        }
        let signature = B64.decode(signature).ok()?;
        let keys = std::iter::once(&self.current).chain(self.previous.iter());
        if !keys
            .into_iter()
            .any(|key| verify(key, signed.as_bytes(), &signature))
        {
            return None;
        }

        let claims: Claims = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
        (claims.exp > seconds(now)).then_some(Placement {
            group: claims.group,
            build: claims.build,
        })
    }
}

fn sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Constant time, through `hmac`'s own comparison: a token is attacker-supplied
/// and a byte-at-a-time comparison would say how much of a forgery was right.
fn verify(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(message);
    mac.verify_slice(signature).is_ok()
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

    /// The shape is an ordinary JWT, so an operator can read one with any tool.
    #[test]
    fn the_shape_is_a_jwt() {
        let token = minted(&keys());
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = B64.decode(parts[0]).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&header).unwrap(),
            serde_json::json!({"alg": "HS256", "typ": "JWT"})
        );
        let claims = B64.decode(parts[1]).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&claims).unwrap()["build"],
            serde_json::json!(BUILD)
        );
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
        for bad in [
            String::new(),
            "....".to_owned(),
            token.replace('.', ""),
            // A claim edited without re-signing: the whole point of signing it.
            format!("{}.{}", JWT_HEADER, token.split('.').nth(1).unwrap()),
            // Another algorithm announced in the header.
            format!(
                "{}.{}",
                B64.encode(br#"{"alg":"none","typ":"JWT"}"#),
                token.split_once('.').unwrap().1
            ),
        ] {
            assert!(keys.placement(&bad, now()).is_none(), "accepted `{bad}`");
        }
    }

    /// A claim edited to name another build does not survive, which is what
    /// makes the comparison in `crate::proxy` worth making: a caller cannot
    /// hand itself a token for a build it was never placed on.
    #[test]
    fn a_rewritten_build_does_not_pass() {
        let keys = keys();
        let token = minted(&keys);
        let (_, rest) = token.split_once('.').unwrap();
        let (_, signature) = rest.split_once('.').unwrap();
        let forged = serde_json::json!({
            "group": "group-7",
            "build": "b".repeat(96),
            "exp": seconds(now() + Duration::from_secs(600)),
        });
        let payload = B64.encode(serde_json::to_vec(&forged).unwrap());
        let bad = format!("{JWT_HEADER}.{payload}.{signature}");
        assert!(keys.placement(&bad, now()).is_none());
    }
}
