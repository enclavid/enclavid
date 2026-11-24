//! `enclavid session ...` — talk to enclavid's API for session
//! lifecycle: create, read state, pull + decrypt disclosures.
//!
//! The API is the one `create` is given, `--api` / `$ENCLAVID_API_URL`:
//! enclavid's own, or the playground's, which answers as it does. A
//! request goes with the bearer in `$ENCLAVID_API_TOKEN` when it goes to
//! the API that token is for, `$ENCLAVID_API_URL`'s, and with none
//! otherwise — the playground asks for none (see [`crate::auth`]). The applicant
//! link `create` prints goes to `--applicants` / `$ENCLAVID_APPLICANT_URL`,
//! as `<base>/<id>`: the session's id is the path's one segment, never in
//! the fragment, which a browser carries across a redirect to another
//! site.
//!
//! `create` caches what later requests about the session need — the API
//! it was created at, the returned `session_token`, the group it
//! was placed on, and the disclosure-key secret — under
//! `enclavid/sessions/<id>/` in the platform config directory (see
//! [`cache`]), so `get` / `disclosures` name the session alone.
//!
//! In front of the API there may be a gateway, which spreads sessions over
//! groups of API instances. It answers a creation with the group it placed
//! the session on, which `create` caches, and `create` may name the build
//! it requires (`--measurement` / `$ENCLAVID_API_MEASUREMENT`). Every later
//! request about the session names the group as a marker at the start of
//! the path, `/-<label>.<build>/api/v1/...`, and so does the applicant
//! link, because the gateway routes a request by that marker alone. That
//! is why both bases are bare origins — see [`bare_origin`]. An API that
//! answers with no group gets paths with no marker.

use anyhow::{Context, Result};

pub mod cache;
pub mod create;
pub mod disclosures;
pub mod get;
mod transport;

/// Where `create` takes the API's origin from.
const API_URL: &str = "--api / $ENCLAVID_API_URL";

/// Where `create` takes the applicants' site's origin from.
const APPLICANT_URL: &str = "--applicants / $ENCLAVID_APPLICANT_URL";

/// The api build `session create` requires, from `--measurement` or,
/// failing that, `$ENCLAVID_API_MEASUREMENT`. `None` when neither is
/// set, which is how a session is created against api directly.
///
/// Checked here rather than left to the gateway so a mistyped value is
/// refused before anything is sent, with the source it came from named.
/// A variable that is set but not UTF-8 is such a value too, not an
/// absent one.
pub fn api_measurement(flag: Option<String>) -> Result<Option<String>> {
    let (value, source) = match flag {
        Some(value) => (value, "--measurement"),
        None => match std::env::var("ENCLAVID_API_MEASUREMENT") {
            Ok(value) => (value, "$ENCLAVID_API_MEASUREMENT"),
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!(
                    "$ENCLAVID_API_MEASUREMENT: expected 96 lowercase hex characters, got a value that is not UTF-8"
                )
            }
        },
    };
    if !is_measurement(&value) {
        anyhow::bail!("{source}: expected 96 lowercase hex characters, got `{value}`");
    }
    Ok(Some(value))
}

/// A launch measurement as the gateway compares it: 48 bytes written
/// as lowercase hex. Uppercase is refused rather than folded, because
/// the build also travels inside the group marker, where it is compared
/// as written.
fn is_measurement(value: &str) -> bool {
    value.len() == 96
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A group as a gateway names it and a path marker carries it,
/// `<label>.<build>`: a label of 1 to 32 characters of a-z, 0-9 or `-`,
/// which is what the gateway holds its labels to, and a build as
/// [`is_measurement`] has it. Nothing else passes, so a group is always
/// exactly one path segment.
fn is_group(value: &str) -> bool {
    value.split_once('.').is_some_and(|(label, build)| {
        (1..=32).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && is_measurement(build)
    })
}

/// `base` as a bare origin, `scheme://host[:port]` with no trailing
/// slash, or an error naming `what`, where it came from.
///
/// A gateway reads a group's marker only at the very start of the path,
/// so a marker behind a path of the base's own —
/// `https://x/verify/-<group>` — is to it an unmarked request, which it
/// refuses. A query or a fragment would swallow the marker the same
/// way. The base cannot carry the marker itself either: the CLI adds
/// it, so it would appear twice.
fn bare_origin(what: &str, base: &str) -> Result<String> {
    let url = url::Url::parse(base).with_context(|| format!("{what} is `{base}`, not a URL"))?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!(
            "{what} is `{base}`, but it must be a bare origin, scheme://host[:port]: \
             a gateway reads the group marker only at the start of the path"
        );
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// `origin`, a bare origin, with the group's marker appended when there
/// is a group, so the gateway sends what follows to that group:
/// `<origin>/-<group>`. Ready for the caller to append an absolute path.
pub fn under_group(origin: &str, group: Option<&str>) -> String {
    match group {
        Some(group) => format!("{origin}/-{group}"),
        None => origin.to_string(),
    }
}

/// The API base for requests about an existing session: the API `create`
/// cached for it, under the marker of the group it cached, or plain when
/// it cached none.
fn session_api(session_id: &str) -> Result<String> {
    let api = cache::read_api(session_id)?;
    let group = cache::read_group(session_id)?;
    Ok(under_group(&api, group.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_measurement_is_96_lowercase_hex() {
        assert!(is_measurement(&"a1".repeat(48)));
        assert!(!is_measurement(&"a1".repeat(47)));
        assert!(!is_measurement(&"a1".repeat(49)));
        assert!(!is_measurement(&"A1".repeat(48)));
        assert!(!is_measurement(&"g1".repeat(48)));
        assert!(!is_measurement(""));
    }

    #[test]
    fn a_flag_is_checked() {
        let good = "0f".repeat(48);
        assert_eq!(api_measurement(Some(good.clone())).unwrap(), Some(good));
        assert!(api_measurement(Some("0F".repeat(48))).is_err());
    }

    #[test]
    fn a_group_is_a_label_and_a_build() {
        let build = "0f".repeat(48);
        assert!(is_group(&format!("blue-2.{build}")));
        assert!(is_group(&format!("{}.{build}", "a".repeat(32))));
        for bad in [
            String::new(),
            " ".to_string(),
            build.clone(),
            format!(".{build}"),
            format!("{}.{build}", "a".repeat(33)),
            format!("Blue.{build}"),
            format!("a/b.{build}"),
            format!("blue.{build}/x"),
            format!("blue.{}", "0F".repeat(48)),
            format!("blue.{}", "0f".repeat(47)),
            "blue.".to_string(),
        ] {
            assert!(!is_group(&bad), "{bad:?}");
        }
    }

    #[test]
    fn a_group_goes_in_as_a_marker() {
        let group = format!("blue.{}", "0f".repeat(48));
        assert_eq!(
            under_group("https://api.example", Some(&group)),
            format!("https://api.example/-{group}"),
        );
        assert_eq!(
            under_group("https://api.example", None),
            "https://api.example"
        );
    }

    #[test]
    fn a_base_is_a_bare_origin() {
        assert_eq!(
            bare_origin("X", "https://api.example/").unwrap(),
            "https://api.example"
        );
        assert_eq!(
            bare_origin("X", "http://localhost:8001").unwrap(),
            "http://localhost:8001"
        );
        let group = format!("blue.{}", "0f".repeat(48));
        for base in [
            "https://example/verify".to_string(),
            "https://example/verify/".to_string(),
            format!("https://example/-{group}"),
            "https://example/?a=b".to_string(),
            "https://example/#x".to_string(),
            "example".to_string(),
        ] {
            assert!(bare_origin("X", &base).is_err(), "{base:?}");
        }
    }
}
