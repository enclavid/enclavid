//! `enclavid session ...` — talk to the Enclavid API for session
//! lifecycle: create, read state, pull + decrypt disclosures.
//!
//! Auth comes from `auth::get_access_token` (env API_TOKEN → M2M →
//! cached cloud login). API endpoint comes from `$ENCLAVID_API_URL`
//! (default `http://localhost:8001`). The applicant URL printed by
//! `create` comes from `$ENCLAVID_APPLICANT_URL` (default
//! `http://localhost:5173`).
//!
//! `create` caches the returned `client_session_token` and the
//! disclosure-key secret under `enclavid/sessions/<id>/` in the
//! platform config directory (see [`cache`]) so subsequent `get` /
//! `disclosures` work without re-passing them.
//!
//! In front of api there may be a gateway, which spreads sessions over
//! groups of api instances. `create` then names the api build it
//! requires (`--measurement` / `$ENCLAVID_API_MEASUREMENT`), the gateway
//! answers with the group it placed the session on, and `create` caches
//! that group beside the token. Every later request about the session
//! names the group as a marker at the start of the path,
//! `/-<label>.<build>/api/v1/...`, and so does the applicant link,
//! because the gateway routes a request by that marker alone. That is
//! why both bases must then be bare origins — see [`under_group`].
//! Talking to api directly, no build is named, no group comes back, and
//! paths carry no marker.

use anyhow::{Context, Result};

pub mod cache;
pub mod create;
pub mod disclosures;
pub mod get;
mod transport;

const API_URL_VAR: &str = "ENCLAVID_API_URL";
const APPLICANT_URL_VAR: &str = "ENCLAVID_APPLICANT_URL";

/// `$ENCLAVID_API_URL` resolver — same lookup pattern as other CLI
/// env overrides. Defaulting to localhost is fine because non-local
/// production CLI usage will set this explicitly (or get it through
/// discovery, when discovery starts publishing it).
pub fn api_url() -> String {
    std::env::var(API_URL_VAR).unwrap_or_else(|_| "http://localhost:8001".to_string())
}

/// `$ENCLAVID_APPLICANT_URL` resolver — base origin of the applicant
/// SPA. Used only for printing the "open this in a browser" hint
/// after `session create`, as `<base>/#/session/<id>`: the page is
/// served at the root and routes on the URL fragment, which a browser
/// never sends, so loading the page names no session. When the
/// session was placed on a group, the link goes under that group's
/// marker — see [`under_group`]. Default targets `pnpm dev` on :5173;
/// set to `http://localhost:8002` when api serves built static instead.
pub fn applicant_url() -> String {
    std::env::var(APPLICANT_URL_VAR).unwrap_or_else(|_| "http://localhost:5173".to_string())
}

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
/// slash, or an error naming `var`, the variable it came from.
///
/// A gateway reads a group's marker only at the very start of the path,
/// so a marker behind a path of the base's own —
/// `https://x/verify/-<group>` — is to it an unmarked request, which it
/// refuses. A query or a fragment would swallow the marker the same
/// way. The base cannot carry the marker itself either: the CLI adds
/// it, so it would appear twice.
fn bare_origin(var: &str, base: &str) -> Result<String> {
    let url = url::Url::parse(base).with_context(|| format!("${var} is `{base}`, not a URL"))?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!(
            "${var} is `{base}`, but through a gateway it must be a bare origin, \
             scheme://host[:port]: the gateway reads the group marker only at the start of the path"
        );
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// `base` with the group's marker appended when there is a group, so
/// the gateway sends what follows to that group: `<base>/-<group>`,
/// `base` then held to a bare origin by [`bare_origin`]. Without a
/// group, `base` as it is, path and all. Either way without a trailing
/// slash, ready for the caller to append an absolute path.
pub fn under_group(var: &str, base: &str, group: Option<&str>) -> Result<String> {
    match group {
        Some(group) => Ok(format!("{}/-{group}", bare_origin(var, base)?)),
        None => Ok(base.trim_end_matches('/').to_string()),
    }
}

/// The api base for requests about an existing session: under the
/// marker of the group `create` cached for it, or plain when it cached
/// none.
fn session_api(session_id: &str) -> Result<String> {
    let group = cache::read_group(session_id)?;
    under_group(API_URL_VAR, &api_url(), group.as_deref())
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
            under_group("X", "https://api.example/", Some(&group)).unwrap(),
            format!("https://api.example/-{group}"),
        );
        assert_eq!(
            under_group("X", "http://localhost:8001", Some(&group)).unwrap(),
            format!("http://localhost:8001/-{group}"),
        );
        assert_eq!(
            under_group("X", "https://api.example/", None).unwrap(),
            "https://api.example"
        );
    }

    #[test]
    fn under_a_group_a_base_must_be_a_bare_origin() {
        let group = format!("blue.{}", "0f".repeat(48));
        for base in [
            "https://example/verify".to_string(),
            "https://example/verify/".to_string(),
            format!("https://example/-{group}"),
            "https://example/?a=b".to_string(),
            "https://example/#x".to_string(),
            "example".to_string(),
        ] {
            assert!(under_group("X", &base, Some(&group)).is_err(), "{base:?}");
        }
    }

    #[test]
    fn without_a_group_a_base_keeps_its_own_path() {
        assert_eq!(
            under_group("X", "https://example/verify/", None).unwrap(),
            "https://example/verify",
        );
    }
}
