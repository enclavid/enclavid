//! The bearer a request to enclavid's API goes with: `ENCLAVID_API_TOKEN`,
//! the token for the API at `ENCLAVID_API_URL`. It goes to that API's origin
//! alone, so a token set for one API never reaches another — the playground,
//! say, which asks for none. A request elsewhere goes without one.

/// The variable the bearer is read from.
pub const ENV_API_TOKEN: &str = "ENCLAVID_API_TOKEN";

/// The variable naming the API the bearer is for.
pub const ENV_API_URL: &str = "ENCLAVID_API_URL";

/// The bearer for a request to `url`, when there is one for its origin.
pub fn api_token_for(url: &str) -> Option<String> {
    bearer_for(url, var(ENV_API_TOKEN), var(ENV_API_URL))
}

/// Whether a bearer is set, for whichever API.
pub fn api_token_set() -> bool {
    var(ENV_API_TOKEN).is_some()
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// `token`, when `url` is at the origin of `api`, the API it is for.
fn bearer_for(url: &str, token: Option<String>, api: Option<String>) -> Option<String> {
    let token = token?;
    (origin(url)? == origin(&api?)?).then_some(token)
}

/// The origin of `url`, `scheme://host[:port]` with a default port left
/// out; none for a URL that is not HTTP's.
fn origin(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bearer_goes_to_the_api_it_is_for_alone() {
        let token = || Some("t".to_string());
        let api = || Some("https://api.enclavid.com".to_string());
        assert_eq!(
            bearer_for("https://api.enclavid.com/api/v1/sessions", token(), api()),
            token()
        );
        assert_eq!(
            bearer_for(
                "https://api.enclavid.com:443/-blue.x/api/v1/sessions/s",
                token(),
                Some("https://api.enclavid.com/".to_string())
            ),
            token()
        );
        for elsewhere in [
            "https://playground.enclavid.com/api/v1/sessions",
            "http://api.enclavid.com/api/v1/sessions",
            "https://api.enclavid.com:8443/api/v1/sessions",
            "https://api.enclavid.com.evil.example/api/v1/sessions",
        ] {
            assert_eq!(bearer_for(elsewhere, token(), api()), None, "{elsewhere}");
        }
        assert_eq!(
            bearer_for("https://api.enclavid.com/api/v1/sessions", token(), None),
            None
        );
        assert_eq!(
            bearer_for("https://api.enclavid.com/api/v1/sessions", None, api()),
            None
        );
        assert_eq!(
            bearer_for(
                "file:///api/v1/sessions",
                token(),
                Some("file:///".to_string())
            ),
            None
        );
    }
}
