//! Live RCAR round-trip against the dev Trustee KBS.
//!
//! Requires the KBS profile up and a registered resource:
//!   cd enclavid-env && docker logout ghcr.io && docker compose --profile kbs up -d
//!   ADMIN=$(cat kbs/config/docker-compose/admin-token)
//!   curl -X POST localhost:8080/kbs/v0/resource/default/test/secret \
//!        -H "Authorization: Bearer $ADMIN" --data-binary 'hello-from-kbs'
//! Run:  cargo test -p enclavid-kbs-client --test live -- --ignored --nocapture

use enclavid_kbs_client::{RcarSession, SampleEvidence, TeeKeyPair};

const KBS: &str = "http://localhost:8080";

/// Send a request; return (status, set-cookies, body) regardless of status.
fn send(req: ureq::Request, body: Option<&[u8]>) -> (u16, Vec<String>, Vec<u8>) {
    let result = match body {
        Some(b) => req.send_bytes(b),
        None => req.call(),
    };
    let resp = match result {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => panic!("transport error: {e}"),
    };
    let status = resp.status();
    let cookies: Vec<String> = resp.all("set-cookie").iter().map(|s| s.to_string()).collect();
    let mut buf = Vec::new();
    use std::io::Read;
    resp.into_reader().read_to_end(&mut buf).unwrap();
    (status, cookies, buf)
}

/// Extract `kbs-session-id=...` (value up to the first `;`) for the Cookie header.
fn session_cookie(set_cookies: &[String]) -> String {
    for c in set_cookies {
        if let Some(rest) = c.strip_prefix("kbs-session-id=") {
            let val = rest.split(';').next().unwrap_or("");
            return format!("kbs-session-id={val}");
        }
    }
    panic!("no kbs-session-id in {set_cookies:?}");
}

#[test]
#[ignore = "requires live Trustee (docker compose --profile kbs up)"]
fn rcar_round_trip_releases_resource() {
    let mut session = RcarSession::new(TeeKeyPair::generate().unwrap(), SampleEvidence);

    // leg 1: auth -> nonce + cookie
    let (st, cookies, body) = send(
        ureq::post(&format!("{KBS}/kbs/v0/auth")).set("Content-Type", "application/json"),
        Some(&session.auth_body().unwrap()),
    );
    assert_eq!(st, 200, "auth failed: {}", String::from_utf8_lossy(&body));
    let cookie = session_cookie(&cookies);
    session.set_challenge(&body).unwrap();

    // leg 2: attest -> token (validates the SHA-384 report_data binding)
    let (st, _c, body) = send(
        ureq::post(&format!("{KBS}/kbs/v0/attest"))
            .set("Content-Type", "application/json")
            .set("Cookie", &cookie),
        Some(&session.attest_body().unwrap()),
    );
    assert_eq!(st, 200, "attest failed: {}", String::from_utf8_lossy(&body));

    // leg 3: resource -> JWE wrapped to our key
    let (st, _c, body) = send(
        ureq::get(&format!("{KBS}/kbs/v0/resource/default/test/secret")).set("Cookie", &cookie),
        None,
    );
    assert_eq!(st, 200, "resource failed: {}", String::from_utf8_lossy(&body));

    let plaintext = session.unwrap_resource(&body).unwrap();
    assert_eq!(plaintext, b"hello-from-kbs", "got: {plaintext:?}");
    println!("RCAR ok: released resource = {:?}", String::from_utf8_lossy(&plaintext));
}
