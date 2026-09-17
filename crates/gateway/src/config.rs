//! What the host may tell this role, and the check a push has to pass.
//!
//! ## Why this is not on the command line
//!
//! The command line is measured, so anything on it is part of this role's
//! digest. What arrives here is the fleet's SHAPE — which api builds run and at
//! which addresses — and it changes whenever a machine is added or a build is
//! rolled. On the command line it would make the digest a function of the
//! deployment, and a consumer, which verifies THIS role and then trusts it to
//! check api, would have nothing stable to verify against.
//!
//! ## Why it may come from the host at all
//!
//! Every value here says WHERE this role may go, never WHETHER to check what it
//! finds there. An upstream's measurement is a routing hint the connector proves
//! at the handshake, so a lie about one is a route that fails, not a route that
//! is taken. There is deliberately no field that could say otherwise.
//!
//! ## The type is the grammar
//!
//! JSON decoded into these structs with `deny_unknown_fields`: an unknown or
//! misspelt key is a refusal rather than a line quietly ignored, and nothing
//! beyond what the structs spell can be expressed.
//!
//! A push is refused WHOLE if any entry in it is wrong, and the answer says
//! which. There is a sender to tell, and a table missing one declared build is a
//! quieter failure than a push that did not apply.

use serde::Deserialize;

/// One push: the complete table, never a change to the previous one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Push {
    upstreams: Vec<Upstream>,
}

/// One api instance, as the host declares it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// The build the host says runs there. Proved at the handshake, not here.
    pub measurement: String,
    /// Where api serves the applicant surface.
    pub applicant: String,
    /// Where api serves the consumer surface.
    pub client: String,
}

/// The upstreams a push declares, or why it is refused.
///
/// The reason goes back to the sender and nowhere else. It may quote what the
/// host sent, which is the host's own configuration.
pub fn parse(body: &[u8]) -> Result<Vec<Upstream>, String> {
    let push: Push = serde_json::from_slice(body).map_err(|e| e.to_string())?;

    for (i, upstream) in push.upstreams.iter().enumerate() {
        if fleet_transport::Measurement::parse(&upstream.measurement).is_none() {
            return Err(format!(
                "upstreams[{i}].measurement: expected 96 lowercase hex characters"
            ));
        }
        // Two entries for one build would leave routing to pick one by position,
        // silently, and the other would never be reached.
        if let Some(j) = push.upstreams[..i]
            .iter()
            .position(|earlier| earlier.measurement == upstream.measurement)
        {
            return Err(format!(
                "upstreams[{i}].measurement: already declared by upstreams[{j}]"
            ));
        }
        fleet_transport::check_dial_addr(&upstream.applicant)
            .map_err(|e| format!("upstreams[{i}].applicant: {e}"))?;
        fleet_transport::check_dial_addr(&upstream.client)
            .map_err(|e| format!("upstreams[{i}].client: {e}"))?;
    }

    Ok(push.upstreams)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(c: char) -> String {
        c.to_string().repeat(96)
    }

    fn upstream(measurement: &str, applicant: &str, client: &str) -> String {
        format!(
            r#"{{"measurement":"{measurement}","applicant":"{applicant}","client":"{client}"}}"#
        )
    }

    fn push(entries: &[String]) -> Vec<u8> {
        format!(r#"{{"upstreams":[{}]}}"#, entries.join(",")).into_bytes()
    }

    #[test]
    fn a_well_formed_push_is_taken_in_order() {
        let got = parse(&push(&[
            upstream(&m('a'), "127.0.0.1:1", "127.0.0.1:2"),
            upstream(&m('b'), "127.0.0.1:3", "127.0.0.1:4"),
        ]))
        .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].measurement, m('a'));
        assert_eq!(got[1].client, "127.0.0.1:4");
    }

    /// Declaring no api at all is a state the host may choose, not a mistake to
    /// refuse: every request then fails as an unavailable upstream.
    #[test]
    fn an_empty_table_is_a_table() {
        assert!(parse(&push(&[])).unwrap().is_empty());
    }

    /// The table is required rather than defaulted: a push that says nothing
    /// about upstreams is not a push that declares none.
    #[test]
    fn a_push_without_the_table_is_refused() {
        assert!(parse(b"{}").is_err());
    }

    #[test]
    fn an_unknown_key_is_refused_not_ignored() {
        assert!(parse(br#"{"upstreams":[],"verify_measurement":false}"#).is_err());

        let body = format!(
            r#"{{"upstreams":[{{"measurement":"{}","applicant":"127.0.0.1:1","client":"127.0.0.1:2","node":"x"}}]}}"#,
            m('a')
        );
        assert!(parse(body.as_bytes()).is_err());
    }

    #[test]
    fn a_measurement_that_could_never_be_proved_is_refused() {
        for bad in ["aa11".to_owned(), m('A'), m('g'), String::new()] {
            let err = parse(&push(&[upstream(&bad, "127.0.0.1:1", "127.0.0.1:2")]))
                .err()
                .unwrap_or_else(|| panic!("accepted `{bad}`"));
            assert!(err.starts_with("upstreams[0].measurement"), "{err}");
        }
    }

    #[test]
    fn a_build_declared_twice_is_refused() {
        let err = parse(&push(&[
            upstream(&m('a'), "127.0.0.1:1", "127.0.0.1:2"),
            upstream(&m('b'), "127.0.0.1:3", "127.0.0.1:4"),
            upstream(&m('a'), "127.0.0.1:5", "127.0.0.1:6"),
        ]))
        .err()
        .unwrap();
        assert!(
            err.contains("upstreams[2]") && err.contains("upstreams[0]"),
            "{err}"
        );
    }

    /// One bad entry refuses the push whole, and the answer names it.
    #[test]
    fn one_bad_address_refuses_the_whole_push() {
        let err = parse(&push(&[
            upstream(&m('a'), "127.0.0.1:1", "127.0.0.1:2"),
            upstream(&m('b'), "127.0.0.1:3", "not an address"),
        ]))
        .err()
        .unwrap();
        assert!(err.starts_with("upstreams[1].client"), "{err}");
    }
}
