//! What reaches the consumer is what the applicant saw and accepted, and
//! nothing else — "show == seal". One rule in two halves, kept together because
//! neither means anything without the other:
//!   * [`authorize`] — `/input` takes an accept only for the screen whose digest
//!     the applicant's browser echoed;
//!   * [`for_round`] — the round then seals exactly that screen's fields.

use axum::http::StatusCode;

use session_types::{Disclosure as PromptDisclosure, DisplayField, Event, Prompt};

use crate::dto;

/// THE SEAL'S AUTHORIZATION. Not a convenience, not a stale-tab guard — the one
/// thing that ties an applicant to the bytes that reach a consumer. Delete it and
/// api age-seals fields chosen by the process that runs adversary-supplied code,
/// with no applicant involved anywhere in the chain.
///
/// Why it carries that weight: a seal needs `Event::ConsentDisclosure(true)`,
/// that event is constructed at exactly one place in the workspace — `/input`,
/// right after this passes. [`for_round`] then derives the fields from this same
/// `current_prompt`, which the execution-worker AUTHORED on the previous round;
/// on its own that proves nothing. What makes it evidence is that the
/// applicant's browser echoed the digest of the screen it rendered, and the only
/// mint site for that digest is `views::consent_view` over the same value. Equal
/// digests ⇒ shown and sealed are the same bytes, by the applicant's own
/// attestation rather than by trusting the worker.
///
/// It also does the job it was first written for: if `current_prompt` advanced (a
/// stale second tab, a concurrent round) the echo no longer matches and we refuse
/// (409). Enforced on ACCEPT only — a decline seals nothing, so a stale decline is
/// harmless.
pub(super) fn authorize(
    prompt: &PromptDisclosure,
    accepted: bool,
    submitted_digest: Option<&str>,
) -> Result<(), StatusCode> {
    if !accepted {
        return Ok(());
    }
    let expected = dto::consent_disclosure_digest(prompt);
    if submitted_digest != Some(expected.as_str()) {
        return Err(StatusCode::CONFLICT);
    }
    Ok(())
}

/// What this round is allowed to disclose to the consumer, if anything.
///
/// The whole consent decision, in one expression: a round seals exactly when the
/// applicant accepted, the screen they were answering was a consent screen, and
/// the fields sealed are the ones that screen carried.
///
/// It runs on THIS side and only here. The execution-worker sees the same event
/// and the same prompt, but it is the process that executes adversary-supplied
/// code, so a disclosure computed there would be worth exactly as much as that
/// process is — and the callback it drives no longer carries one to be tempted
/// by. Both inputs are ours and both are already bound to the applicant:
/// `/input` built the event from their request, and refused the accept unless
/// the digest they echoed matched this same `current_prompt` ([`authorize`]).
pub(super) fn for_round(
    event: &Event,
    current_prompt: &Option<Prompt>,
) -> Option<Vec<DisplayField>> {
    match (event, current_prompt) {
        (Event::ConsentDisclosure(true), Some(Prompt::ConsentDisclosure(d))) => {
            Some(d.fields.clone())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::applicant::views::{RequestView, consent_view};
    use crate::locale::Locale;
    use session_types::MediaSpec;

    /// The digest exactly as the applicant's browser receives it — read off the
    /// rendered screen, not recomputed. Taking it from anywhere else would make
    /// these tests compare a function with itself.
    fn digest_the_browser_sees(prompt: &PromptDisclosure) -> String {
        match consent_view(prompt, &Locale::default()) {
            RequestView::Consent {
                disclosure_digest, ..
            } => disclosure_digest,
            _ => panic!("a consent prompt must render a consent view"),
        }
    }

    fn screen(value: &str) -> PromptDisclosure {
        PromptDisclosure {
            fields: vec![DisplayField {
                key: "dob".into(),
                label: Default::default(),
                value: value.into(),
            }],
            ..Default::default()
        }
    }

    /// The whole chain, in one test: the digest the APPLICANT'S SCREEN carried
    /// authorizes the accept, and the accept then seals exactly that screen's
    /// fields. Break either half — stop checking the echo, or stop deriving from
    /// `current_prompt` — and this fails.
    #[test]
    fn the_screen_the_applicant_saw_is_what_authorizes_and_what_seals() {
        let prompt = screen("1990-01-01");
        // Minted the way the browser gets it: off the rendered view, not off the
        // value the check will later recompute over.
        let rendered = digest_the_browser_sees(&prompt);

        authorize(&prompt, true, Some(&rendered))
            .expect("the digest the screen carried must authorize its own accept");

        let sealed = for_round(
            &Event::ConsentDisclosure(true),
            &Some(Prompt::ConsentDisclosure(prompt.clone())),
        )
        .expect("an authorized accept seals");
        assert_eq!(sealed, prompt.fields, "sealed fields must be the screen's");
    }

    /// One character of one value, and the accept is refused — which is what
    /// makes the digest a binding rather than a formality.
    #[test]
    fn a_screen_that_changed_under_the_applicant_is_refused() {
        let shown = screen("1990-01-01");
        let swapped = screen("1990-01-02");
        let rendered = digest_the_browser_sees(&shown);

        assert_eq!(
            authorize(&swapped, true, Some(&rendered)),
            Err(StatusCode::CONFLICT),
        );
    }

    /// No echo at all fails closed, rather than being read as "nothing to check".
    #[test]
    fn an_accept_with_no_digest_is_refused() {
        assert_eq!(
            authorize(&screen("1990-01-01"), true, None),
            Err(StatusCode::CONFLICT),
        );
    }

    /// A decline is a first-class answer: it needs no digest and seals nothing.
    #[test]
    fn a_decline_needs_no_digest_and_seals_nothing() {
        let prompt = screen("1990-01-01");
        authorize(&prompt, false, None).expect("a decline is always allowed");
        assert!(
            for_round(
                &Event::ConsentDisclosure(false),
                &Some(Prompt::ConsentDisclosure(prompt)),
            )
            .is_none()
        );
    }

    /// The accept has to be answering a consent screen. Every other round —
    /// a capture, the genesis round, a session that has rendered nothing —
    /// seals nothing, whatever else happens during it.
    #[test]
    fn no_consent_screen_means_no_seal() {
        for prompt in [None, Some(Prompt::Media(MediaSpec::default()))] {
            assert!(for_round(&Event::ConsentDisclosure(true), &prompt).is_none());
        }
        let consent = Some(Prompt::ConsentDisclosure(screen("1990-01-01")));
        assert!(for_round(&Event::Start, &consent).is_none());
    }
}
