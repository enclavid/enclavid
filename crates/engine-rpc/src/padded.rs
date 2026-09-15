//! Constant-size framing for the values whose LENGTH is a covert channel.
//!
//! A fleet leg is necessarily two hops: vsock addresses guest↔host, so a host
//! process splices every byte api and a worker exchange. It reads none of them —
//! the leg is mutual RA-TLS — but it counts them exactly. A value whose encoded
//! length varies with policy-chosen content therefore relays that content to the
//! host at whatever rate the round count allows.
//!
//! The sealed store already closes this for `SessionState`: `SetState`'s `Covert`
//! vouch pads the encoded state to a constant before sealing, so every round
//! writes the same number of ciphertext bytes whatever the policy put in it.
//! Moving execution into its own CVM put the same two policy-chosen lengths — the
//! opaque `state` blob and the rendered `current_prompt` — onto a wire the same
//! observer watches, where nothing padded them. The round's `RunStatus` carries a
//! second copy of the prompt back, and its VARIANT is legible by size too: a
//! terminal `Completed(Decision)` is a few bytes where `AwaitingInput` is a
//! screen.
//!
//! ## Why a type, and not only a call-site vouch
//!
//! [`Padded`] is not a second mechanism beside `Exposed`/`Untrusted`. It is the
//! CODOMAIN of the `Covert` peel, which `Exposed::vouch`'s own contract asks for:
//! *both sides close their concern by performing the transformation, not just
//! attesting to it*. On the storage leg that transformation returns a bare
//! `Vec<u8>` and needs no name, because the value goes straight to a writer in the
//! same crate. Here it has to survive a serde round-trip and be reconstructed by
//! the peer, so the codomain gets a name and a private field.
//!
//! The private field is the part a vouch cannot buy: `vouch::<Covert>(|s|
//! Ok(encode(s)))` type-checks while padding nothing. [`Padded::seal`] is the only
//! constructor, so no path on either side puts an unpadded value on this wire —
//! and that matters most in the direction no marker reaches at all, since api is
//! the RECEIVER of `session_change` and `RunReply` and `Covert` is outbound-only
//! by construction.
//!
//! ## The peer is bound too, which is not the same as trusting it
//!
//! The worker constructs these frames on the return path. That does not
//! contradict "a discharge written by the party the marker distrusts is worth
//! nothing" — which is about `Asserted`, a claim about the peer's WORD. `Covert`
//! is a property of the encoding at a hop, and the transformation must be
//! performed by whoever holds the bytes there. That is the worker's supervisor:
//! our own measured code, which api already relies on for exactly this class of
//! obligation — `POLICY_MAX_STATE_BYTES` is enforced worker-side and api takes it.
//! A compromised supervisor can skip the pad, but a compromised supervisor holds
//! the plaintext and a socket, so the pad was never a defence against it. What it
//! denies is the POLICY using the worker as an unwitting relay to the host.
//!
//! Decoding enforces the frame as well as encoding does, so a peer that sends a
//! short frame is refused by the codec rather than merely noticed.
//!
//! ## The failure path beside it, and how it is closed instead
//!
//! Framing is not the only way to make an encoding independent of its content,
//! and on the failure path it is the wrong one. [`ExecError`] used to be
//! `Run(String)` built as `format!("{e:#}")` over the whole trap chain — and that
//! chain interpolates wasm-supplied text, so a policy set the reply's byte count
//! directly. A round that trapped carried on this same hop exactly the channel the
//! frames close on the round that succeeds, and a policy can trap deliberately and
//! retry.
//!
//! That is now closed by CARDINALITY rather than by a frame, and it needed no
//! frame in the end. [`ExecError`](crate::ExecError) is a fixed enum in which NO
//! variant carries a free value: two values, so a policy choosing which failure to
//! provoke moves the reply between two fixed sizes — about half a bit on top of the
//! one it already has by choosing whether to fail at all — and there is no length
//! anywhere for it to set.
//!
//! One variant nearly did carry one — the key of an undeclared embedded ref, which
//! api wanted for a 422. A cap on it would NOT have been enough (1..=128 bytes is
//! seven bits a round on this same hop) and a frame would have worked; the value
//! was dropped instead, because wasm picks that key and it could be a function of
//! the applicant's data. See the variant for why a field safe from one reader is
//! worse than an absent one.
//!
//! `media_load`'s reply is likewise unframed, and the policy chooses which blob
//! it asks for — though there the length is an applicant capture's, already
//! stored and already observable at rest.
//!
//! And the shape of the conversation. On an L1 miss the host still sees a second
//! request plus a multi-megabyte bundle transfer, so "this composition was cold"
//! stays legible, and `composition_key` is a stable per-consumer pseudonym. That
//! is a separate channel; padding values does not touch it.
//!
//! ## TIMING, which dwarfs every byte counted above
//!
//! The residuals named so far are half a bit here and seven bits there, and it
//! would be easy to read this module as though those were the scale of what is
//! left. They are not. The host splices this hop, so it TIMESTAMPS both ends of
//! every round, and how long a round takes is the policy's to choose: it holds a
//! ten-billion-instruction fuel budget and a 120-second deadline and may spend any
//! part of either. That is a clock the policy writes to directly, at whatever
//! resolution the host's own clock reads, and it carries orders of magnitude more
//! than every length this module frames.
//!
//! It is not closed here, and it is not closable at this layer. Making it go away
//! means making every round take the same wall-clock time, which means making every
//! round take the deadline — the product does not survive that. Nothing in this
//! tree bounds it today.
//!
//! So the reason to close the LENGTH channels is not that they are the biggest.
//! It is that they close STRUCTURALLY and permanently, at zero runtime cost: a type
//! with a private field makes an unpadded value unexpressible, and it stays that way
//! without anyone maintaining it. Timing cannot be bought on those terms at any
//! price. Both facts belong in the same place, because a reader who finds only the
//! first will conclude this hop is shut.
//!
//! ## Who the observer is, and why this exists even so
//!
//! Every channel above is POLICY → HOST, and every one of them needs the policy to
//! encode. The policy's author is the consumer, who already receives — legitimately,
//! through consent — what the applicant agreed to share, so the recorded position is
//! that policy/host collusion has no motive and is out of scope.
//!
//! This module is not a bet against that position. It is what lets the platform's
//! claim be "provably cannot learn" rather than "no consumer would want to", which
//! is the same move as a guest with no NIC instead of a firewall rule: the property
//! holds without anyone having to be trusted for it to.

use std::marker::PhantomData;

use serde::de::{self, Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

use hatch_client::SessionState;

use crate::execute::{CallbackError, ExecError, RunStatus};

/// A value that did not fit the constant frame its type must occupy, or a frame
/// that did not decode.
///
/// The message is structural on purpose. On the seal side it may name sizes —
/// they are this side's own. On the open side it names none: the length is the
/// very thing the frame exists to hide, and this error reaches a log.
#[derive(Debug)]
pub struct FrameError(String);

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "frame error: {}", self.0)
    }
}
impl std::error::Error for FrameError {}

/// The frame's own message does NOT travel: it names a length, and a length is the
/// one thing the frame exists to keep off this hop. It stays in the guest's log,
/// where [`FrameError`]'s own doc already puts it.
///
/// `Unknown` is the conservative default, because this conversion cannot see which
/// side built the frame. A site where the POLICY sized the value — a resolved
/// prompt that will not fit — says so at the site instead of leaning on this.
impl From<FrameError> for ExecError {
    fn from(_: FrameError) -> Self {
        ExecError::Unknown
    }
}
/// The message is dropped here too, and here it was the sharpest case: a frame
/// error names a LENGTH, and this conversion used to hand that length straight to
/// the party whose policy chose it.
impl From<FrameError> for CallbackError {
    fn from(_: FrameError) -> Self {
        CallbackError
    }
}

/// A type whose encoding on a host-spliced hop must be a constant number of
/// bytes, and the constant it must be.
///
/// Implementing this is the decision that a value's LENGTH is policy-controlled
/// and therefore carries bandwidth. It is not a default: most wire values are
/// fixed-shape or consumer-chosen, and framing those would cost the hot path
/// without closing anything.
pub trait Framed: Serialize + serde::de::DeserializeOwned {
    /// Encoded size on the wire. An encoding OVER this traps the send rather than
    /// silently shrinking the frame, which would reopen the channel.
    const FRAME: usize;
}

/// `T`, CBOR-encoded and zero-padded to `T::FRAME` — the shape a value takes once
/// its `Covert` concern has been closed by transformation.
///
/// The field is private and [`seal`](Self::seal) is the only way to fill it. What
/// crosses the wire is one CBOR byte string of exactly `T::FRAME` bytes, on every
/// call, whatever `T` holds.
pub struct Padded<T> {
    frame: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Clone for Padded<T> {
    /// Not derived: a derived `Clone` would demand `T: Clone`, and nothing about
    /// copying a frame depends on the framed type being cloneable.
    fn clone(&self) -> Self {
        Self {
            frame: self.frame.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T: Framed> Padded<T> {
    /// Encode and pad to the frame. Fails if the encoding is already over it —
    /// the caller traps rather than sending a short frame.
    ///
    /// This is written to be the `vouch::<Covert>` closure at the call site that
    /// releases the value, so the discharge of the concern IS this call and not a
    /// sentence beside it.
    pub fn seal(value: &T) -> Result<Self, FrameError> {
        let mut frame = Vec::with_capacity(T::FRAME);
        ciborium::into_writer(value, &mut frame)
            .map_err(|e| FrameError(format!("encode for the constant frame failed: {e}")))?;
        if frame.len() > T::FRAME {
            return Err(FrameError(format!(
                "encoded value is {} bytes, over the {}-byte frame",
                frame.len(),
                T::FRAME,
            )));
        }
        frame.resize(T::FRAME, 0);
        Ok(Self {
            frame,
            _marker: PhantomData,
        })
    }

    /// Decode the framed value. `ciborium::from_reader` reads exactly one value
    /// and ignores what follows it, so the padding needs no stripping — it is
    /// write-only, transparent on read.
    pub fn open(&self) -> Result<T, FrameError> {
        ciborium::from_reader(self.frame.as_slice())
            .map_err(|_| FrameError("a framed value did not decode".into()))
    }
}

impl<T> Serialize for Padded<T> {
    /// One CBOR byte string, not a sequence of integers — `serde_bytes` for the
    /// same reason `CompiledBundle::cwasm` uses it, and it matters more here
    /// because the frame is over a megabyte on every single round.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(&self.frame, serializer)
    }
}

impl<'de, T: Framed> Deserialize<'de> for Padded<T> {
    /// The frame is checked HERE as well as at `seal`. Enforcing it only on the
    /// way out would leave a peer free to send whatever length it liked, which is
    /// precisely the channel — so the codec refuses a short frame instead of
    /// handing on a value that merely looks framed.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let frame: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if frame.len() != T::FRAME {
            return Err(de::Error::invalid_length(
                frame.len(),
                &"exactly the constant frame this value is padded to",
            ));
        }
        Ok(Self {
            frame,
            _marker: PhantomData,
        })
    }
}

impl Framed for SessionState {
    /// The same frame the seal boundary pads to, because it is the same two
    /// policy-chosen lengths — the opaque `state` blob and `current_prompt`. One
    /// constant for both places the value is observable keeps them from drifting
    /// apart, which is how this hop came to be unpadded in the first place.
    const FRAME: usize = hatch_client::SEALED_STATE_PLAINTEXT_BYTES;
}

impl Framed for RunStatus {
    /// The SAME constant as `SessionState`, not the headroom above the state cap.
    ///
    /// The tighter frame is the tempting one — `SEALED_STATE_PLAINTEXT_BYTES`'s own
    /// doc calls the 256 KiB above `POLICY_MAX_STATE_BYTES` the prompt's headroom
    /// — and it is wrong, because that headroom is what remains when the state is
    /// AT its cap. A prompt is not bounded on its own: `value` is capped per field
    /// and fields are counted, but the `Localized` labels, reason and requester are
    /// copied verbatim out of the embedded registry, which caps how MANY entries a
    /// component declares and not how long each is. So a round with a small state
    /// and a large prompt seals fine today, and a 256 KiB reply frame would trap
    /// it — rejecting rounds the seal path accepts.
    ///
    /// One constant for both keeps the invariant checkable instead of audited: a
    /// status that carries a prompt which fits the state frame fits this one.
    const FRAME: usize = <SessionState as Framed>::FRAME;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_client::{Decision, Localized, Prompt, Translation};

    #[test]
    fn round_trips_through_the_frame() {
        let state = SessionState {
            state: vec![7u8; 4096],
            current_prompt: None,
        };
        let padded = Padded::seal(&state).expect("fits the frame");
        assert_eq!(padded.open().expect("decodes"), state);
    }

    /// The property the whole type exists for: what crosses is the same length
    /// whatever the policy put in the value.
    #[test]
    fn encoded_length_does_not_vary_with_content() {
        let small = Padded::seal(&SessionState {
            state: Vec::new(),
            current_prompt: None,
        })
        .expect("fits");
        let large = Padded::seal(&SessionState {
            state: vec![0xAB; 512 * 1024],
            current_prompt: None,
        })
        .expect("fits");

        let mut small_wire = Vec::new();
        let mut large_wire = Vec::new();
        ciborium::into_writer(&small, &mut small_wire).expect("encodes");
        ciborium::into_writer(&large, &mut large_wire).expect("encodes");
        assert_eq!(small_wire.len(), large_wire.len());
    }

    /// Both `RunStatus` variants too — otherwise "the session just ended" is
    /// readable off a short reply.
    #[test]
    fn run_status_variants_are_indistinguishable_by_length() {
        let awaiting = Padded::seal(&RunStatus::AwaitingInput(Prompt::ConsentDisclosure(
            Default::default(),
        )))
        .expect("fits");
        let completed = Padded::seal(&RunStatus::Completed(Decision::Approved)).expect("fits");

        let mut awaiting_wire = Vec::new();
        let mut completed_wire = Vec::new();
        ciborium::into_writer(&awaiting, &mut awaiting_wire).expect("encodes");
        ciborium::into_writer(&completed, &mut completed_wire).expect("encodes");
        assert_eq!(awaiting_wire.len(), completed_wire.len());
    }

    /// The invariant the two frames exist to keep: a prompt big enough to need
    /// most of the state frame still fits the reply that carries the same prompt.
    /// Deriving the status frame as "the headroom above the state cap" broke this
    /// — a small state with a large prompt seals but would not send.
    #[test]
    fn a_prompt_that_seals_into_the_state_frame_also_sends_in_the_reply() {
        let big = "x".repeat(SessionState::FRAME / 2);
        let prompt = Prompt::ConsentDisclosure(hatch_client::PromptDisclosure {
            reason: Localized {
                translations: vec![Translation {
                    language: "en".into(),
                    text: big,
                }],
            },
            ..Default::default()
        });
        Padded::seal(&SessionState {
            state: Vec::new(),
            current_prompt: Some(prompt.clone()),
        })
        .expect("a small state with a large prompt seals, as it does at rest");
        Padded::seal(&RunStatus::AwaitingInput(prompt))
            .expect("and the reply carrying that same prompt must send");
    }

    /// A state at the engine's own cap must fit the frame, or the two limits
    /// disagree and a policy obeying the one it is told about trips the other.
    /// They did disagree: without `serde_bytes` on `SessionState::state`, binary
    /// state encoded at ~1.9 bytes per byte and the real ceiling was ~640 KiB.
    #[test]
    fn a_state_at_the_engine_cap_fits_the_frame() {
        let at_cap = SessionState {
            // Near-uniform bytes: the array encoding cost two bytes for each of
            // these, which is what put a legal state over the frame.
            state: (0..engine_types::limits::POLICY_MAX_STATE_BYTES)
                .map(|i| (i % 256) as u8)
                .collect(),
            current_prompt: None,
        };
        Padded::seal(&at_cap).expect("a state at POLICY_MAX_STATE_BYTES must fit its frame");
    }

    #[test]
    fn an_encoding_over_the_frame_traps_the_send() {
        let over = SessionState {
            state: vec![0u8; SessionState::FRAME + 1],
            current_prompt: None,
        };
        assert!(Padded::seal(&over).is_err());
    }

    /// A peer that sends a short frame is refused by the codec. Without this the
    /// invariant would hold only on the side that already wanted it.
    #[test]
    fn a_short_frame_is_refused_on_decode() {
        let mut wire = Vec::new();
        ciborium::into_writer(&serde_bytes::ByteBuf::from(vec![0u8; 16]), &mut wire)
            .expect("encodes");
        let decoded: Result<Padded<SessionState>, _> = ciborium::from_reader(wire.as_slice());
        assert!(decoded.is_err());
    }
}
