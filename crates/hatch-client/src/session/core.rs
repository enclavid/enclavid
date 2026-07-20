//! Shared traits, helpers, and tuple machinery used by the per-field
//! modules (`status`, `metadata`, `state`, `disclosure`). Each field
//! file impls `ReadField` / `WriteField` for its own markers using
//! the helpers exposed here.

use hatch_protocol::{FieldSelector, Op, ReadRequest, Slot};

use crate::boundary;
use crate::boundary::{AuthN, AuthZ, Covert, Exposed, Replay, Untrusted};
use crate::error::BridgeError;
use crate::reason;

use super::Ctx;
use super::SessionStore;

// ---------- traits ----------

/// Decode a single field from a host-returned slot. The slot's oneof
/// shape (scalar vs list) is determined by the marker's selector;
/// decoding mismatch surfaces as a `BridgeError::Transport`.
///
/// `Output` is the field's typed return wrapped in an `Untrusted<_, S>`
/// whose scope `S` lists exactly the concerns a caller still needs to
/// address for THAT field. AEAD-verified fields (Metadata, State)
/// have AuthN already cleared inside `decode`, so their scope omits
/// it; host-plaintext fields (Status) leave AuthN open. Per-field
/// scopes mean the caller's peel-pattern stays minimal — only the
/// concerns the field actually has, no ceremony for what's already
/// known.
pub trait ReadField: Sized {
    type Output;
    fn selector(&self) -> FieldSelector;
    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, BridgeError>;
}

/// Single field-op for the `/write` request. Implementors carry the
/// value being written; `ctx` provides keys + AAD for any encryption
/// step. Both scalar-field markers (`SetStatus`, `SetMetadata`,
/// `SetState`) and list-append markers (`AppendDisclosure`) implement
/// this trait — they emit the right `Op::Blob` or `Op::ListAppend`
/// shape so the SessionStore client stays uniform across both kinds.
///
/// `build_op` returns `Exposed<Op, ()>`: a fully-vouched outbound
/// wrapper. Inside the body the implementation constructs an
/// `Exposed<Op, S>` where `S` lists the outbound concerns it cares
/// about — typically `(AuthN, AuthZ, Covert)` — and then peels each
/// with `vouch_unchecked::<X>(reason!("…"))` recording why the
/// concern was addressed (AEAD-seal under what key, app-level
/// consent / by-design plaintext, sanitisation step, ...). By the
/// time the wrapper returns, `S == ()` and only `into_inner` lifts
/// the raw `Op` for the wire send inside
/// [`SessionStore::write`](super::SessionStore::write). Reviewers
/// grep for `Exposed::new` to find every TEE → host data release
/// and for `vouch_unchecked::<` to read the per-concern rationale.
///
/// Object-safe by design (`&self` method, no `Sized` bound) so callers
/// pass heterogeneous slices `&[&dyn WriteField]` for atomic writes
/// mixing static markers and dynamic accumulator buffers (e.g.
/// `pending_disclosures` from a policy run).
///
/// `Send + Sync` supertraits keep the trait-object usable across
/// async-await boundaries (axum requires `Send` futures).
pub trait WriteField: Send + Sync {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, BridgeError>;
}

// ---------- slot / op helpers ----------

pub(super) fn unwrap_scalar(slot: Slot) -> Result<Option<Vec<u8>>, BridgeError> {
    match slot {
        Slot::Scalar(s) => Ok(s.value),
        Slot::List(_) => Err(BridgeError::Transport(
            "expected scalar slot, got list".to_string(),
        )),
    }
}

pub(super) fn unwrap_list(slot: Slot) -> Result<Vec<Vec<u8>>, BridgeError> {
    match slot {
        Slot::List(l) => Ok(l.items),
        Slot::Scalar(_) => Err(BridgeError::Transport(
            "expected list slot, got scalar".to_string(),
        )),
    }
}

// ---------- read request ----------

/// Build the vouched read request from a tuple's selectors. The
/// selectors are field-kind enum tags chosen by the caller's marker
/// tuple — not external secret data — so hatch-client (their producer)
/// legitimately vouches their release here, before handing the
/// `Exposed<ReadRequest>` to `read_raw`.
pub(super) fn read_request(selectors: Vec<FieldSelector>) -> Exposed<ReadRequest, ()> {
    boundary::outbound::to_untrusted(ReadRequest { fields: selectors })
        .vouch_unchecked::<AuthN, _>(reason!("selectors are field-kind tags only — no TEE data leaves"))
        .vouch_unchecked::<AuthZ, _>(reason!("a read releases no TEE data; it names fields to fetch"))
        .vouch_unchecked::<Covert, _>(reason!("selector set bounded by field-enum cardinality"))
}

// ---------- ReadTuple ----------

/// Tuple of `ReadField`s. `fetch` returns the typed fields paired
/// with the session's current version. Each field in the result
/// tuple carries its own per-field scope (set by its `ReadField::decode`);
/// the version comes back as `Untrusted<u64, (AuthN, AuthZ, Replay)>`
/// — host-supplied counter with no concern closed at this layer.
/// Caller peels with channel-specific rationale (typical: "counter
/// is not an ownership signal" closes AuthZ; CAS-feed-forward closes
/// Replay; the CAS-mismatch failure path closes AuthN downstream).
pub trait ReadTuple {
    type Output;
    #[allow(async_fn_in_trait)]
    async fn fetch(
        self,
        store: &SessionStore,
        id: Exposed<&str>,
    ) -> Result<(Self::Output, Untrusted<u64, (AuthN, AuthZ, Replay)>), BridgeError>;
}

macro_rules! impl_read_tuple {
    ($($idx:tt: $T:ident),+) => {
        impl<$($T: ReadField),+> ReadTuple for ($($T,)+) {
            type Output = ($(<$T as ReadField>::Output,)+);

            async fn fetch(
                self,
                store: &SessionStore,
                id: Exposed<&str>,
            ) -> Result<(Self::Output, Untrusted<u64, (AuthN, AuthZ, Replay)>), BridgeError> {
                // `as_inner` reads the vouched id for the per-blob AAD (an
                // internal crypto binding, not a host release); `read_raw`
                // does the URL release via `into_inner`.
                let ctx = Ctx { tee_seal_key: store.tee_seal_key(), session_id: *id.as_inner() };
                let selectors = vec![$(self.$idx.selector()),+];
                let (raw, version) = store.read_raw(id, read_request(selectors)).await?;
                let mut iter = raw.into_iter();
                let fields = ($(self.$idx.decode(
                    iter.next().expect("slot count matches request"),
                    &ctx,
                )?,)+);
                Ok((fields, version))
            }
        }
    };
}

impl_read_tuple!(0: F1);
impl_read_tuple!(0: F1, 1: F2);
impl_read_tuple!(0: F1, 1: F2, 2: F3);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8, 8: F9);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8, 8: F9, 9: F10);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8, 8: F9, 9: F10, 10: F11);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8, 8: F9, 9: F10, 10: F11, 11: F12);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8, 8: F9, 9: F10, 10: F11, 11: F12, 12: F13);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8, 8: F9, 9: F10, 10: F11, 11: F12, 12: F13, 13: F14);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8, 8: F9, 9: F10, 10: F11, 11: F12, 12: F13, 13: F14, 14: F15);
impl_read_tuple!(0: F1, 1: F2, 2: F3, 3: F4, 4: F5, 5: F6, 6: F7, 7: F8, 8: F9, 9: F10, 10: F11, 11: F12, 12: F13, 13: F14, 14: F15, 15: F16);
