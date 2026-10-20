//! Shared traits, helpers, and tuple machinery used by the per-field
//! modules (`status`, `metadata`, `state`, `disclosure`). Each field
//! file impls `ReadField` / `WriteField` for its own markers using
//! the helpers exposed here.

use storage_rpc::{FieldSelector, Op, ReadRequest, Slot};

use crate::error::StoreError;
use enclavid_boundary::{AuthN, AuthZ, Exposed, Replay, Untrusted};

use super::Ctx;
use super::SessionStore;

// ---------- traits ----------

/// Decode a single field from a host-returned slot. The slot's oneof
/// shape (scalar vs list) is determined by the marker's selector;
/// decoding mismatch surfaces as a `StoreError::Transport`.
///
/// `Output` is the field's typed return wrapped in an `Untrusted<_, S>`
/// whose scope `S` lists exactly the concerns a caller still needs to
/// address for THAT field. AEAD-verified fields (Metadata, State)
/// have AuthN already cleared inside `decode`, so their scope omits
/// it; disclosures, sealed to the consumer rather than to this side,
/// leave it open. Per-field scopes mean the caller's peel-pattern stays minimal — only the
/// concerns the field actually has, no ceremony for what's already
/// known.
pub trait ReadField: Sized {
    type Output;
    fn selector(&self) -> FieldSelector;
    fn decode(self, slot: Slot, ctx: &Ctx<'_>) -> Result<Self::Output, StoreError>;
}

/// Single field-op for the `/write` request. Implementors carry the
/// value being written; `ctx` provides keys + AAD for any encryption
/// step. Scalar-field markers (`SetMetadata`, `SetState`), media
/// (`SetMedia`), list appends (`AppendDisclosure`) and the reset
/// (`DropApplicantData`) all implement this trait — each emits its own
/// `Op` shape so the SessionStore client stays uniform across them.
///
/// `build_op` returns `Exposed<Op, ()>`: a fully-vouched outbound
/// wrapper. Inside the body the implementation constructs an
/// `Exposed<Op, S>` where `S` lists the outbound concerns it cares
/// about — typically `(AuthN, AuthZ, Covert)` — and then answers each:
/// with work (`vouch_with`, the AEAD seal under the field's key), or with
/// an argued kind (`vouch(reason!(Kind, "…"))`, recording why it holds:
/// app-level consent, by-design plaintext, ...). By the time the wrapper
/// returns, `S == ()` and only `into_inner` lifts the raw `Op` for the
/// wire send inside [`SessionStore::write`](super::SessionStore::write).
/// Reviewers grep for `to_untrusted(` to find every TEE → host data
/// release and for `vouch(` / `vouch_with(` to read how each concern
/// was answered.
///
/// Object-safe by design (`&self` method, no `Sized` bound) so callers
/// pass heterogeneous slices `&[&dyn WriteField]` for atomic writes
/// mixing static markers and dynamic accumulator buffers (e.g.
/// `pending_disclosures` from a policy run).
///
/// `Send + Sync` supertraits keep the trait-object usable across
/// async-await boundaries (axum requires `Send` futures).
pub trait WriteField: Send + Sync {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op, ()>, StoreError>;
}

// ---------- slot / op helpers ----------

pub(super) fn unwrap_scalar(slot: Slot) -> Result<Option<Vec<u8>>, StoreError> {
    match slot {
        Slot::Scalar(s) => Ok(s.value),
        Slot::List(_) => Err(StoreError::Transport(
            "expected scalar slot, got list".to_string(),
        )),
    }
}

pub(super) fn unwrap_list(slot: Slot) -> Result<Vec<Vec<u8>>, StoreError> {
    match slot {
        Slot::List(l) => Ok(l.items),
        Slot::Scalar(_) => Err(StoreError::Transport(
            "expected list slot, got scalar".to_string(),
        )),
    }
}

// ---------- read request ----------

/// The read request for a tuple's selectors. It crosses as a plain value, as
/// the id it reads under does (see [`SessionStore`]): the selectors are
/// field-kind tags the caller's marker tuple picks, bounded by the selector
/// enum. The one that carries more is a media read's, and what it carries is
/// the blob's HKDF name — the name the volume already holds it under.
pub(super) fn read_request(selectors: Vec<FieldSelector>) -> ReadRequest {
    ReadRequest { fields: selectors }
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
        id: &str,
    ) -> Result<(Self::Output, Untrusted<u64, (AuthN, AuthZ, Replay)>), StoreError>;
}

macro_rules! impl_read_tuple {
    ($($idx:tt: $T:ident),+) => {
        impl<$($T: ReadField),+> ReadTuple for ($($T,)+) {
            type Output = ($(<$T as ReadField>::Output,)+);

            async fn fetch(
                self,
                store: &SessionStore,
                id: &str,
            ) -> Result<(Self::Output, Untrusted<u64, (AuthN, AuthZ, Replay)>), StoreError> {
                let ctx = Ctx { tee_seal_key: store.tee_seal_key(), session_id: id };
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
