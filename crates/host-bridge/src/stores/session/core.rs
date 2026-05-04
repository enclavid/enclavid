//! Shared traits, helpers, and tuple machinery used by the per-field
//! modules (`status`, `metadata`, `state`, `disclosure`). Each field
//! file impls `ReadField` / `WriteField` for its own markers using
//! the helpers exposed here.

use enclavid_untrusted::{AuthN, Exposed, Replay, Untrusted};

use crate::error::BridgeError;
use crate::proto::session_store::read_response::Slot;
use crate::proto::session_store::read_response::slot::Kind as SlotKind;
use crate::proto::session_store::write_request::Op;
use crate::proto::session_store::FieldSelector;

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

/// Single field-op for the gRPC `Write` request. Implementors carry
/// the value being written; `ctx` provides keys + AAD for any
/// encryption step. Both scalar-field markers (`SetStatus`,
/// `SetMetadata`, `SetState`) and list-append markers
/// (`AppendDisclosure`) implement this trait — they emit the right
/// `Op::Blob` or `Op::ListAppend` shape so the SessionStore client
/// stays uniform across both kinds of write.
///
/// `build_op` returns `Exposed<Op>`: the act of producing an `Op` IS
/// the moment plaintext (state, metadata, ...) becomes ciphertext
/// destined for the host. The wrapper makes that transition explicit
/// in the type — anything that goes onto the wire must come through
/// here, and the `release()` only happens inside `SessionStore::write`
/// at the wire boundary. Reviewers grep for `Exposed::expose` to find
/// every TEE → host data release.
///
/// Object-safe by design (`&self` method, no `Sized` bound) so callers
/// pass heterogeneous slices `&[&dyn WriteField]` for atomic writes
/// mixing static markers and dynamic accumulator buffers (e.g.
/// `pending_disclosures` from a policy run).
///
/// `Send + Sync` supertraits keep the trait-object usable across
/// async-await boundaries (axum requires `Send` futures).
pub trait WriteField: Send + Sync {
    fn build_op(&self, ctx: &Ctx<'_>) -> Result<Exposed<Op>, BridgeError>;
}

// ---------- slot / op helpers ----------

pub(super) fn unwrap_scalar(slot: Slot) -> Result<Option<Vec<u8>>, BridgeError> {
    match slot.kind {
        Some(SlotKind::Scalar(s)) => Ok(s.value),
        Some(SlotKind::List(_)) => Err(BridgeError::Transport(
            "expected scalar slot, got list".to_string(),
        )),
        None => Err(BridgeError::Transport("missing slot kind".to_string())),
    }
}

pub(super) fn unwrap_list(slot: Slot) -> Result<Vec<Vec<u8>>, BridgeError> {
    match slot.kind {
        Some(SlotKind::List(l)) => Ok(l.items),
        Some(SlotKind::Scalar(_)) => Err(BridgeError::Transport(
            "expected list slot, got scalar".to_string(),
        )),
        None => Err(BridgeError::Transport("missing slot kind".to_string())),
    }
}

// ---------- ReadTuple ----------

/// Tuple of `ReadField`s. `fetch` returns the typed fields paired
/// with the session's current version. Each field in the result
/// tuple carries its own per-field scope (set by its `ReadField::decode`);
/// the version comes back as `Untrusted<u64, (AuthN, Replay)>` since
/// it's a host-controlled counter that may be fabricated or stale.
pub trait ReadTuple {
    type Output;
    #[allow(async_fn_in_trait)]
    async fn fetch(
        self,
        store: &SessionStore,
        id: &str,
    ) -> Result<(Self::Output, Untrusted<u64, (AuthN, Replay)>), BridgeError>;
}

macro_rules! impl_read_tuple {
    ($($idx:tt: $T:ident),+) => {
        impl<$($T: ReadField),+> ReadTuple for ($($T,)+) {
            type Output = ($(<$T as ReadField>::Output,)+);

            async fn fetch(
                self,
                store: &SessionStore,
                id: &str,
            ) -> Result<(Self::Output, Untrusted<u64, (AuthN, Replay)>), BridgeError> {
                let ctx = Ctx { tee_key: store.tee_key(), session_id: id };
                let selectors = vec![$(self.$idx.selector()),+];
                let (raw, version) = store.read_raw(id, selectors).await?;
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
