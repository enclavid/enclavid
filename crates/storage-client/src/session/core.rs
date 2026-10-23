//! Shared traits, helpers, and tuple machinery used by the per-field
//! modules (`metadata`, `state`, `disclosure`). Each field file impls
//! `ReadField` / `WriteField` for its own markers using the helpers
//! exposed here.

use storage_rpc::{Fields, Ops, Slot};

use crate::boundary::Storage;
use crate::error::StoreError;
use enclavid_boundary::{AuthN, AuthZ, Replay, Untrusted};

use super::Ctx;
use super::SessionStore;

// ---------- traits ----------

/// One field of a read: what it asks the store for, and how its slot is
/// decoded. The slot's shape (scalar vs list) is fixed by what `select` asked
/// for; a slot of the other shape is refused as `StoreError::Transport`.
///
/// The slot arrives open on everything [`Storage`] leaves open on one, and
/// `Output` is the field's typed value still open on exactly the concerns a
/// caller has to answer for THAT field. Metadata answers AuthN inside `decode`
/// with its AEAD open, so its scope omits it; the state is opened beside the
/// metadata it is bound to, so it comes back sealed; disclosures, sealed to the
/// consumer rather than to this side, leave every concern open. Per-field
/// scopes mean the caller's peel-pattern stays minimal — only the concerns
/// the field actually has, no ceremony for what's already known.
pub trait ReadField: Sized {
    type Output;
    fn select(&self, fields: &mut Fields<Storage>);
    fn decode(
        self,
        slot: Untrusted<Slot, (AuthN, AuthZ, Replay), Storage>,
        ctx: &Ctx<'_>,
    ) -> Result<Self::Output, StoreError>;
}

/// One op of a write. Implementors carry the value being written; `ctx`
/// provides keys + AAD for any encryption step. Scalar-field markers
/// (`SetMetadata`, `SetState`), media (`SetMedia`), list appends
/// (`AppendDisclosure`) and the reset (`DropApplicantData`) all implement this
/// trait, each adding its own kind of op to the write.
///
/// `add_to` adds the op only answered in full at [`Storage`]: what its kind's
/// declaration line leaves open, the caller answered where it built the value,
/// and the seal under the field's own key is the work that builds the op here.
/// [`Ops`] takes nothing else.
///
/// Object-safe by design (`&self` method, no `Sized` bound) so callers
/// pass heterogeneous slices `&[&dyn WriteField]` for atomic writes
/// mixing static markers and dynamic accumulator buffers (e.g.
/// `pending_disclosures` from a policy run).
///
/// `Send + Sync` supertraits keep the trait-object usable across
/// async-await boundaries (axum requires `Send` futures).
pub trait WriteField: Send + Sync {
    fn add_to(&self, ops: &mut Ops<Storage>, ctx: &Ctx<'_>) -> Result<(), StoreError>;
}

// ---------- slot helpers ----------

/// The value of a scalar slot, still open on all the slot was. Which shape a
/// slot has decides nothing but this refusal, so it is taken apart with
/// `split` and the other shape dropped unread.
pub(super) fn scalar<S>(
    slot: Untrusted<Slot, S, Storage>,
) -> Result<Untrusted<Option<Vec<u8>>, S, Storage>, StoreError> {
    slot.split(|slot| match slot {
        Slot::Scalar(s) => Ok(s.value),
        other => Err(other),
    })
    .map_err(|_| StoreError::Transport("expected scalar slot, got list".to_string()))
}

/// The items of a list slot, still open on all the slot was.
pub(super) fn list<S>(
    slot: Untrusted<Slot, S, Storage>,
) -> Result<Untrusted<Vec<Vec<u8>>, S, Storage>, StoreError> {
    slot.split(|slot| match slot {
        Slot::List(l) => Ok(l.items),
        other => Err(other),
    })
    .map_err(|_| StoreError::Transport("expected list slot, got scalar".to_string()))
}

// ---------- ReadTuple ----------

/// Tuple of `ReadField`s. `fetch` returns the typed fields paired with
/// the session's current version. Each field in the result tuple carries
/// its own per-field scope (set by its `ReadField::decode`); the version
/// comes back open on `Replay` alone — [`Storage`] answers the rest for
/// every version — and the caller answers it with how a stale one plays
/// out where it is fed back.
pub trait ReadTuple {
    type Output;
    #[allow(async_fn_in_trait)]
    async fn fetch(
        self,
        store: &SessionStore,
        id: &str,
    ) -> Result<(Self::Output, Untrusted<u64, (Replay,), Storage>), StoreError>;
}

macro_rules! impl_read_tuple {
    ($($idx:tt: $T:ident),+) => {
        impl<$($T: ReadField),+> ReadTuple for ($($T,)+) {
            type Output = ($(<$T as ReadField>::Output,)+);

            async fn fetch(
                self,
                store: &SessionStore,
                id: &str,
            ) -> Result<(Self::Output, Untrusted<u64, (Replay,), Storage>), StoreError> {
                let ctx = Ctx { tee_seal_key: store.tee_seal_key(), session_id: id };
                let mut fields = Fields::new();
                $(self.$idx.select(&mut fields);)+
                let (raw, version) = store.read_raw(id, fields).await?;
                let mut iter = raw.into_iter();
                let fields = ($(self.$idx.decode(
                    iter.next().expect("read_raw holds the slots to the selectors"),
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
