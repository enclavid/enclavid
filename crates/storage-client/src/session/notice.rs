//! A session's notice: one sealed value the store keeps beside the session's
//! record, due at a time, which api takes once it is due and settles once it has
//! acted on it. One notice a session — its name is derived from the session id —
//! so adding it again puts it in place of the one before.

use std::time::Duration;

use storage_rpc::{NextDue, NoticeDue, NoticeName, NoticeOp, Ops, Settle, TakeRequest};

use enclavid_boundary::{AuthN, AuthZ, Exposed, ExposedBuilder, Replay, Untrusted, reason};
use enclavid_crypto::{aead, derive_key};

use crate::boundary::Storage;
use crate::error::StoreError;
use crate::link::storage;

use super::Ctx;
use super::SessionStore;
use super::core::WriteField;

/// HKDF info label for the subkey a notice's name is derived under.
const NOTICE_INFO: &[u8] = b"enclavid.session-notice.v1";
/// What a notice's seal is labelled with, before the name it is kept under.
const NOTICE_AAD: &[u8] = b"enclavid.notice.v1";

/// The name the notice of `session_id` is kept under: a keyed digest of the id,
/// which tells whoever reads it nothing of the id.
fn name(tee_seal_key: &[u8], session_id: &str) -> Result<NoticeName, StoreError> {
    let master = <&[u8; 32]>::try_from(tee_seal_key)
        .map_err(|_| StoreError::Crypto("a seal key of another length".into()))?;
    Ok(NoticeName(derive_key(
        &derive_key(master, NOTICE_INFO),
        session_id.as_bytes(),
    )))
}

/// The AAD a notice is sealed under: the label, then the name it is kept under,
/// so a value moved under another name does not open.
fn aad(name: &NoticeName) -> Vec<u8> {
    let mut aad = Vec::with_capacity(NOTICE_AAD.len() + name.0.len());
    aad.extend_from_slice(NOTICE_AAD);
    aad.extend_from_slice(&name.0);
    aad
}

/// Write marker: the notice of the session written, due at `due`, carrying
/// `value`. `value` is being built into a [`NoticeOp`] with `AuthN` alone open:
/// [`Storage`] answers `AuthZ` for every notice op, the caller `Covert` for its
/// own value, and the seal under `tee_seal_key` here `AuthN`.
pub struct AddNotice {
    pub due: Exposed<NoticeDue, (), Storage>,
    pub value: ExposedBuilder<Vec<u8>, NoticeOp, (AuthN,), Storage>,
}

impl WriteField for AddNotice {
    fn add_to(&self, ops: &mut Ops<Storage>, ctx: &Ctx<'_>) -> Result<(), StoreError> {
        // The keyed digest is the work that lets the name leave.
        let notice = Storage::expose_builder::<NoticeName, _>(ctx.session_id)
            .vouch_with(AuthN::Verified, |id| name(ctx.tee_seal_key, id))?
            .build();
        let aad = aad(notice.as_inner());
        // The seal this side owns the key for answers AuthN, and builds the op.
        let op = self
            .value
            .clone()
            .vouch_with(AuthN::Verified, |value| -> Result<_, StoreError> {
                Ok(NoticeOp(aead::seal(&value, ctx.tee_seal_key, &aad)?))
            })?
            .build();
        ops.notice(notice, self.due.clone(), op);
        Ok(())
    }
}

/// The name a notice taken was kept under: what settles it.
pub struct NoticeHandle(NoticeName);

/// A notice taken, its value opened.
pub struct TakenNotice {
    pub handle: NoticeHandle,
    pub value: Vec<u8>,
}

/// What one take hands back.
pub struct Take {
    /// The notices that were due, opened.
    pub notices: Vec<Untrusted<TakenNotice, (AuthZ, Replay), Storage>>,
    /// When the store says the next is due, the ones just taken among them.
    pub next_due: Untrusted<NextDue, (AuthN, Replay), Storage>,
}

impl SessionStore {
    /// Take up to `max` of the notices that are due, each held for `hold`: no
    /// other take hands it out meanwhile, and it is due again once `hold` passes
    /// unless it is settled first.
    ///
    /// Each comes back opened, and open on what its caller answers: whether it
    /// may act on it (`AuthZ`), and what an older one put back does (`Replay`).
    /// One that does not open — not sealed here, or moved under another name —
    /// is dropped as it is found.
    pub async fn take_notices(&self, max: u32, hold: Duration) -> Result<Take, StoreError> {
        let ask = Storage::expose(TakeRequest {
            max,
            hold_secs: u32::try_from(hold.as_secs()).unwrap_or(u32::MAX),
        });
        let (due, next_due) = storage(self.link.as_ref())?.take_notices(ask).await?;
        let mut taken = Vec::with_capacity(due.len());
        for notice in due {
            let opened = notice.trust_with(AuthN::Verified, |n| {
                match aead::open(&n.value, self.tee_seal_key(), &aad(&n.name)) {
                    Ok(value) => Ok(TakenNotice {
                        handle: NoticeHandle(n.name),
                        value,
                    }),
                    Err(_) => Err(n.name),
                }
            });
            match opened {
                Ok(opened) => taken.push(opened),
                Err(name) => self.settle(name, Settle::Done).await?,
            }
        }
        Ok(Take {
            notices: taken,
            next_due,
        })
    }

    /// Once a write through this store, or a clone of it, has added a notice:
    /// at once where one has since this last returned.
    pub async fn notice_written(&self) {
        self.noticed.notified().await
    }

    /// Drop the notice `handle` names, or make it due again, as `settle` says.
    pub async fn settle_notice(
        &self,
        handle: &NoticeHandle,
        settle: Settle,
    ) -> Result<(), StoreError> {
        self.settle(handle.0, settle).await
    }

    async fn settle(&self, name: NoticeName, settle: Settle) -> Result<(), StoreError> {
        let name = Storage::expose(name).vouch(reason!(
            AuthN::Indifferent,
            "a name the store handed back with the notice it keeps under it"
        ));
        storage(self.link.as_ref())?
            .settle_notice(name, Storage::expose(settle))
            .await?
            .into_inner();
        Ok(())
    }
}
