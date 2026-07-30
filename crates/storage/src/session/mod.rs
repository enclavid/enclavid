//! The per-session store, split into two tiers:
//!
//!   * [`db_blobs`] — one SQLite file per session (`blobs/<sha256(id)>.sqlite`):
//!     the actual session data (state / metadata / version / media / disclosure),
//!     a round committing atomically in one transaction.
//!   * [`db_meta`] — the global cross-session index (`meta.sqlite`), the
//!     "metadata" tier: today the absolute TTL deadline, extensible to any future
//!     globally-queryable per-session metadata.
//!
//! [`SessionStore`] is the facade over both: it owns `session_id` → path mapping
//! (hashed — hides which session a file is under the CVM's dm-crypt disk, and
//! guards path traversal) and the create ordering + sweep that tie the two tiers
//! together. One file per session gives isolation, wholesale delete (`rm` returns
//! space to the OS — no compaction), atomic rounds, and cross-session write
//! parallelism (the hot update path touches neither the index nor any global
//! lock).

mod db_blobs;
mod db_meta;

use std::path::PathBuf;

use hatch_protocol::{DeleteResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use storage_rpc::SessionError;

use db_blobs::DbBlobs;
use db_meta::DbMeta;

/// Crate-internal error so the tier bodies use plain `?`. `rusqlite::Error` and
/// the public `SessionError` are both foreign, so the orphan rule forbids a
/// direct `impl From<rusqlite::Error> for SessionError`; this local type sidesteps
/// that and is converted once at each public boundary. `Internal` carries any
/// non-CAS failure as a message.
pub(crate) enum StoreErr {
    Internal(String),
    /// CAS precondition failed: stale `expected_version`, an update of an absent
    /// session, or a must-not-exist create that found an existing session.
    VersionMismatch,
}

impl From<rusqlite::Error> for StoreErr {
    fn from(e: rusqlite::Error) -> Self {
        StoreErr::Internal(e.to_string())
    }
}
impl From<std::io::Error> for StoreErr {
    fn from(e: std::io::Error) -> Self {
        StoreErr::Internal(e.to_string())
    }
}
impl From<StoreErr> for SessionError {
    fn from(e: StoreErr) -> Self {
        match e {
            StoreErr::VersionMismatch => SessionError::VersionMismatch,
            StoreErr::Internal(msg) => SessionError::Internal(msg),
        }
    }
}

/// The session store facade over the two tiers: [`DbBlobs`] (per-session files)
/// and [`DbMeta`] (the shared deadline index). Trivially `Send + Sync` behind
/// `Arc`.
pub struct SessionStore {
    blobs: DbBlobs,
    meta: DbMeta,
}

impl SessionStore {
    /// Open the store rooted at `dir`, creating `blobs/` (per-session files) and
    /// the deadline index (`meta.sqlite`). Idempotent.
    pub fn open(dir: &str) -> Result<SessionStore, SessionError> {
        (|| -> Result<SessionStore, StoreErr> {
            let root = PathBuf::from(dir);
            let blobs = DbBlobs::open(&root.join("blobs"))?;
            let meta = DbMeta::open(&root.join("meta.sqlite"))?;
            Ok(SessionStore { blobs, meta })
        })()
        .map_err(SessionError::from)
    }

    /// Batched typed read (see [`DbBlobs::read`]).
    pub fn read(&self, id: &str, req: ReadRequest) -> Result<ReadResponse, SessionError> {
        self.blobs.read(id, req).map_err(SessionError::from)
    }

    /// Atomic CAS write. `expected_version == None` dispatches to a create,
    /// `Some(v)` to a CAS update. `deadline` (`Some` only on create) is recorded
    /// in the index FIRST — after the must-not-exist check passes (so a duplicate
    /// create can't reset an existing session's deadline) and as its OWN durable
    /// commit BEFORE the session file — so a committed session always has a
    /// durable deadline row (the reverse is harmless, swept self-healingly).
    /// `req.ops` must be non-empty.
    pub fn write(
        &self,
        id: &str,
        req: WriteRequest,
        deadline: Option<u64>,
    ) -> Result<WriteResponse, SessionError> {
        (|| -> Result<WriteResponse, StoreErr> {
            if req.ops.is_empty() {
                return Err(StoreErr::Internal("write with no ops".to_string()));
            }
            match req.expected_version {
                None => {
                    if self.blobs.committed_exists(id)? {
                        return Err(StoreErr::VersionMismatch);
                    }
                    if let Some(dl) = deadline {
                        self.meta.put_deadline(id, dl)?;
                    }
                    self.blobs.create(id, req.ops)
                }
                Some(expected) => self.blobs.update(id, req.ops, expected),
            }
        })()
        .map_err(SessionError::from)
    }

    /// `/reset`: drop STATE + media, keep the session (see [`DbBlobs::delete`]).
    pub fn delete(&self, id: &str) -> Result<DeleteResponse, SessionError> {
        self.blobs.delete(id).map_err(SessionError::from)
    }

    /// Existence probe (see [`DbBlobs::exists`]).
    pub fn exists(&self, id: &str) -> Result<bool, SessionError> {
        self.blobs.exists(id).map_err(SessionError::from)
    }

    /// Delete every session whose deadline is `<= now`, up to `max` per call:
    /// query the index (indexed range, O(log N + expired), no session-file
    /// opens), `rm` each session file, then drop the index rows. Self-healing —
    /// a crash mid-sweep re-selects leftover rows; a row whose file is already
    /// gone just `rm`s a missing file.
    pub fn sweep_once(&self, now: u64, max: usize) -> Result<usize, SessionError> {
        (|| -> Result<usize, StoreErr> {
            let ids = self.meta.expired(now, max)?;
            for id in &ids {
                self.blobs.remove_files(id);
            }
            self.meta.remove(&ids)?;
            Ok(ids.len())
        })()
        .map_err(SessionError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::SessionStore;
    use hatch_protocol::{
        BlobField, BlobWrite, FieldSelector, ListAppend, ListField, ListSlot, MediaWrite, Op,
        ReadRequest, ScalarSlot, Slot, WriteRequest,
    };
    use storage_rpc::SessionError;

    fn tmp_store() -> (tempfile::TempDir, SessionStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap()).unwrap();
        (dir, store)
    }

    fn set_blob(field: BlobField, value: &[u8]) -> WriteRequest {
        WriteRequest {
            ops: vec![Op::Blob(BlobWrite { field, value: value.to_vec() })],
            expected_version: None,
        }
    }

    #[test]
    fn cas_rejects_stale_and_must_not_exist() {
        let (_d, s) = tmp_store();
        let v1 = s.write("s", set_blob(BlobField::Metadata, b"m1"), Some(100)).unwrap();
        assert_eq!(v1.new_version, 1);
        // second create at None → conflict
        assert!(matches!(
            s.write("s", set_blob(BlobField::Metadata, b"x"), Some(100)),
            Err(SessionError::VersionMismatch)
        ));
        // CAS at 1 → v2
        let mut upd = set_blob(BlobField::State, b"st");
        upd.expected_version = Some(1);
        assert_eq!(s.write("s", upd, None).unwrap().new_version, 2);
        // stale CAS at 1 → conflict, losing value not applied
        let mut stale = set_blob(BlobField::State, b"loser");
        stale.expected_version = Some(1);
        assert!(matches!(s.write("s", stale, None), Err(SessionError::VersionMismatch)));
        let got = s
            .read("s", ReadRequest { fields: vec![FieldSelector::Blob(BlobField::State)] })
            .unwrap();
        assert_eq!(got.version, 2);
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: Some(b"st".to_vec()) }));
    }

    #[test]
    fn update_of_absent_session_is_mismatch() {
        let (_d, s) = tmp_store();
        let mut upd = set_blob(BlobField::State, b"x");
        upd.expected_version = Some(1);
        assert!(matches!(s.write("nope", upd, None), Err(SessionError::VersionMismatch)));
    }

    #[test]
    fn empty_write_rejected_no_phantom_session() {
        let (_d, s) = tmp_store();
        let empty = WriteRequest { ops: vec![], expected_version: None };
        assert!(s.write("s", empty, Some(100)).is_err());
        assert!(!s.exists("s").unwrap(), "no phantom session materialized");
        // An empty UPDATE is rejected too, version untouched.
        s.write("s", set_blob(BlobField::Metadata, b"m"), Some(100)).unwrap();
        let empty_upd = WriteRequest { ops: vec![], expected_version: Some(1) };
        assert!(s.write("s", empty_upd, None).is_err());
        assert_eq!(s.read("s", ReadRequest { fields: vec![] }).unwrap().version, 1);
    }

    #[test]
    fn read_none_vs_empty() {
        let (_d, s) = tmp_store();
        // absent session → version 0, absent slot
        let got = s
            .read("s", ReadRequest { fields: vec![FieldSelector::Blob(BlobField::State)] })
            .unwrap();
        assert_eq!(got.version, 0);
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: None }));
        // present-but-empty must read back as Some(empty), not None
        s.write("s", set_blob(BlobField::Metadata, b""), Some(100)).unwrap();
        let got = s
            .read("s", ReadRequest { fields: vec![FieldSelector::Blob(BlobField::Metadata)] })
            .unwrap();
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: Some(vec![]) }));
    }

    #[test]
    fn read_media_absent_slot() {
        let (_d, s) = tmp_store();
        s.write("s", set_blob(BlobField::Metadata, b"m"), Some(100)).unwrap();
        let got = s
            .read("s", ReadRequest { fields: vec![FieldSelector::Media(vec![7u8; 32])] })
            .unwrap();
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: None }));
    }

    #[test]
    fn disclosure_set_membership_order_agnostic() {
        let (_d, s) = tmp_store();
        s.write("s", set_blob(BlobField::Metadata, b"m"), Some(100)).unwrap();
        for (i, val) in [b"c".as_slice(), b"a", b"b"].iter().enumerate() {
            let req = WriteRequest {
                ops: vec![Op::ListAppend(ListAppend {
                    field: ListField::Disclosure,
                    value: val.to_vec(),
                })],
                expected_version: Some((i + 1) as u64),
            };
            s.write("s", req, None).unwrap();
        }
        let got = s
            .read("s", ReadRequest { fields: vec![FieldSelector::List(ListField::Disclosure)] })
            .unwrap();
        let Slot::List(ListSlot { mut items }) = got.slots.into_iter().next().unwrap() else {
            panic!("expected a list slot");
        };
        items.sort();
        assert_eq!(items, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }

    #[test]
    fn delete_purges_media_keeps_session() {
        let (_d, s) = tmp_store();
        let req = WriteRequest {
            ops: vec![
                Op::Blob(BlobWrite { field: BlobField::State, value: b"st".to_vec() }),
                Op::MediaWrite(MediaWrite { blob_key: vec![1u8; 32], value: b"jpeg".to_vec() }),
            ],
            expected_version: None,
        };
        s.write("s", req, Some(100)).unwrap();
        let del = s.delete("s").unwrap();
        assert_eq!(del.deleted, 1);
        assert!(s.exists("s").unwrap(), "session still exists after reset");
        let got = s
            .read(
                "s",
                ReadRequest {
                    fields: vec![
                        FieldSelector::Blob(BlobField::State),
                        FieldSelector::Media(vec![1u8; 32]),
                    ],
                },
            )
            .unwrap();
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: None }));
        assert_eq!(got.slots[1], Slot::Scalar(ScalarSlot { value: None }));
    }

    #[test]
    fn sweeper_purges_expired_only() {
        let (_d, s) = tmp_store();
        s.write("s_old", set_blob(BlobField::Metadata, b"m"), Some(100)).unwrap();
        s.write("s_new", set_blob(BlobField::Metadata, b"m"), Some(10_000_000)).unwrap();
        let purged = s.sweep_once(1_000, 1024).unwrap();
        assert_eq!(purged, 1);
        assert!(!s.exists("s_old").unwrap());
        assert!(s.exists("s_new").unwrap());
    }

    #[test]
    fn sweep_removes_whole_session() {
        let (_d, s) = tmp_store();
        s.write("s", set_blob(BlobField::Metadata, b"m"), Some(100)).unwrap();
        let req = WriteRequest {
            ops: vec![Op::ListAppend(ListAppend {
                field: ListField::Disclosure,
                value: b"d1".to_vec(),
            })],
            expected_version: Some(1),
        };
        s.write("s", req, None).unwrap();
        assert_eq!(s.sweep_once(1_000, 1024).unwrap(), 1);
        assert!(!s.exists("s").unwrap());
        let got = s
            .read("s", ReadRequest { fields: vec![FieldSelector::List(ListField::Disclosure)] })
            .unwrap();
        assert_eq!(got.slots[0], Slot::List(ListSlot { items: vec![] }));
        // Swept id is gone from the index too: re-sweep finds nothing.
        assert_eq!(s.sweep_once(1_000_000, 1024).unwrap(), 0);
    }

    #[test]
    fn sweep_respects_max() {
        let (_d, s) = tmp_store();
        s.write("a", set_blob(BlobField::Metadata, b"m"), Some(10)).unwrap();
        s.write("b", set_blob(BlobField::Metadata, b"m"), Some(20)).unwrap();
        s.write("c", set_blob(BlobField::Metadata, b"m"), Some(5_000)).unwrap(); // future
        assert_eq!(s.sweep_once(1_000, 1).unwrap(), 1);
        assert_eq!(s.sweep_once(1_000, 1024).unwrap(), 1);
        assert!(s.exists("c").unwrap());
    }
}
