//! The per-session store, split into two tiers:
//!
//!   * [`db_blobs`] — one SQLite file per session (`blobs/<sha256(name)>.sqlite`):
//!     the actual session data (state / metadata / version / media / disclosure),
//!     a round committing atomically in one transaction.
//!   * [`db_meta`] — the global cross-session index (`meta.sqlite`), the
//!     "metadata" tier: today the absolute TTL deadline, extensible to any future
//!     globally-queryable per-session metadata.
//!
//! [`SessionStore`] is the facade over both: it owns the name → path mapping
//! (hashed, which guards path traversal; it hides nothing, since the index keeps
//! each name as it is) and the create ordering + sweep that tie the
//! two tiers together. One file per session gives isolation, wholesale delete (`rm` returns
//! space to the OS — no compaction), atomic rounds, and cross-session write
//! parallelism (the hot update path touches neither the index nor any global
//! lock).
//!
//! **A [`Name`], not a session id.** The facade takes a name only the
//! crate-private `scope` module can make: a digest of the calling peer's
//! measurement and the record name it asked for, which api in turn derived from
//! a session id under a key only api holds. So two callers stay out of each
//! other's records, and nothing this store keeps on the volume is a name a caller
//! sent, let alone a session id. Under the facade the tiers are a KV over opaque
//! strings, the names the facade gives them.

mod db_blobs;
mod db_meta;

use std::path::PathBuf;
use std::time::Duration;

use storage_rpc::{ReadRequest, ReadResponse, SessionError, WriteRequest, WriteResponse};

use crate::scope::Name;
use db_blobs::DbBlobs;
use db_meta::DbMeta;

/// How long a statement waits on a file another operation holds locked before
/// it fails, unless the host says otherwise (the storage role's `db-busy-secs`
/// setting). Contention is per session — two operations on one session's file,
/// or the create and the sweep on the index — and a commit holds the lock for
/// the length of its fsync, so this is a matter of the disk under the volume.
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// the deadline index (`meta.sqlite`). Idempotent. `busy` is how long a
    /// statement waits on a file another operation holds locked
    /// ([`DEFAULT_BUSY_TIMEOUT`]).
    pub fn open(dir: &str, busy: Duration) -> Result<SessionStore, SessionError> {
        (|| -> Result<SessionStore, StoreErr> {
            let root = PathBuf::from(dir);
            let blobs = DbBlobs::open(&root.join("blobs"), busy)?;
            let meta = DbMeta::open(&root.join("meta.sqlite"), busy)?;
            Ok(SessionStore { blobs, meta })
        })()
        .map_err(SessionError::from)
    }

    /// Batched typed read (see [`DbBlobs::read`]).
    pub(crate) fn read(&self, name: &Name, req: ReadRequest) -> Result<ReadResponse, SessionError> {
        self.blobs
            .read(name.as_str(), req)
            .map_err(SessionError::from)
    }

    /// Atomic CAS write. `expected_version == None` dispatches to a create,
    /// `Some(v)` to a CAS update. A create's deadline is recorded in the index
    /// FIRST — after the must-not-exist check passes (so a duplicate create can't
    /// reset an existing session's deadline) and as its OWN durable commit BEFORE
    /// the session file — so a committed session always has a durable deadline
    /// row (the reverse is harmless, swept self-healingly). An update's deadline
    /// is ignored: a record's deadline is set once. `req.ops` must be non-empty.
    pub(crate) fn write(
        &self,
        name: &Name,
        req: WriteRequest,
    ) -> Result<WriteResponse, SessionError> {
        let name = name.as_str();
        (|| -> Result<WriteResponse, StoreErr> {
            if req.ops.is_empty() {
                return Err(StoreErr::Internal("write with no ops".to_string()));
            }
            match req.expected_version {
                None => {
                    if self.blobs.committed_exists(name)? {
                        return Err(StoreErr::VersionMismatch);
                    }
                    if let Some(dl) = req.deadline_unix_secs {
                        self.meta.put_deadline(name, dl)?;
                    }
                    self.blobs.create(name, req.ops)
                }
                Some(expected) => self.blobs.update(name, req.ops, expected),
            }
        })()
        .map_err(SessionError::from)
    }

    /// Existence probe (see [`DbBlobs::exists`]).
    #[cfg(test)]
    pub(crate) fn exists(&self, name: &Name) -> Result<bool, SessionError> {
        self.blobs.exists(name.as_str()).map_err(SessionError::from)
    }

    /// Delete every session whose deadline is `<= now`, up to `max` per call:
    /// query the index (indexed range, O(log N + expired), no session-file
    /// opens), `rm` each session file, then drop the index rows. Self-healing —
    /// a crash mid-sweep re-selects leftover rows; a row whose file is already
    /// gone just `rm`s a missing file.
    ///
    /// Deliberately unscoped: a TTL is a TTL, and every caller's records expire
    /// on the same terms. The names it sweeps are opaque to it, so it needs to
    /// know nothing about whose they are.
    pub fn sweep_once(&self, now: u64, max: usize) -> Result<usize, SessionError> {
        (|| -> Result<usize, StoreErr> {
            let names = self.meta.expired(now, max)?;
            for name in &names {
                self.blobs.remove_files(name);
            }
            self.meta.remove(&names)?;
            Ok(names.len())
        })()
        .map_err(SessionError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_BUSY_TIMEOUT, SessionStore};
    use crate::scope::{Name, Scope};
    use storage_rpc::{
        BlobField, BlobWrite, FieldSelector, ListAppend, ListField, ListSlot, MediaName,
        MediaWrite, Op, ReadRequest, RecordName, ScalarSlot, SessionError, Slot, WriteRequest,
    };

    fn tmp_store() -> (tempfile::TempDir, SessionStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap(), DEFAULT_BUSY_TIMEOUT).unwrap();
        (dir, store)
    }

    /// The name one test caller's record `tag` is kept under.
    fn n(tag: u8) -> Name {
        Scope::new("aa".repeat(48)).session(&RecordName([tag; 32]))
    }

    /// One field set, at whatever version the caller then gives it.
    fn set_blob(field: BlobField, value: &[u8]) -> WriteRequest {
        WriteRequest {
            ops: vec![Op::Blob(BlobWrite {
                field,
                value: value.to_vec(),
            })],
            expected_version: None,
            deadline_unix_secs: None,
        }
    }

    /// A create of one field, dropped once `deadline` passes.
    fn create(field: BlobField, value: &[u8], deadline: u64) -> WriteRequest {
        WriteRequest {
            deadline_unix_secs: Some(deadline),
            ..set_blob(field, value)
        }
    }

    #[test]
    fn cas_rejects_stale_and_must_not_exist() {
        let (_d, s) = tmp_store();
        let v1 = s
            .write(&n(1), create(BlobField::Metadata, b"m1", 100))
            .unwrap();
        assert_eq!(v1.new_version, 1);
        // second create at None → conflict
        assert!(matches!(
            s.write(&n(1), create(BlobField::Metadata, b"x", 100)),
            Err(SessionError::VersionMismatch)
        ));
        // CAS at 1 → v2
        let mut upd = set_blob(BlobField::State, b"st");
        upd.expected_version = Some(1);
        assert_eq!(s.write(&n(1), upd).unwrap().new_version, 2);
        // stale CAS at 1 → conflict, losing value not applied
        let mut stale = set_blob(BlobField::State, b"loser");
        stale.expected_version = Some(1);
        assert!(matches!(
            s.write(&n(1), stale),
            Err(SessionError::VersionMismatch)
        ));
        let got = s
            .read(
                &n(1),
                ReadRequest {
                    fields: vec![FieldSelector::Blob(BlobField::State)],
                },
            )
            .unwrap();
        assert_eq!(got.version, 2);
        assert_eq!(
            got.slots[0],
            Slot::Scalar(ScalarSlot {
                value: Some(b"st".to_vec())
            })
        );
    }

    #[test]
    fn update_of_absent_session_is_mismatch() {
        let (_d, s) = tmp_store();
        let mut upd = set_blob(BlobField::State, b"x");
        upd.expected_version = Some(1);
        assert!(matches!(
            s.write(&n(9), upd),
            Err(SessionError::VersionMismatch)
        ));
    }

    #[test]
    fn empty_write_rejected_no_phantom_session() {
        let (_d, s) = tmp_store();
        let empty = WriteRequest {
            ops: vec![],
            expected_version: None,
            deadline_unix_secs: Some(100),
        };
        assert!(s.write(&n(1), empty).is_err());
        assert!(!s.exists(&n(1)).unwrap(), "no phantom session materialized");
        // An empty UPDATE is rejected too, version untouched.
        s.write(&n(1), create(BlobField::Metadata, b"m", 100))
            .unwrap();
        let empty_upd = WriteRequest {
            ops: vec![],
            expected_version: Some(1),
            deadline_unix_secs: None,
        };
        assert!(s.write(&n(1), empty_upd).is_err());
        assert_eq!(
            s.read(&n(1), ReadRequest { fields: vec![] })
                .unwrap()
                .version,
            1
        );
    }

    #[test]
    fn read_none_vs_empty() {
        let (_d, s) = tmp_store();
        // absent session → version 0, absent slot
        let got = s
            .read(
                &n(1),
                ReadRequest {
                    fields: vec![FieldSelector::Blob(BlobField::State)],
                },
            )
            .unwrap();
        assert_eq!(got.version, 0);
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: None }));
        // present-but-empty must read back as Some(empty), not None
        s.write(&n(1), create(BlobField::Metadata, b"", 100))
            .unwrap();
        let got = s
            .read(
                &n(1),
                ReadRequest {
                    fields: vec![FieldSelector::Blob(BlobField::Metadata)],
                },
            )
            .unwrap();
        assert_eq!(
            got.slots[0],
            Slot::Scalar(ScalarSlot {
                value: Some(vec![])
            })
        );
    }

    #[test]
    fn read_media_absent_slot() {
        let (_d, s) = tmp_store();
        s.write(&n(1), create(BlobField::Metadata, b"m", 100))
            .unwrap();
        let got = s
            .read(
                &n(1),
                ReadRequest {
                    fields: vec![FieldSelector::Media(MediaName([7u8; 32]))],
                },
            )
            .unwrap();
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: None }));
    }

    #[test]
    fn disclosure_set_membership_order_agnostic() {
        let (_d, s) = tmp_store();
        s.write(&n(1), create(BlobField::Metadata, b"m", 100))
            .unwrap();
        for (i, val) in [b"c".as_slice(), b"a", b"b"].iter().enumerate() {
            let req = WriteRequest {
                ops: vec![Op::ListAppend(ListAppend {
                    field: ListField::Disclosure,
                    value: val.to_vec(),
                })],
                expected_version: Some((i + 1) as u64),
                deadline_unix_secs: None,
            };
            s.write(&n(1), req).unwrap();
        }
        let got = s
            .read(
                &n(1),
                ReadRequest {
                    fields: vec![FieldSelector::List(ListField::Disclosure)],
                },
            )
            .unwrap();
        let Slot::List(ListSlot { mut items }) = got.slots.into_iter().next().unwrap() else {
            panic!("expected a list slot");
        };
        items.sort();
        assert_eq!(items, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }

    /// Everything one applicant put here goes, and the session stays claimable.
    /// The disclosure assertion is the load-bearing one: an entry surviving a
    /// reset is an entry the next applicant's would be appended to, under a
    /// session id the consumer reads as one person.
    #[test]
    fn a_reset_purges_state_media_and_disclosures_and_keeps_the_session() {
        let (_d, s) = tmp_store();
        let req = WriteRequest {
            ops: vec![
                Op::Blob(BlobWrite {
                    field: BlobField::State,
                    value: b"st".to_vec(),
                }),
                Op::MediaWrite(MediaWrite {
                    name: MediaName([1u8; 32]),
                    value: b"jpeg".to_vec(),
                }),
                Op::ListAppend(ListAppend {
                    field: ListField::Disclosure,
                    value: b"consented".to_vec(),
                }),
            ],
            expected_version: None,
            deadline_unix_secs: Some(100),
        };
        let created = s.write(&n(1), req).unwrap();
        let reset = WriteRequest {
            ops: vec![Op::Reset],
            expected_version: Some(created.new_version),
            deadline_unix_secs: None,
        };
        s.write(&n(1), reset).unwrap();
        assert!(s.exists(&n(1)).unwrap(), "session still exists after reset");
        let got = s
            .read(
                &n(1),
                ReadRequest {
                    fields: vec![
                        FieldSelector::Blob(BlobField::State),
                        FieldSelector::Media(MediaName([1u8; 32])),
                        FieldSelector::List(ListField::Disclosure),
                    ],
                },
            )
            .unwrap();
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: None }));
        assert_eq!(got.slots[1], Slot::Scalar(ScalarSlot { value: None }));
        assert_eq!(got.slots[2], Slot::List(ListSlot { items: vec![] }));
    }

    /// A reset under a version the session has moved past drops nothing: what a
    /// round committed after the reset read the session stays.
    #[test]
    fn a_reset_under_a_stale_version_drops_nothing() {
        let (_d, s) = tmp_store();
        let read_at = s
            .write(&n(1), create(BlobField::State, b"st", 100))
            .unwrap()
            .new_version;
        let round = WriteRequest {
            ops: vec![Op::ListAppend(ListAppend {
                field: ListField::Disclosure,
                value: b"consented".to_vec(),
            })],
            expected_version: Some(read_at),
            deadline_unix_secs: None,
        };
        s.write(&n(1), round).unwrap();

        let reset = WriteRequest {
            ops: vec![Op::Reset],
            expected_version: Some(read_at),
            deadline_unix_secs: None,
        };
        assert!(matches!(
            s.write(&n(1), reset),
            Err(SessionError::VersionMismatch)
        ));
        let got = s
            .read(
                &n(1),
                ReadRequest {
                    fields: vec![
                        FieldSelector::Blob(BlobField::State),
                        FieldSelector::List(ListField::Disclosure),
                    ],
                },
            )
            .unwrap();
        assert_eq!(
            got.slots[0],
            Slot::Scalar(ScalarSlot {
                value: Some(b"st".to_vec())
            })
        );
        assert_eq!(
            got.slots[1],
            Slot::List(ListSlot {
                items: vec![b"consented".to_vec()]
            })
        );
    }

    /// An update carries no deadline that sticks: a record's deadline is set once,
    /// at its create.
    #[test]
    fn an_update_does_not_move_the_deadline() {
        let (_d, s) = tmp_store();
        s.write(&n(1), create(BlobField::Metadata, b"m", 100))
            .unwrap();
        let mut later = set_blob(BlobField::State, b"st");
        later.expected_version = Some(1);
        later.deadline_unix_secs = Some(10_000_000);
        s.write(&n(1), later).unwrap();
        assert_eq!(s.sweep_once(1_000, 1024).unwrap(), 1);
        assert!(!s.exists(&n(1)).unwrap());
    }

    #[test]
    fn sweeper_purges_expired_only() {
        let (_d, s) = tmp_store();
        s.write(&n(1), create(BlobField::Metadata, b"m", 100))
            .unwrap();
        s.write(&n(2), create(BlobField::Metadata, b"m", 10_000_000))
            .unwrap();
        let purged = s.sweep_once(1_000, 1024).unwrap();
        assert_eq!(purged, 1);
        assert!(!s.exists(&n(1)).unwrap());
        assert!(s.exists(&n(2)).unwrap());
    }

    #[test]
    fn sweep_removes_whole_session() {
        let (_d, s) = tmp_store();
        s.write(&n(1), create(BlobField::Metadata, b"m", 100))
            .unwrap();
        let req = WriteRequest {
            ops: vec![Op::ListAppend(ListAppend {
                field: ListField::Disclosure,
                value: b"d1".to_vec(),
            })],
            expected_version: Some(1),
            deadline_unix_secs: None,
        };
        s.write(&n(1), req).unwrap();
        assert_eq!(s.sweep_once(1_000, 1024).unwrap(), 1);
        assert!(!s.exists(&n(1)).unwrap());
        let got = s
            .read(
                &n(1),
                ReadRequest {
                    fields: vec![FieldSelector::List(ListField::Disclosure)],
                },
            )
            .unwrap();
        assert_eq!(got.slots[0], Slot::List(ListSlot { items: vec![] }));
        // Swept id is gone from the index too: re-sweep finds nothing.
        assert_eq!(s.sweep_once(1_000_000, 1024).unwrap(), 0);
    }

    #[test]
    fn sweep_respects_max() {
        let (_d, s) = tmp_store();
        s.write(&n(1), create(BlobField::Metadata, b"m", 10))
            .unwrap();
        s.write(&n(2), create(BlobField::Metadata, b"m", 20))
            .unwrap();
        s.write(&n(3), create(BlobField::Metadata, b"m", 5_000))
            .unwrap(); // future
        assert_eq!(s.sweep_once(1_000, 1).unwrap(), 1);
        assert_eq!(s.sweep_once(1_000, 1024).unwrap(), 1);
        assert!(s.exists(&n(3)).unwrap());
    }
}
