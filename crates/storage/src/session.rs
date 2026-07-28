//! The per-session store, backed by redb. A blind ciphertext KV: every value is
//! already AEAD-sealed TEE-side, so this module never interprets bytes — it moves
//! opaque blobs keyed by `session_id`, mirroring the Redis shape the hatch had
//! but with real ACID CAS (redb serializes writers, so the Lua `WRITE_SCRIPT`
//! becomes a plain write transaction).
//!
//! Tables use **tuple keys** (redb orders them element-wise), so `(id, seq)` /
//! `(id, hash)` ranges can never prefix-collide with another session — a class
//! of bug the old `session:{id}:…` string keys invited. Media lives in its own
//! table so 64 MiB values stay off the hot BLOBS/VERSION B-tree pages.

use redb::{
    Database, MultimapTableDefinition, ReadableDatabase, ReadableTable, TableDefinition,
};

use hatch_protocol::{
    BlobField, DeleteResponse, FieldSelector, ListField, ListSlot, Op, ReadRequest, ReadResponse,
    ScalarSlot, Slot, WriteRequest, WriteResponse,
};
use storage_rpc::SessionError;

/// Scalar blobs: `(session_id, blob_tag) -> sealed bytes`. Tag values are stable
/// wire ints (see [`blob_tag`]); the whole session's four scalars share this
/// table.
const BLOBS: TableDefinition<(&str, u8), &[u8]> = TableDefinition::new("blobs");
/// Authoritative CAS counter + existence marker: `session_id -> version`.
/// Presence here IS "the session exists" (Redis `EXISTS` on the hash).
const VERSION: TableDefinition<&str, u64> = TableDefinition::new("version");
/// Disclosure set: `session_id -> {age-sealed entry}` (redb MULTIMAP). Order is
/// NOT preserved (multimap sorts values by bytes = age's random ephemeral prefix)
/// and NOT relied upon — the api commits to the SET, not the order. Values are
/// age ciphertexts, distinct with overwhelming probability (random ephemeral key
/// per seal), so multimap set-dedup of byte-identical values is benign (a host
/// re-serving a genuine entry is a count/commitment mismatch the api catches).
const DISCLOSURE: MultimapTableDefinition<&str, &[u8]> = MultimapTableDefinition::new("disclosure");
/// Media blobs: `(session_id, content_key) -> double-AEAD sealed blob` (≤64 MiB).
const MEDIA: TableDefinition<(&str, &[u8]), &[u8]> = TableDefinition::new("media");
/// Time-ordered TTL index: `(deadline_unix_secs, session_id) -> ()`. ABSOLUTE
/// TTL — one entry per session, inserted ONCE at create (`created_at + ttl`) and
/// never moved, so no reverse `id -> deadline` table and no decrease-key. The
/// sweeper range-scans the expired prefix. Sole deadline table.
const DEADLINE_INDEX: TableDefinition<(u64, &str), ()> = TableDefinition::new("deadline_index");

/// Stable wire tag for a scalar field. Kept here (not `BlobField as u8`) so the
/// on-disk encoding is decoupled from the enum's declaration order.
fn blob_tag(f: BlobField) -> u8 {
    match f {
        BlobField::Status => 0,
        BlobField::Metadata => 1,
        BlobField::State => 2,
        BlobField::Principal => 3,
    }
}

/// Module-internal error so the store bodies use plain `?` on redb ops. redb's
/// error types and the public `SessionError` are BOTH foreign to this crate, so
/// the orphan rule forbids `impl From<redb::_> for SessionError` directly; a local
/// type sidesteps that and is converted to `SessionError` once at each public
/// boundary (via [`From<StoreErr>`]). `Internal` holds any non-CAS failure as a
/// message (a stringified redb error, or a guard like the empty-write reject) —
/// small, so `Result<_, StoreErr>` stays cheap to move.
enum StoreErr {
    Internal(String),
    /// CAS precondition failed (stale `expected_version` or a must-not-exist
    /// create that found an existing session) — NOT a redb failure.
    VersionMismatch,
}

macro_rules! from_redb {
    ($($ty:ty),+ $(,)?) => {$(
        impl From<$ty> for StoreErr {
            fn from(e: $ty) -> Self { StoreErr::Internal(e.to_string()) }
        }
    )+};
}
from_redb!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
);

impl From<StoreErr> for SessionError {
    fn from(e: StoreErr) -> Self {
        match e {
            StoreErr::VersionMismatch => SessionError::VersionMismatch,
            StoreErr::Internal(msg) => SessionError::Internal(msg),
        }
    }
}

/// Open (or create) the redb database and materialize all tables so later reads
/// never hit `TableDoesNotExist`. Idempotent.
pub fn open(path: &str) -> Result<Database, SessionError> {
    (|| -> Result<Database, StoreErr> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        // Opening a table in a write txn creates it if absent.
        txn.open_table(BLOBS)?;
        txn.open_table(VERSION)?;
        txn.open_multimap_table(DISCLOSURE)?;
        txn.open_table(MEDIA)?;
        txn.open_table(DEADLINE_INDEX)?;
        txn.commit()?;
        Ok(db)
    })()
    .map_err(SessionError::from)
}

/// Batched typed read (MVCC snapshot). Slots come back in request order, each
/// variant matching its selector. `None` (absent) vs `Some(empty)` is preserved.
/// Empty `req.fields` is a version probe. `version == 0` ⇒ session absent.
pub fn read(db: &Database, id: &str, req: ReadRequest) -> Result<ReadResponse, SessionError> {
    (|| -> Result<ReadResponse, StoreErr> {
        let txn = db.begin_read()?;

        let version = {
            let ver = txn.open_table(VERSION)?;
            ver.get(id)?.map(|g| g.value()).unwrap_or(0)
        };

        let mut slots = Vec::with_capacity(req.fields.len());
        if !req.fields.is_empty() {
            let blobs = txn.open_table(BLOBS)?;
            let media = txn.open_table(MEDIA)?;
            let disc = txn.open_multimap_table(DISCLOSURE)?;
            for f in &req.fields {
                match f {
                    FieldSelector::Blob(bf) => {
                        let value = blobs.get((id, blob_tag(*bf)))?.map(|g| g.value().to_vec());
                        slots.push(Slot::Scalar(ScalarSlot { value }));
                    }
                    FieldSelector::Media(hash) => {
                        let value = media.get((id, hash.as_slice()))?.map(|g| g.value().to_vec());
                        slots.push(Slot::Scalar(ScalarSlot { value }));
                    }
                    FieldSelector::List(ListField::Disclosure) => {
                        // The whole disclosure SET for this session. Value-byte
                        // order (NOT emission order) — intended; the api commits
                        // to the set, not the order.
                        let mut items = Vec::new();
                        for v in disc.get(id)? {
                            items.push(v?.value().to_vec());
                        }
                        slots.push(Slot::List(ListSlot { items }));
                    }
                }
            }
        }
        Ok(ReadResponse { slots, version })
    })()
    .map_err(SessionError::from)
}

/// Atomic CAS write. `expected_version`: `None` = must-not-exist (create),
/// `Some(v)` = current must equal `v`; otherwise [`SessionError::VersionMismatch`]
/// (the txn drops un-committed). `deadline` = `Some` only on the create write
/// (absolute TTL, set once, committed atomically). `req.ops` must be non-empty —
/// an empty write is a caller invariant violation (the api always carries ≥1 op)
/// and is rejected before any version bump, so it can't materialize a
/// version-only phantom session.
pub fn write(
    db: &Database,
    id: &str,
    req: WriteRequest,
    deadline: Option<u64>,
) -> Result<WriteResponse, SessionError> {
    (move || -> Result<WriteResponse, StoreErr> {
        if req.ops.is_empty() {
            return Err(StoreErr::Internal("write with no ops".to_string()));
        }
        let txn = db.begin_write()?;
        let new_version;
        {
            let mut ver = txn.open_table(VERSION)?;
            let current = ver.get(id)?.map(|g| g.value());
            match req.expected_version {
                None if current.is_some() => return Err(StoreErr::VersionMismatch),
                Some(v) if current != Some(v) => return Err(StoreErr::VersionMismatch),
                _ => {}
            }
            new_version = current.unwrap_or(0) + 1;
            ver.insert(id, new_version)?;

            let mut blobs = txn.open_table(BLOBS)?;
            let mut disc = txn.open_multimap_table(DISCLOSURE)?;
            let mut media = txn.open_table(MEDIA)?;
            for op in req.ops {
                match op {
                    Op::Blob(b) => {
                        blobs.insert((id, blob_tag(b.field)), b.value.as_slice())?;
                    }
                    Op::ListAppend(a) => {
                        // Add to the session's disclosure set — no seq/cursor;
                        // order is not preserved and not needed.
                        disc.insert(id, a.value.as_slice())?;
                    }
                    Op::MediaWrite(m) => {
                        media.insert((id, m.blob_key.as_slice()), m.value.as_slice())?;
                    }
                }
            }

            if let Some(dl) = deadline {
                // Absolute TTL: the api passes `Some` ONLY on the create write, so
                // this is a single insert per session — no get-old / remove-old
                // (decrease-key) and no reverse `id -> deadline` table.
                let mut di = txn.open_table(DEADLINE_INDEX)?;
                di.insert((dl, id), ())?;
            }
        }
        txn.commit()?;
        Ok(WriteResponse { new_version })
    })()
    .map_err(SessionError::from)
}

/// The `/reset` path: drop the STATE scalar + purge all media for the session.
/// Metadata/version/deadline are LEFT intact so the session still `exists` and
/// the next `/connect` re-claims it with a fresh applicant key (old state/media
/// were sealed under the discarded token, already unreadable). Returns the
/// state-field delete count.
pub fn delete(db: &Database, id: &str) -> Result<DeleteResponse, SessionError> {
    (|| -> Result<DeleteResponse, StoreErr> {
        let txn = db.begin_write()?;
        let deleted;
        {
            let mut blobs = txn.open_table(BLOBS)?;
            deleted = blobs.remove((id, blob_tag(BlobField::State)))?.is_some() as u64;

            let mut media = txn.open_table(MEDIA)?;
            // Collect this session's media keys (contiguous, MEDIA is keyed by
            // `(id, hash)`) then remove — the range iterator borrows `media`
            // immutably, so it must drop before the `remove` mutable borrow.
            let keys: Vec<Vec<u8>> = {
                let lo: (&str, &[u8]) = (id, &[]);
                let mut ks = Vec::new();
                for entry in media.range(lo..)? {
                    let (k, _) = entry?;
                    let (sid, hash) = k.value();
                    if sid != id {
                        break;
                    }
                    ks.push(hash.to_vec());
                }
                ks
            };
            for k in keys {
                media.remove((id, k.as_slice()))?;
            }
        }
        txn.commit()?;
        Ok(DeleteResponse { deleted })
    })()
    .map_err(SessionError::from)
}

/// Existence probe: the session's version row is present.
pub fn exists(db: &Database, id: &str) -> Result<bool, SessionError> {
    (|| -> Result<bool, StoreErr> {
        let txn = db.begin_read()?;
        let ver = txn.open_table(VERSION)?;
        Ok(ver.get(id)?.is_some())
    })()
    .map_err(SessionError::from)
}

/// Delete every session whose deadline is `<= now`, up to `max` per call
/// (bounds the write-txn lock hold). Returns how many were purged. Ordered by
/// `(deadline, id)`, so we stop at the first future deadline.
pub fn sweep_once(db: &Database, now: u64, max: usize) -> Result<usize, SessionError> {
    (|| -> Result<usize, StoreErr> {
        let txn = db.begin_write()?;
        // Remove up to `max` expired index entries (deadline ≤ now) in time order
        // and collect their session ids. `extract_from_if` removes each entry as
        // it is read from the returned iterator; `.take(max)` bounds the write-txn
        // lock hold. The upper bound `(now+1, "")` includes every `(≤now, *)`.
        let expired: Vec<String> = {
            let mut di = txn.open_table(DEADLINE_INDEX)?;
            let lo: (u64, &str) = (0, "");
            let hi: (u64, &str) = (now.saturating_add(1), "");
            di.extract_from_if(lo..hi, |_, _| true)?
                .take(max)
                .map(|r| r.map(|(k, _)| k.value().1.to_string()))
                .collect::<Result<_, _>>()?
        };
        for id in &expired {
            purge_session(&txn, id)?;
        }
        txn.commit()?;
        Ok(expired.len())
    })()
    .map_err(SessionError::from)
}

/// Remove every table entry for one session (used by the sweeper).
fn purge_session(txn: &redb::WriteTransaction, id: &str) -> Result<(), StoreErr> {
    {
        let mut ver = txn.open_table(VERSION)?;
        ver.remove(id)?;
    }
    {
        let mut blobs = txn.open_table(BLOBS)?;
        for tag in 0u8..=3 {
            blobs.remove((id, tag))?;
        }
    }
    {
        let mut disc = txn.open_multimap_table(DISCLOSURE)?;
        disc.remove_all(id)?;
    }
    {
        let mut media = txn.open_table(MEDIA)?;
        let keys: Vec<Vec<u8>> = {
            let lo: (&str, &[u8]) = (id, &[]);
            let mut ks = Vec::new();
            for entry in media.range(lo..)? {
                let (k, _) = entry?;
                let (sid, hash) = k.value();
                if sid != id {
                    break;
                }
                ks.push(hash.to_vec());
            }
            ks
        };
        for k in keys {
            media.remove((id, k.as_slice()))?;
        }
    }
    // No deadline cleanup here: the sweeper (the only caller) already removed the
    // session's `(deadline, id)` index entry via `extract_from_if`.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatch_protocol::{BlobWrite, ListAppend, MediaWrite};

    fn tmp_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.redb");
        let db = open(path.to_str().unwrap()).unwrap();
        (dir, db)
    }

    fn set_blob(field: BlobField, value: &[u8]) -> WriteRequest {
        WriteRequest {
            ops: vec![Op::Blob(BlobWrite { field, value: value.to_vec() })],
            expected_version: None,
        }
    }

    #[test]
    fn probe_read_txn_open_missing_table_errors() {
        // WHY `open()` eagerly materializes tables: a read txn CANNOT create a
        // table, so opening a never-written table in one errors. Fresh DB, no
        // writes → the table does not exist.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raw.redb");
        let db = Database::create(path.to_str().unwrap()).unwrap();
        let txn = db.begin_read().unwrap();
        assert!(
            txn.open_table(VERSION).is_err(),
            "read-txn open_table on a never-created table must error"
        );
    }

    #[test]
    fn probe_read_after_write_that_skipped_media_table() {
        // A write that touches only VERSION+BLOBS does NOT create MEDIA. Our
        // `read` opens MEDIA unconditionally, so WITHOUT `open()`'s eager
        // materialization this read would hit TableDoesNotExist. With it, MEDIA
        // exists (empty) and the media slot reads back absent.
        let (_d, db) = tmp_db();
        write(&db, "s", set_blob(BlobField::Metadata, b"m"), None).unwrap();
        let got = read(
            &db,
            "s",
            ReadRequest { fields: vec![FieldSelector::Media(vec![7u8; 32])] },
        )
        .unwrap();
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: None }));
    }

    #[test]
    fn cas_rejects_stale_and_must_not_exist() {
        let (_d, db) = tmp_db();
        // create at None → v1
        let v1 = write(&db, "s", set_blob(BlobField::Metadata, b"m1"), None).unwrap();
        assert_eq!(v1.new_version, 1);
        // second create at None → conflict
        assert!(matches!(
            write(&db, "s", set_blob(BlobField::Metadata, b"x"), None),
            Err(SessionError::VersionMismatch)
        ));
        // CAS at 1 → v2
        let mut upd = set_blob(BlobField::State, b"st");
        upd.expected_version = Some(1);
        assert_eq!(write(&db, "s", upd, None).unwrap().new_version, 2);
        // stale CAS at 1 → conflict, and the losing write's value not applied
        let mut stale = set_blob(BlobField::State, b"loser");
        stale.expected_version = Some(1);
        assert!(matches!(write(&db, "s", stale, None), Err(SessionError::VersionMismatch)));
        let got = read(
            &db,
            "s",
            ReadRequest { fields: vec![FieldSelector::Blob(BlobField::State)] },
        )
        .unwrap();
        assert_eq!(got.version, 2);
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: Some(b"st".to_vec()) }));
    }

    #[test]
    fn empty_write_rejected_no_phantom_session() {
        let (_d, db) = tmp_db();
        // A create with zero ops is a caller invariant violation — rejected
        // before any version bump, so no version-only phantom session is left.
        let empty = WriteRequest { ops: vec![], expected_version: None };
        assert!(write(&db, "s", empty, Some(100)).is_err());
        assert!(!exists(&db, "s").unwrap(), "no phantom session materialized");
        // An empty UPDATE is rejected too (still no bump).
        write(&db, "s", set_blob(BlobField::Metadata, b"m"), None).unwrap();
        let empty_upd = WriteRequest { ops: vec![], expected_version: Some(1) };
        assert!(write(&db, "s", empty_upd, None).is_err());
        // Version untouched (still 1) — the reject happens before the bump.
        let v = read(&db, "s", ReadRequest { fields: vec![] }).unwrap().version;
        assert_eq!(v, 1);
    }

    #[test]
    fn read_none_vs_empty() {
        let (_d, db) = tmp_db();
        // absent session → version 0, absent slot
        let got = read(
            &db,
            "s",
            ReadRequest { fields: vec![FieldSelector::Blob(BlobField::State)] },
        )
        .unwrap();
        assert_eq!(got.version, 0);
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: None }));
        // present-but-empty must read back as Some(empty), not None
        write(&db, "s", set_blob(BlobField::Metadata, b""), None).unwrap();
        let got = read(
            &db,
            "s",
            ReadRequest { fields: vec![FieldSelector::Blob(BlobField::Metadata)] },
        )
        .unwrap();
        assert_eq!(got.slots[0], Slot::Scalar(ScalarSlot { value: Some(vec![]) }));
    }

    #[test]
    fn disclosure_set_membership_order_agnostic() {
        let (_d, db) = tmp_db();
        write(&db, "s", set_blob(BlobField::Metadata, b"m"), None).unwrap();
        // Append in a deliberately non-sorted order; the multimap stores a SET
        // (value-byte order, not append order), so read returns the same MEMBERS
        // regardless of insertion order.
        for (i, val) in [b"c".as_slice(), b"a", b"b"].iter().enumerate() {
            let req = WriteRequest {
                ops: vec![Op::ListAppend(ListAppend {
                    field: ListField::Disclosure,
                    value: val.to_vec(),
                })],
                expected_version: Some((i + 1) as u64),
            };
            write(&db, "s", req, None).unwrap();
        }
        let got = read(
            &db,
            "s",
            ReadRequest { fields: vec![FieldSelector::List(ListField::Disclosure)] },
        )
        .unwrap();
        let Slot::List(ListSlot { mut items }) = got.slots.into_iter().next().unwrap() else {
            panic!("expected a list slot");
        };
        items.sort();
        assert_eq!(items, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()], "same set, order-agnostic");
    }

    #[test]
    fn purge_removes_disclosures() {
        let (_d, db) = tmp_db();
        write(&db, "s", set_blob(BlobField::Metadata, b"m"), Some(100)).unwrap();
        let req = WriteRequest {
            ops: vec![Op::ListAppend(ListAppend {
                field: ListField::Disclosure,
                value: b"d1".to_vec(),
            })],
            expected_version: Some(1),
        };
        // Absolute TTL: deadline set only at create (above), None on updates.
        write(&db, "s", req, None).unwrap();
        // Expire + sweep → the whole session (incl. its disclosure set) is gone.
        assert_eq!(sweep_once(&db, 1_000, 1024).unwrap(), 1);
        assert!(!exists(&db, "s").unwrap());
        let got = read(
            &db,
            "s",
            ReadRequest { fields: vec![FieldSelector::List(ListField::Disclosure)] },
        )
        .unwrap();
        assert_eq!(got.slots[0], Slot::List(ListSlot { items: vec![] }));
    }

    #[test]
    fn delete_purges_media_keeps_session() {
        let (_d, db) = tmp_db();
        let req = WriteRequest {
            ops: vec![
                Op::Blob(BlobWrite { field: BlobField::State, value: b"st".to_vec() }),
                Op::MediaWrite(MediaWrite { blob_key: vec![1u8; 32], value: b"jpeg".to_vec() }),
            ],
            expected_version: None,
        };
        write(&db, "s", req, None).unwrap();
        let del = delete(&db, "s").unwrap();
        assert_eq!(del.deleted, 1);
        assert!(exists(&db, "s").unwrap(), "session still exists after reset");
        // state gone, media gone
        let got = read(
            &db,
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
        let (_d, db) = tmp_db();
        // s_old deadline in the past, s_new in the future
        write(&db, "s_old", set_blob(BlobField::Metadata, b"m"), Some(100)).unwrap();
        write(&db, "s_new", set_blob(BlobField::Metadata, b"m"), Some(10_000)).unwrap();
        let purged = sweep_once(&db, 1_000, 1024).unwrap();
        assert_eq!(purged, 1);
        assert!(!exists(&db, "s_old").unwrap());
        assert!(exists(&db, "s_new").unwrap());
    }
}
