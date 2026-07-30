//! The per-session data tier: **one SQLite database file per session** under a
//! `blobs/` directory. [`DbBlobs`] owns that directory and the `session_id` →
//! path mapping; the facade ([`super::SessionStore`]) holds one `DbBlobs` and
//! delegates. A blind ciphertext KV — every value is already AEAD-sealed
//! TEE-side, so this tier never interprets bytes.
//!
//! The file is `<dir>/<sha256(id)>.sqlite` — hashing the id both hides which
//! session a file is (defense-in-depth under the CVM's dm-crypt disk) and guards
//! path traversal. A round's ops (state + metadata + version + media + disclosure)
//! commit in ONE transaction, so a committed state never references media that
//! isn't durable. Connections are opened per operation (SQLite opens in ~tens of
//! µs) — no pool, no persistent handle.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use hatch_protocol::{
    BlobField, DeleteResponse, FieldSelector, ListField, ListSlot, Op, ReadRequest, ReadResponse,
    ScalarSlot, Slot, WriteResponse,
};

use super::StoreErr;

/// Per-session schema. `meta` holds the CAS version in its sole row (k=1);
/// `scalars` the four `BlobField`s by [`blob_tag`]; `media` the double-AEAD blobs
/// by content hash; `disclosure` the age-sealed entries as a SET (rowid order is
/// not meaningful — the api commits to the set, not the order). `IF NOT EXISTS`
/// so re-opening / a crash-empty file is idempotent.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS meta(k INTEGER PRIMARY KEY, version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS scalars(tag INTEGER PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS media(hash BLOB PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS disclosure(seq INTEGER PRIMARY KEY, v BLOB NOT NULL);";

/// The per-session file store, rooted at a `blobs/` directory. Stateless beyond
/// the directory path — every operation opens a fresh connection to the one
/// session's file.
pub(super) struct DbBlobs {
    dir: PathBuf,
}

impl DbBlobs {
    /// Open the store rooted at `dir` (the `blobs/` directory), creating it if
    /// absent. Idempotent.
    pub(super) fn open(dir: &Path) -> Result<DbBlobs, StoreErr> {
        std::fs::create_dir_all(dir)?;
        Ok(DbBlobs { dir: dir.to_path_buf() })
    }

    /// `<dir>/<sha256(id)>.sqlite`.
    fn path(&self, id: &str) -> PathBuf {
        let sh = hex::encode(Sha256::digest(id.as_bytes()));
        self.dir.join(format!("{sh}.sqlite"))
    }

    /// Batched typed read on a consistent snapshot. Slots come back in request
    /// order, each variant matching its selector; `None` (absent) vs `Some(empty)`
    /// preserved. Empty `req.fields` is a version probe. Absent (or crash-empty)
    /// file ⇒ `version == 0` with absent slots.
    pub(super) fn read(&self, id: &str, req: ReadRequest) -> Result<ReadResponse, StoreErr> {
        let conn = match open_ro(&self.path(id))? {
            Some(c) => c,
            None => return Ok(absent_response(&req)),
        };
        if !schema_present(&conn)? {
            return Ok(absent_response(&req));
        }
        // Deferred read transaction = a stable snapshot across all field reads.
        let tx = conn.unchecked_transaction()?;
        let version: u64 = tx
            .query_row("SELECT version FROM meta WHERE k=1", [], |r| r.get(0))
            .optional()?
            .unwrap_or(0);
        let mut slots = Vec::with_capacity(req.fields.len());
        for f in &req.fields {
            match f {
                FieldSelector::Blob(bf) => {
                    let v: Option<Vec<u8>> = tx
                        .query_row("SELECT v FROM scalars WHERE tag=?1", [blob_tag(*bf)], |r| {
                            r.get(0)
                        })
                        .optional()?;
                    slots.push(Slot::Scalar(ScalarSlot { value: v }));
                }
                FieldSelector::Media(hash) => {
                    let v: Option<Vec<u8>> = tx
                        .query_row(
                            "SELECT v FROM media WHERE hash=?1",
                            params![hash.as_slice()],
                            |r| r.get(0),
                        )
                        .optional()?;
                    slots.push(Slot::Scalar(ScalarSlot { value: v }));
                }
                FieldSelector::List(ListField::Disclosure) => {
                    let mut stmt = tx.prepare("SELECT v FROM disclosure")?;
                    let items = stmt
                        .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    slots.push(Slot::List(ListSlot { items }));
                }
            }
        }
        Ok(ReadResponse { slots, version })
    }

    /// Create the session file (must-not-exist). The facade has already done the
    /// pre-check + deadline write; this does the atomic in-txn must-not-exist
    /// guard + `version=1` + the round's ops, all in ONE fsync (schema
    /// materialised inside the txn).
    pub(super) fn create(&self, id: &str, ops: Vec<Op>) -> Result<WriteResponse, StoreErr> {
        let mut conn = open_create(&self.path(id))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        if tx
            .query_row("SELECT version FROM meta WHERE k=1", [], |r| r.get::<_, u64>(0))
            .optional()?
            .is_some()
        {
            return Err(StoreErr::VersionMismatch);
        }
        tx.execute("INSERT INTO meta(k, version) VALUES(1, 1)", [])?;
        apply_ops(&tx, ops)?;
        tx.commit()?;
        Ok(WriteResponse { new_version: 1 })
    }

    /// CAS update of an existing session. Absent file ⇒ mismatch. Never touches
    /// the deadline (absolute, fixed at create).
    pub(super) fn update(
        &self,
        id: &str,
        ops: Vec<Op>,
        expected: u64,
    ) -> Result<WriteResponse, StoreErr> {
        let mut conn = match open_rw(&self.path(id))? {
            Some(c) => c,
            None => return Err(StoreErr::VersionMismatch),
        };
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?; // no-op if present; guards a crash-empty file
        let current: Option<u64> =
            tx.query_row("SELECT version FROM meta WHERE k=1", [], |r| r.get(0)).optional()?;
        if current != Some(expected) {
            return Err(StoreErr::VersionMismatch);
        }
        let new_version = expected + 1;
        tx.execute(
            "INSERT INTO meta(k, version) VALUES(1, ?1) ON CONFLICT(k) DO UPDATE SET version=?1",
            [new_version],
        )?;
        apply_ops(&tx, ops)?;
        tx.commit()?;
        Ok(WriteResponse { new_version })
    }

    /// The `/reset` path: drop the STATE scalar + all media, keeping the session.
    /// Returns the state-field delete count (0 or 1). Absent file ⇒ 0.
    pub(super) fn delete(&self, id: &str) -> Result<DeleteResponse, StoreErr> {
        let mut conn = match open_rw(&self.path(id))? {
            Some(c) => c,
            None => return Ok(DeleteResponse { deleted: 0 }),
        };
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?; // no-op if present; guards a crash-empty file
        let deleted =
            tx.execute("DELETE FROM scalars WHERE tag=?1", [blob_tag(BlobField::State)])? as u64;
        tx.execute("DELETE FROM media", [])?;
        tx.commit()?;
        Ok(DeleteResponse { deleted })
    }

    /// Existence probe: file present with a committed version row.
    pub(super) fn exists(&self, id: &str) -> Result<bool, StoreErr> {
        self.committed_exists(id)
    }

    /// Whether a real (committed-meta) session file exists. Absent or crash-empty
    /// ⇒ `false`.
    pub(super) fn committed_exists(&self, id: &str) -> Result<bool, StoreErr> {
        let conn = match open_ro(&self.path(id))? {
            Some(c) => c,
            None => return Ok(false),
        };
        if !schema_present(&conn)? {
            return Ok(false);
        }
        Ok(conn.query_row("SELECT 1 FROM meta WHERE k=1", [], |_| Ok(())).optional()?.is_some())
    }

    /// Remove a session's on-disk SQLite file and any transient sidecars
    /// (`-journal`/`-wal`/`-shm`). Best-effort — a missing sidecar (the common
    /// case in rollback-journal mode) is ignored. Deleting a database is a
    /// filesystem operation (SQLite/rusqlite offer no "drop the file" helper). On
    /// Unix, unlinking a file that happens to be open succeeds: the open
    /// connection keeps working on the inode until it closes, then the space is
    /// freed; a later open by path sees it absent.
    pub(super) fn remove_files(&self, id: &str) {
        let base = self.path(id);
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", base.display()));
        }
    }
}

/// Stable wire tag for a scalar field. Decoupled from `BlobField as u8` so the
/// on-disk encoding does not depend on the enum's declaration order.
fn blob_tag(f: BlobField) -> u8 {
    match f {
        BlobField::Status => 0,
        BlobField::Metadata => 1,
        BlobField::State => 2,
        BlobField::Principal => 3,
    }
}

/// Apply a round's ops inside the caller's transaction — so state + media +
/// disclosure commit atomically.
fn apply_ops(tx: &Transaction, ops: Vec<Op>) -> Result<(), StoreErr> {
    for op in ops {
        match op {
            Op::Blob(b) => {
                tx.execute(
                    "INSERT INTO scalars(tag, v) VALUES(?1, ?2) \
                     ON CONFLICT(tag) DO UPDATE SET v=?2",
                    params![blob_tag(b.field), b.value],
                )?;
            }
            Op::ListAppend(a) => {
                tx.execute("INSERT INTO disclosure(v) VALUES(?1)", params![a.value])?;
            }
            Op::MediaWrite(m) => {
                tx.execute(
                    "INSERT INTO media(hash, v) VALUES(?1, ?2) \
                     ON CONFLICT(hash) DO UPDATE SET v=?2",
                    params![m.blob_key, m.value],
                )?;
            }
        }
    }
    Ok(())
}

/// All-absent read response (missing file, or a crash-empty one).
fn absent_response(req: &ReadRequest) -> ReadResponse {
    let slots = req
        .fields
        .iter()
        .map(|f| match f {
            FieldSelector::List(_) => Slot::List(ListSlot { items: vec![] }),
            _ => Slot::Scalar(ScalarSlot { value: None }),
        })
        .collect();
    ReadResponse { slots, version: 0 }
}

fn write_pragmas(conn: &Connection) -> Result<(), StoreErr> {
    conn.busy_timeout(Duration::from_secs(5))?;
    // Durable commits: full fsync per commit (fullfsync forces a real platter
    // flush on macOS; a harmless no-op elsewhere). Rollback-journal mode (default)
    // keeps one file at rest per session.
    conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")?;
    Ok(())
}

fn schema_present(conn: &Connection) -> Result<bool, StoreErr> {
    Ok(conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'", [], |_| Ok(()))
        .optional()?
        .is_some())
}

/// Open an existing file read-only. `Ok(None)` = the file does not exist.
fn open_ro(path: &Path) -> Result<Option<Connection>, StoreErr> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    match Connection::open_with_flags(path, flags) {
        Ok(c) => {
            c.busy_timeout(Duration::from_secs(5))?;
            Ok(Some(c))
        }
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::CannotOpen => {
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Open an existing file read-write (no create). `Ok(None)` = absent.
fn open_rw(path: &Path) -> Result<Option<Connection>, StoreErr> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    match Connection::open_with_flags(path, flags) {
        Ok(c) => {
            write_pragmas(&c)?;
            Ok(Some(c))
        }
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::CannotOpen => {
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Open (creating if absent) a file read-write. Schema is materialised inside the
/// write transaction (see [`DbBlobs::create`]) so a create is a single fsync.
fn open_create(path: &Path) -> Result<Connection, StoreErr> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    write_pragmas(&conn)?;
    Ok(conn)
}
