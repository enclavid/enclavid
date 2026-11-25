//! The **global session index** — the cross-session "metadata" tier. One shared
//! SQLite file (`meta.sqlite`) holding data that must be queried ACROSS sessions
//! rather than per-session: the absolute TTL `deadline` of each record, and every
//! caller's notices.
//!
//! Kept apart from the per-session files ([`super::db_blobs`]) because its access
//! pattern is different: shared tables touched on create (insert a deadline), on
//! the write that adds a notice, on a take and a settle, and on the sweep — never
//! on a plain per-round update. A held `Mutex<Connection>` serialises those
//! writers; a plain round never contends it.
//!
//! The row key is the record name, not the session id — the sweep has to name a
//! file, and after [`crate::scope`] the file is not a function of the id alone. A
//! notice is keyed the same way, by the name the caller's partition gave it, and
//! kept in that partition's list.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, params};

use storage_rpc::{DueNotice, NoticeName, Settle};

use super::StoreErr;

/// Absolute `deadline` per record, indexed for the range sweep; and each
/// notice, in its caller's `list` beside the name that caller gave it
/// (`asked`), indexed for a take and for the sweep.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS deadlines(name TEXT PRIMARY KEY, deadline INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS deadlines_by_time ON deadlines(deadline);
CREATE TABLE IF NOT EXISTS notices(name TEXT PRIMARY KEY, list TEXT NOT NULL, asked BLOB NOT NULL, due INTEGER NOT NULL, value BLOB NOT NULL) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS notices_by_list ON notices(list, due);
CREATE INDEX IF NOT EXISTS notices_by_time ON notices(due);";

/// Every statement this store issues, named here so [`DbMeta::open`] can compile
/// them all against the file it just opened.
const PUT: &str = "INSERT OR REPLACE INTO deadlines(name, deadline) VALUES(?1, ?2)";
const EXPIRED: &str = "SELECT name FROM deadlines WHERE deadline <= ?1 ORDER BY deadline LIMIT ?2";
const REMOVE: &str = "DELETE FROM deadlines WHERE name = ?1";
const PUT_NOTICE: &str =
    "INSERT OR REPLACE INTO notices(name, list, asked, due, value) VALUES(?1, ?2, ?3, ?4, ?5)";
const DUE_NOTICES: &str =
    "SELECT name, asked, value FROM notices WHERE list = ?1 AND due <= ?2 ORDER BY due LIMIT ?3";
const MOVE_NOTICE: &str = "UPDATE notices SET due = ?2 WHERE name = ?1";
const NEXT_NOTICE: &str = "SELECT MIN(due) FROM notices WHERE list = ?1";
const DROP_NOTICE: &str = "DELETE FROM notices WHERE name = ?1";
const STALE_NOTICES: &str = "DELETE FROM notices WHERE name IN \
     (SELECT name FROM notices WHERE due <= ?1 ORDER BY due LIMIT ?2)";

/// A notice as the index keeps it: under the name its caller's partition gave
/// it, with the name the caller gave beside it, to hand back when it is taken.
pub(super) struct NoticeRow<'a> {
    pub(super) name: &'a str,
    pub(super) asked: &'a NoticeName,
    pub(super) due: u64,
    pub(super) value: &'a [u8],
}

/// A time in unix seconds as SQLite keeps an integer, one past its range held at
/// the end of it.
fn secs(t: u64) -> i64 {
    i64::try_from(t).unwrap_or(i64::MAX)
}

pub(super) struct DbMeta {
    conn: Mutex<Connection>,
}

impl DbMeta {
    /// Open (creating if absent) the shared index at `path`. Durable commits
    /// (`synchronous=FULL` + `fullfsync`) so a deadline row is durable before the
    /// session that relies on it commits (see the create ordering in
    /// [`super::SessionStore::write`]).
    ///
    /// A file this store cannot serve is refused here rather than at the first
    /// request. `busy` is how long a statement waits on the file locked by
    /// another ([`super::DEFAULT_BUSY_TIMEOUT`]).
    pub(super) fn open(path: &Path, busy: Duration) -> Result<DbMeta, StoreErr> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(busy)?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")?;
        conn.execute_batch(SCHEMA)?;
        // `CREATE TABLE IF NOT EXISTS` is a no-op on a table that is already
        // there, whatever its columns are — so the batch above proves nothing
        // about a file some earlier build wrote. Compiling every statement does:
        // SQLite resolves column references at PREPARE, so one that this schema
        // does not satisfy fails here, at boot, in the same voice as a missing
        // environment variable.
        //
        // Asking SQLite rather than tracking a version of our own is what keeps
        // this from crying wolf: reindenting the SQL above changes no statement's
        // meaning and changes nothing here, where a stamp over the text would
        // have refused a perfectly good file.
        for sql in [
            PUT,
            EXPIRED,
            REMOVE,
            PUT_NOTICE,
            DUE_NOTICES,
            MOVE_NOTICE,
            NEXT_NOTICE,
            DROP_NOTICE,
            STALE_NOTICES,
        ] {
            conn.prepare(sql)?;
        }
        Ok(DbMeta {
            conn: Mutex::new(conn),
        })
    }

    /// Record the absolute deadline for `name` (its own durable commit).
    /// Idempotent — `INSERT OR REPLACE`.
    pub(super) fn put_deadline(&self, name: &str, deadline: u64) -> Result<(), StoreErr> {
        let conn = self.lock()?;
        conn.execute(PUT, params![name, deadline as i64])?;
        Ok(())
    }

    /// The record names whose deadline is `<= now`, up to `max`, earliest first
    /// (indexed range scan).
    pub(super) fn expired(&self, now: u64, max: usize) -> Result<Vec<String>, StoreErr> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(EXPIRED)?;
        let names = stmt
            .query_map(params![now as i64, max as i64], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }

    /// Drop the given record names from the index in one commit. No-op on empty.
    pub(super) fn remove(&self, names: &[String]) -> Result<(), StoreErr> {
        if names.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        for name in names {
            tx.execute(REMOVE, params![name])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Keep `notices` in `list`, each in place of any kept under its name, in one
    /// durable commit. No-op on empty.
    pub(super) fn put_notices(
        &self,
        list: &str,
        notices: &[NoticeRow<'_>],
    ) -> Result<(), StoreErr> {
        if notices.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        for n in notices {
            tx.execute(
                PUT_NOTICE,
                params![n.name, list, n.asked.0.as_slice(), secs(n.due), n.value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The notices of `list` due by `now`, earliest first, at most `max` — each
    /// made due at `held_until` in the same commit, so no other take hands it out
    /// before then — and when the earliest of `list` is due after that, if it
    /// keeps any.
    pub(super) fn take_notices(
        &self,
        list: &str,
        now: u64,
        max: usize,
        held_until: u64,
    ) -> Result<(Vec<DueNotice>, Option<u64>), StoreErr> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let rows = {
            let mut stmt = tx.prepare(DUE_NOTICES)?;
            stmt.query_map(params![list, secs(now), max as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        let mut taken = Vec::with_capacity(rows.len());
        for (name, asked, value) in rows {
            tx.execute(MOVE_NOTICE, params![name, secs(held_until)])?;
            let asked = <[u8; 32]>::try_from(asked)
                .map_err(|_| StoreErr::Internal("a notice kept beside a short name".into()))?;
            taken.push(DueNotice {
                name: NoticeName(asked),
                value,
            });
        }
        let next = tx
            .query_row(NEXT_NOTICE, params![list], |r| r.get::<_, Option<i64>>(0))?
            .map(|due| u64::try_from(due).unwrap_or(0));
        tx.commit()?;
        Ok((taken, next))
    }

    /// Drop the notice kept under `name`, or make it due at another time, as
    /// `settle` says. A no-op where none is kept.
    pub(super) fn settle_notice(&self, name: &str, settle: Settle) -> Result<(), StoreErr> {
        let conn = self.lock()?;
        match settle {
            Settle::Done => conn.execute(DROP_NOTICE, params![name])?,
            Settle::Again { due_unix_secs } => {
                conn.execute(MOVE_NOTICE, params![name, secs(due_unix_secs)])?
            }
        };
        Ok(())
    }

    /// Drop the notices due at or before `before`, at most `max`, earliest first;
    /// how many went.
    pub(super) fn drop_stale_notices(&self, before: u64, max: usize) -> Result<usize, StoreErr> {
        let conn = self.lock()?;
        Ok(conn.execute(STALE_NOTICES, params![secs(before), max as i64])?)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreErr> {
        self.conn
            .lock()
            .map_err(|_| StoreErr::Internal("index mutex poisoned".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUSY: Duration = super::super::DEFAULT_BUSY_TIMEOUT;

    // `StoreErr` is deliberately not `Debug` — it carries store messages — so
    // these unwrap through `ok()`.
    #[test]
    fn a_file_this_build_wrote_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.sqlite");
        DbMeta::open(&path, BUSY)
            .ok()
            .expect("fresh open")
            .put_deadline("n", 10)
            .ok()
            .expect("write");
        let again = DbMeta::open(&path, BUSY).ok().expect("reopen");
        assert_eq!(
            again.expired(100, 10).ok().expect("select"),
            vec!["n".to_string()]
        );
    }

    #[test]
    fn a_file_another_schema_wrote_is_refused_at_open() {
        // What an earlier build left behind: the same table under a different
        // key column. `CREATE TABLE IF NOT EXISTS` accepts it silently, and
        // every write afterwards fails — which is the mode this check removes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE deadlines(session_id TEXT PRIMARY KEY, deadline INTEGER NOT NULL);",
            )
            .unwrap();
        assert!(DbMeta::open(&path, BUSY).is_err());
    }

    #[test]
    fn reformatting_the_ddl_is_not_a_schema_change() {
        // The reason the check asks SQLite instead of stamping a version of its
        // own: this file is byte-for-byte unlike SCHEMA and satisfies every
        // statement, so refusing it would be crying wolf.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE deadlines (\n\
                 \x20   name      TEXT    PRIMARY KEY,  -- the record name\n\
                 \x20   deadline  INTEGER NOT NULL\n\
                 ) WITHOUT ROWID;",
            )
            .unwrap();
        assert!(DbMeta::open(&path, BUSY).is_ok());
    }
}
