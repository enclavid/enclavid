//! The **global session index** — the cross-session "metadata" tier. One shared
//! SQLite file (`meta.sqlite`) holding data that must be queried ACROSS sessions
//! rather than per-session. Today that is only the absolute TTL `deadline`; it is
//! the home for any future globally-queryable per-session metadata.
//!
//! Kept apart from the per-session files ([`super::db_blobs`]) because its access
//! pattern is different: it is a single shared table touched only on create
//! (insert a deadline) and sweep (range-select + delete), never on the hot
//! per-round update path. A held `Mutex<Connection>` serialises those infrequent
//! writers; the hot path never contends it.
//!
//! The row key is the record name, not the session id — the sweep has to name a
//! file, and after [`crate::scope`] the file is not a function of the id alone.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, params};

use super::StoreErr;

/// Absolute `deadline` per record, indexed for the range sweep.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS deadlines(name TEXT PRIMARY KEY, deadline INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS deadlines_by_time ON deadlines(deadline);";

/// Every statement this store issues, named here so [`DbMeta::open`] can compile
/// them all against the file it just opened.
const PUT: &str = "INSERT OR REPLACE INTO deadlines(name, deadline) VALUES(?1, ?2)";
const EXPIRED: &str = "SELECT name FROM deadlines WHERE deadline <= ?1 ORDER BY deadline LIMIT ?2";
const REMOVE: &str = "DELETE FROM deadlines WHERE name = ?1";

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
    /// request.
    pub(super) fn open(path: &Path) -> Result<DbMeta, StoreErr> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
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
        for sql in [PUT, EXPIRED, REMOVE] {
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

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreErr> {
        self.conn
            .lock()
            .map_err(|_| StoreErr::Internal("index mutex poisoned".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `StoreErr` is deliberately not `Debug` — it carries store messages — so
    // these unwrap through `ok()`.
    #[test]
    fn a_file_this_build_wrote_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.sqlite");
        DbMeta::open(&path)
            .ok()
            .expect("fresh open")
            .put_deadline("n", 10)
            .ok()
            .expect("write");
        let again = DbMeta::open(&path).ok().expect("reopen");
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
        assert!(DbMeta::open(&path).is_err());
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
        assert!(DbMeta::open(&path).is_ok());
    }
}
