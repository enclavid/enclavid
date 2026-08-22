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

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, params};

use super::StoreErr;

/// Absolute `deadline` per session, indexed for the range sweep.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS deadlines(session_id TEXT PRIMARY KEY, deadline INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS deadlines_by_time ON deadlines(deadline);";

pub(super) struct DbMeta {
    conn: Mutex<Connection>,
}

impl DbMeta {
    /// Open (creating if absent) the shared index at `path`. Durable commits
    /// (`synchronous=FULL` + `fullfsync`) so a deadline row is durable before the
    /// session that relies on it commits (see the create ordering in
    /// [`super::SessionStore::write`]).
    pub(super) fn open(path: &Path) -> Result<DbMeta, StoreErr> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(DbMeta {
            conn: Mutex::new(conn),
        })
    }

    /// Record the absolute deadline for `id` (its own durable commit).
    /// Idempotent — `INSERT OR REPLACE`.
    pub(super) fn put_deadline(&self, id: &str, deadline: u64) -> Result<(), StoreErr> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO deadlines(session_id, deadline) VALUES(?1, ?2)",
            params![id, deadline as i64],
        )?;
        Ok(())
    }

    /// The session ids whose deadline is `<= now`, up to `max`, earliest first
    /// (indexed range scan).
    pub(super) fn expired(&self, now: u64, max: usize) -> Result<Vec<String>, StoreErr> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT session_id FROM deadlines WHERE deadline <= ?1 ORDER BY deadline LIMIT ?2",
        )?;
        let ids = stmt
            .query_map(params![now as i64, max as i64], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Drop the given session ids from the index in one commit. No-op on empty.
    pub(super) fn remove(&self, ids: &[String]) -> Result<(), StoreErr> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        for id in ids {
            tx.execute("DELETE FROM deadlines WHERE session_id = ?1", params![id])?;
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
