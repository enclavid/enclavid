//! The L1: the compositions this worker holds, and the one budget they share
//! with the bundles still streaming in.
//!
//! A workspace more than a cache. A round's child runs its cwasm straight from
//! the entry here, mapping it, so an entry stays for as long as a round holds a
//! [`Lease`] on it — until that round's child has exited, not just until it
//! answers. An entry no round holds stays as well, for the next round of its
//! composition, and goes when another needs its room or once no round has used
//! it for the idle time the host set, at most [`MAX_IDLE`].
//!
//! The map, the order entries go in, the weights and one fill per composition
//! are `quick_cache`'s. What is here is the rest of the budget: the room a
//! bundle reserves before its first byte, taken out of the cache's capacity so
//! the cache makes it by evicting what no round is using, and the wait when
//! rounds are using everything.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use quick_cache::sync::{Cache, PlaceholderGuard};
use quick_cache::{DefaultHashBuilder, Lifecycle, OptionsBuilder, Weighter};
use safe_logger::{debug, reason};
use tokio::sync::Notify;
use tokio::time::Instant;

use engine_executor::admission::l1_entry_weight;
use engine_rpc::{CatalogEntry, ExecError, MAX_DECODED_META_BYTES, META_WEIGHT_MARGIN};
use engine_types::composition::EmbeddedImport;

use crate::cwasm::Cwasm;
use crate::service::Slot;

/// The longest an entry no round has used stays, so that a composition nobody
/// runs any more does not keep its compiled code in this process for good.
/// Going gives its memory back to the kernel to be reused and overwritten in
/// time; it does not clear it.
///
/// The `bundle-idle-secs` setting may shorten it and is refused above it: how
/// soon a consumer's code goes is the host's to choose, how long it may stay is
/// the build's.
pub(crate) const MAX_IDLE: Duration = Duration::from_secs(60 * 60);

/// How often the cache looks for idle entries, or as often as the idle time
/// itself where that is shorter.
pub(crate) const IDLE_SWEEP: Duration = Duration::from_secs(60);

/// One composition's compiled artifact, the L1's value. The cwasm is a single
/// anonymous in-RAM file held by fd — a sealed Linux `memfd` (no filesystem name,
/// RAM-backed, write-sealed) in prod, an unlinked tmpfile in dev — so it is the
/// FLEET's ONE long-lived copy of these bytes: api's stream is written straight
/// into it. Each per-round child receives an fd to THIS file (never a path),
/// open for writing as the memfd was made but sealed against it, so no child
/// can change what the next one maps; the spawn in [`engine_supervisor`] leaves
/// a child no other composition's fd. Freed when the last fd closes — this
/// entry dropping plus any child unmapping.
///
/// The cwasm is plaintext (possible embedded ML weights), but it is NOT scrubbed on
/// drop: SEV-SNP blinds the host to this RAM whether live or freed, and the entry is
/// legitimately resident in the cache for the whole time its composition is in use —
/// so a kernel-level in-guest attacker would read the LIVE copy regardless, and
/// zeroing the freed copy buys almost nothing for a chunk of `unsafe`. (Scrubbing is
/// spent where it pays and is safe: key material via `secrecy`, not bulk plaintext.)
pub(crate) struct CompositionEntry {
    /// The cwasm, sealed and found to be a component ([`Cwasm`]); handed to the
    /// child by fd.
    pub(crate) cwasm: Cwasm,
    /// What this whole entry is charged, in bytes ([`entry_charge`] of the lengths
    /// both blobs streamed in at), so the two metadata fields below are charged
    /// too, subject to the per-entry floor in [`engine_executor::admission`] that
    /// stops a weightless entry from being free.
    pub(crate) charged: u64,
    /// Per-catalog i18n/icons import manifest (registered as strict host `Linker`
    /// instances at prime). Small in every legitimate composition, and NOT small
    /// by construction — it comes verbatim from a caller no leaf can identify, so
    /// it is charged rather than assumed. Shared with every round's `prime`
    /// request, never copied into one.
    pub(crate) embedded_imports: Arc<[EmbeddedImport]>,
    /// Per-component parsed catalogs (the registry-builder inputs). Charged and
    /// shared for the same reasons, and it is the bigger of the two.
    pub(crate) catalogs: Arc<[CatalogEntry]>,
    /// When a round last took or let go of this entry.
    pub(crate) used: LastUsed,
}

/// When a round last took or let go of an entry: what [`Bundles::evict_idle`]
/// reads.
pub(crate) struct LastUsed(Mutex<Instant>);

impl LastUsed {
    pub(crate) fn now() -> Self {
        Self(Mutex::new(Instant::now()))
    }

    fn touch(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn at(&self) -> Instant {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What an entry is charged, from the lengths its cwasm and metadata streamed in
/// at. Every field is charged, not just the cwasm, because every field is
/// retained and every field came from the caller — the metadata at the most its
/// decoded form holds per byte, and never past what the compiler lets one
/// composition's catalogs decode to.
pub(crate) const fn entry_charge(cwasm_len: u64, meta_len: u64) -> u64 {
    let meta = meta_len.saturating_mul(META_WEIGHT_MARGIN);
    let meta = if meta < MAX_DECODED_META_BYTES {
        meta
    } else {
        MAX_DECODED_META_BYTES
    };
    cwasm_len.saturating_add(meta)
}

/// What a fill reserves before its first byte: what the entry it becomes is
/// charged, and the metadata's receive buffer, which grows by doubling and is
/// gone once the metadata is decoded.
pub(crate) const fn fill_charge(cwasm_len: u64, meta_len: u64) -> u64 {
    entry_charge(cwasm_len, meta_len).saturating_add(meta_len.saturating_mul(2))
}

/// What an entry takes out of the budget: its charge, or the per-entry floor if
/// that is more ([`l1_entry_weight`]).
#[derive(Clone, Copy)]
pub(crate) struct ByCharge {
    budget: u64,
    max_entries: u64,
}

impl ByCharge {
    fn of(&self, charged: u64) -> u64 {
        l1_entry_weight(charged, self.budget, self.max_entries)
    }
}

impl Weighter<Slot, Arc<CompositionEntry>> for ByCharge {
    fn weight(&self, _slot: &Slot, entry: &Arc<CompositionEntry>) -> u64 {
        self.of(entry.charged)
    }
}

/// Keeps every entry a round is using: one something holds besides the cache.
///
/// The count is read as the cache evicts, under its shard's write lock, and a
/// round takes its reference under the same shard's read lock — so an entry is
/// never evicted between a round finding it and the round holding it.
#[derive(Clone)]
pub(crate) struct InUse;

impl Lifecycle<Slot, Arc<CompositionEntry>> for InUse {
    type RequestState = ();

    fn is_pinned(&self, _slot: &Slot, entry: &Arc<CompositionEntry>) -> bool {
        Arc::strong_count(entry) > 1
    }
}

type Entries = Cache<Slot, Arc<CompositionEntry>, ByCharge, DefaultHashBuilder, InUse>;

/// A round's claim on filling one slot: while it lives, every other round that
/// misses on the slot waits for it rather than staging its own. Dropped without
/// an entry — refused, stalled, or its caller gone — it hands the claim to one
/// of them.
pub(crate) type Fill<'a> =
    PlaceholderGuard<'a, Slot, Arc<CompositionEntry>, ByCharge, DefaultHashBuilder, InUse>;

/// What a round finds for its slot.
pub(crate) enum Claim<'a> {
    Kept(Lease),
    Fill(Fill<'a>),
}

pub(crate) struct Bundles {
    entries: Entries,
    /// In bytes: the host's setting, which the worker checks at boot holds a
    /// fill of the largest bundle by itself.
    budget: u64,
    /// How an entry or a fill is weighed against it.
    weigh: ByCharge,
    /// What the fills streaming in hold, in bytes. The cache's capacity is the
    /// budget less this, set under this lock.
    reserved: Mutex<u64>,
    /// Told whenever a lease or a reservation is given back: what a fill
    /// waiting for room wakes to.
    released: Arc<Notify>,
}

impl Bundles {
    /// A cache of `budget` bytes holding at most `max_entries` entries, each
    /// charged at least the budget's share of that count.
    pub(crate) fn new(budget: u64, max_entries: u64) -> Self {
        let weigh = ByCharge {
            budget,
            max_entries,
        };
        let options = OptionsBuilder::new()
            .estimated_items_capacity(usize::try_from(max_entries).unwrap_or(usize::MAX))
            .weight_capacity(budget)
            // One shard: the cache divides its capacity between its shards, and
            // one bundle may take most of the whole.
            .shards(1)
            .build()
            .unwrap_or_else(|_| {
                safe_logger::error_and_panic!(
                    "execution-worker: the bundle cache's options do not build. Stopping.",
                    reason!("a constant of the measured build, naming no runtime input")
                )
            });
        Self {
            entries: Cache::with_options(options, weigh, DefaultHashBuilder::default(), InUse),
            budget,
            weigh,
            reserved: Mutex::new(0),
            released: Arc::new(Notify::new()),
        }
    }

    /// A lease on the entry under `slot`, if one is kept.
    pub(crate) fn lease(&self, slot: &Slot) -> Option<Lease> {
        self.entries.get(slot).map(|entry| self.leased(entry))
    }

    /// A lease on the entry under `slot` — once another round's fill of it has
    /// ended, if one is under way — or the claim to fill it. Busy past
    /// `deadline`.
    pub(crate) async fn claim(
        &self,
        slot: &Slot,
        deadline: Instant,
    ) -> Result<Claim<'_>, ExecError> {
        match tokio::time::timeout_at(deadline, self.entries.get_value_or_guard_async(slot)).await {
            Ok(Ok(entry)) => Ok(Claim::Kept(self.leased(entry))),
            Ok(Err(fill)) => Ok(Claim::Fill(fill)),
            Err(_elapsed) => Err(ExecError::Busy),
        }
    }

    /// Room for a fill whose stream declares `cwasm_len` and `meta_len`, out of
    /// the cache's capacity: the cache evicts what no round is using to make it.
    /// What rounds are using it cannot evict, so when that fills the budget the
    /// fill waits for a lease or a reservation to be given back, and answers busy
    /// past `deadline`. The budget holds the largest fill by itself, so only
    /// rounds in progress can keep one out, and only while they run.
    ///
    /// The cache evicts before anyone knows whether the room will come of it: a
    /// fill that goes on to wait, or to answer busy, may still have cost entries
    /// no round was using.
    pub(crate) async fn reserve(
        &self,
        cwasm_len: u64,
        meta_len: u64,
        deadline: Instant,
    ) -> Result<Room<'_>, ExecError> {
        let need = self.weigh.of(fill_charge(cwasm_len, meta_len));
        loop {
            // Taken before the look, so whatever is given back after it wakes
            // this fill.
            let released = self.released.notified();
            if self.try_reserve(need) {
                return Ok(Room {
                    bundles: self,
                    bytes: need,
                });
            }
            if tokio::time::timeout_at(deadline, released).await.is_err() {
                return Err(ExecError::Busy);
            }
        }
    }

    fn try_reserve(&self, need: u64) -> bool {
        let mut reserved = self.reserved();
        let Some(capacity) = reserved
            .checked_add(need)
            .and_then(|held| self.budget.checked_sub(held))
        else {
            return false;
        };
        self.entries.set_capacity(capacity);
        if self.entries.weight() <= capacity {
            *reserved += need;
            true
        } else {
            self.entries.set_capacity(self.budget - *reserved);
            false
        }
    }

    /// Keep what a fill brought under the slot it claimed, out of the room it
    /// reserved, and lease it to the round that filled it.
    ///
    /// Unknown if the claim is no longer in the cache — which takes a removal,
    /// or an insert that bypassed a claim, and nothing here makes either. The
    /// entry would then run outside the budget, so the round ends instead.
    pub(crate) fn keep(
        &self,
        fill: Fill<'_>,
        mut room: Room<'_>,
        entry: CompositionEntry,
    ) -> Result<Lease, ExecError> {
        // A fill reserves the charge of the lengths its stream declares, and an
        // entry is made only of a stream that arrived at exactly those.
        debug_assert!(self.weigh.of(entry.charged) <= room.bytes);
        let lease = self.leased(Arc::new(entry));
        let kept = {
            // The room goes back and the entry takes it in one step: a fill
            // reserving in between could leave the cache no room to insert, and
            // with every entry in use it would go past its capacity rather than
            // refuse. The lease is held already, so the entry is inserted as one
            // a round is using.
            let mut reserved = self.reserved();
            *reserved -= room.bytes;
            room.bytes = 0;
            self.entries.set_capacity(self.budget - *reserved);
            fill.insert(lease.entry.clone()).is_ok()
        };
        // What the reservation held beyond the entry's charge is free now.
        drop(room);
        if !kept {
            debug!("keep: the slot's claim was gone");
            return Err(ExecError::Unknown);
        }
        Ok(lease)
    }

    /// Let go of every entry no round holds and no round has used for `idle`,
    /// and wake the fills waiting for room.
    ///
    /// Under the cache's write lock, which a round takes its reference under
    /// too, so no lease begins while this looks. One that ends while it looks
    /// has marked the entry used before letting go of it, so the entry stays.
    pub(crate) fn evict_idle(&self, idle: Duration) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            Arc::strong_count(entry) > 1 || now.saturating_duration_since(entry.used.at()) < idle
        });
        self.released.notify_waiters();
    }

    fn leased(&self, entry: Arc<CompositionEntry>) -> Lease {
        entry.used.touch();
        Lease {
            entry,
            _released: Released(self.released.clone()),
        }
    }

    fn reserved(&self) -> MutexGuard<'_, u64> {
        self.reserved.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A round's hold on an entry: while it lives the cache keeps the entry
/// ([`InUse`]). The round hands it to the child runner with its child, and the
/// runner lets go of it once the child has exited — a child maps the cwasm for as
/// long as it lives.
///
/// Its fields drop in order: the hold first, then the word to the fills
/// waiting for room, so a fill woken by it finds the entry free.
#[must_use = "dropping a lease lets the cache evict the entry it holds"]
pub(crate) struct Lease {
    entry: Arc<CompositionEntry>,
    _released: Released,
}

impl Lease {
    pub(crate) fn entry(&self) -> &Arc<CompositionEntry> {
        &self.entry
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Before the hold goes: an entry is idle from when its last round lets
        // go of it.
        self.entry.used.touch();
    }
}

struct Released(Arc<Notify>);

impl Drop for Released {
    fn drop(&mut self) {
        self.0.notify_waiters();
    }
}

/// Room a fill holds in the budget while it streams in, given back when dropped.
#[must_use = "dropping the room gives it back before the fill has used it"]
pub(crate) struct Room<'a> {
    bundles: &'a Bundles,
    bytes: u64,
}

impl Drop for Room<'_> {
    fn drop(&mut self) {
        {
            let mut reserved = self.bundles.reserved();
            *reserved -= self.bytes;
            self.bundles
                .entries
                .set_capacity(self.bundles.budget - *reserved);
        }
        self.bundles.released.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::Arc;
    use std::time::Duration;

    use engine_executor::admission::DEFAULT_BUNDLE_CACHE_ENTRIES;
    use engine_rpc::CompositionKey;
    use tokio::time::Instant;

    use super::{
        Bundles, Claim, CompositionEntry, Cwasm, ExecError, LastUsed, Lease,
        MAX_DECODED_META_BYTES, MAX_IDLE, META_WEIGHT_MARGIN, Slot, entry_charge, fill_charge,
    };

    /// A cache of `BUDGET` bytes at the default entry count.
    fn cache() -> Bundles {
        Bundles::new(BUDGET, DEFAULT_BUNDLE_CACHE_ENTRIES)
    }

    const MIB: u64 = 1024 * 1024;
    /// Room for two entries of `ENTRY`, both well above the per-entry floor.
    const BUDGET: u64 = 512 * MIB;
    const ENTRY: u64 = 256 * MIB;
    const WAIT: Duration = Duration::from_secs(10);

    /// A slot of one caller's, its composition named by `name`'s bytes.
    fn slot(name: &str) -> Slot {
        let mut digest = [0u8; 32];
        digest[..name.len()].copy_from_slice(name.as_bytes());
        Slot::of("m", CompositionKey::from_digest(digest))
    }

    fn entry(charged: u64) -> CompositionEntry {
        CompositionEntry {
            cwasm: Cwasm::unchecked(File::open("/dev/null").expect("/dev/null opens")),
            charged,
            embedded_imports: Vec::new().into(),
            catalogs: Vec::new().into(),
            used: LastUsed::now(),
        }
    }

    /// Fill `name` with an entry charged `ENTRY`, as a round does, and hand back
    /// that round's lease.
    async fn fill(bundles: &Bundles, name: &str) -> Lease {
        let Ok(Claim::Fill(fill)) = bundles.claim(&slot(name), Instant::now() + WAIT).await else {
            panic!("{name} is neither kept nor being filled");
        };
        let room = bundles
            .reserve(ENTRY, 0, Instant::now() + WAIT)
            .await
            .expect("there is room");
        bundles
            .keep(fill, room, entry(ENTRY))
            .expect("the claim is kept")
    }

    fn kept(bundles: &Bundles, name: &str) -> bool {
        bundles.lease(&slot(name)).is_some()
    }

    /// Whether `name` is kept, without taking a lease — which would count as
    /// using it.
    fn present(bundles: &Bundles, name: &str) -> bool {
        bundles.entries.contains_key(&slot(name))
    }

    /// An entry no round has used for the idle time goes. One a round holds
    /// stays however long it is held, and is idle from when the round lets go
    /// of it.
    #[tokio::test(start_paused = true)]
    async fn an_entry_idle_past_its_time_goes_and_a_held_one_stays() {
        const IDLE: Duration = MAX_IDLE;
        let second = Duration::from_secs(1);
        let bundles = cache();
        drop(fill(&bundles, "idle").await);
        let held = fill(&bundles, "held").await;

        tokio::time::advance(IDLE - second).await;
        bundles.evict_idle(IDLE);
        assert!(present(&bundles, "idle") && present(&bundles, "held"));
        tokio::time::advance(2 * second).await;
        bundles.evict_idle(IDLE);
        assert!(!present(&bundles, "idle"));
        assert!(present(&bundles, "held"));

        drop(held);
        tokio::time::advance(IDLE - second).await;
        bundles.evict_idle(IDLE);
        assert!(present(&bundles, "held"));
        tokio::time::advance(2 * second).await;
        bundles.evict_idle(IDLE);
        assert!(!present(&bundles, "held"));
        assert_eq!(bundles.entries.weight(), 0);
    }

    /// An entry a round holds stays when a fill needs room; one nobody holds
    /// goes. With every entry held, the fill waits — and gets its room as soon
    /// as a round lets go, from the entry that round held.
    #[tokio::test(start_paused = true)]
    async fn a_held_entry_stays_and_a_fill_waits_for_its_room() {
        let bundles = cache();
        let a = fill(&bundles, "a").await;
        drop(fill(&bundles, "b").await);
        let c = fill(&bundles, "c").await;
        assert!(kept(&bundles, "a"));
        assert!(!kept(&bundles, "b"));

        let started = Instant::now();
        let (room, ()) = tokio::join!(bundles.reserve(ENTRY, 0, started + WAIT), async move {
            tokio::time::sleep(WAIT / 2).await;
            drop(a);
        });
        assert!(room.is_ok());
        assert_eq!(started.elapsed(), WAIT / 2);
        assert!(!kept(&bundles, "a"));
        assert!(kept(&bundles, "c"));
        drop(c);
    }

    /// A fill no room can be made for answers busy at its deadline, and leaves
    /// the cache its whole capacity again.
    #[tokio::test(start_paused = true)]
    async fn a_fill_that_finds_no_room_answers_busy_and_holds_nothing() {
        let bundles = cache();
        let a = fill(&bundles, "a").await;
        let b = fill(&bundles, "b").await;
        let started = Instant::now();
        assert_eq!(
            bundles.reserve(ENTRY, 0, started + WAIT).await.err(),
            Some(ExecError::Busy)
        );
        assert_eq!(started.elapsed(), WAIT);
        assert_eq!(bundles.entries.capacity(), BUDGET);
        assert!(kept(&bundles, "a") && kept(&bundles, "b"));
        drop((a, b));
    }

    /// A fill's room comes out of the cache's capacity while it streams, and
    /// all of it comes back when the fill ends without an entry.
    #[tokio::test]
    async fn a_reservation_is_given_back_whole() {
        let bundles = cache();
        let room = bundles
            .reserve(ENTRY, 0, Instant::now() + WAIT)
            .await
            .expect("there is room");
        assert_eq!(bundles.entries.capacity(), BUDGET - ENTRY);
        drop(room);
        assert_eq!(bundles.entries.capacity(), BUDGET);
    }

    /// However a fill ends without an entry, a round waiting on it wakes to the
    /// claim to fill the slot itself.
    #[tokio::test]
    async fn a_round_waiting_on_a_failed_fill_fills_it_itself() {
        let bundles = cache();
        let deadline = Instant::now() + WAIT;
        let a = slot("a");
        let Ok(Claim::Fill(first)) = bundles.claim(&a, deadline).await else {
            panic!("a is free");
        };
        let (second, ()) = tokio::join!(bundles.claim(&a, deadline), async move {
            tokio::task::yield_now().await;
            drop(first);
        });
        assert!(matches!(second, Ok(Claim::Fill(_))));
    }

    /// A fill that ends with an entry wakes a round waiting on it to the entry
    /// kept, and the cache has its whole capacity again.
    #[tokio::test]
    async fn a_round_waiting_on_a_fill_finds_what_it_kept() {
        let bundles = cache();
        let deadline = Instant::now() + WAIT;
        let a = slot("a");
        let Ok(Claim::Fill(first)) = bundles.claim(&a, deadline).await else {
            panic!("a is free");
        };
        let room = bundles
            .reserve(ENTRY, MIB, deadline)
            .await
            .expect("there is room");
        let (second, lease) = tokio::join!(bundles.claim(&a, deadline), async {
            tokio::task::yield_now().await;
            bundles
                .keep(first, room, entry(ENTRY))
                .expect("the claim is kept")
        });
        assert!(matches!(second, Ok(Claim::Kept(_))));
        assert_eq!(bundles.entries.capacity(), BUDGET);
        assert_eq!(bundles.entries.weight(), ENTRY);
        drop(lease);
    }

    /// An entry is charged for the metadata it keeps, not only for its cwasm: a
    /// MiB of metadata beside a tiny cwasm costs the cache what the margin says it
    /// may decode to.
    #[test]
    fn an_entry_is_charged_for_its_metadata_not_just_its_cwasm() {
        assert_eq!(entry_charge(64, MIB), 64 + META_WEIGHT_MARGIN * MIB);
    }

    /// But never past what one composition's catalogs can decode to, whatever
    /// length its metadata streamed in at — and a fill reserves the metadata's
    /// receive buffer on top.
    #[test]
    fn the_metadata_charge_stops_at_what_catalogs_decode_to() {
        assert_eq!(entry_charge(64, 7 * MIB), 64 + MAX_DECODED_META_BYTES);
        assert_eq!(
            fill_charge(64, 7 * MIB),
            64 + MAX_DECODED_META_BYTES + 14 * MIB
        );
    }

    /// The lease a round takes is to the very entry it found.
    #[tokio::test]
    async fn a_lease_holds_the_entry_it_found() {
        let bundles = cache();
        let lease = fill(&bundles, "a").await;
        let again = bundles.lease(&slot("a")).expect("a is kept");
        assert!(Arc::ptr_eq(lease.entry(), again.entry()));
    }
}
