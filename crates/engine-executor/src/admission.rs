//! What may enter the supervisor's L1, and what one entry is charged for its
//! slot.
//!
//! The L1 is a cache the CALLER fills: any attested guest reaching
//! `run_with_bundle` fills an entry under a key it chose, inside its own
//! measurement partition. That partition bounds WHOSE bytes a caller can reach.
//! It bounds nothing about HOW MANY entries a caller fills, and this module is
//! the second bound.
//!
//! It has to be separate from the RAM budget because of two accounting gaps, and
//! they are not the same gap.
//!
//! The first is COUNT. The budget is a sum of what entries are charged, so an
//! entry charged nothing is admitted without limit, and every entry
//! holds an OPEN FILE (its cwasm memfd). What runs out first is then not RAM but
//! the descriptor table, and a worker out of descriptors stops accepting
//! connections and stops spawning children — the whole-worker blast radius the
//! per-round child split exists to bound, reached without escaping anything.
//!
//! The second is WHAT IS WEIGHED. An entry retains its cwasm AND the bundle's
//! `embedded_imports` and `catalogs`, all three taken verbatim from a caller no
//! leaf can identify. Weighing the cwasm alone made the byte budget a cwasm
//! budget: a minimal header with megabytes of catalog was charged almost nothing
//! for memory it kept for as long as it was kept. That one is answered where
//! the entry is made: the worker charges it the cwasm's length plus the
//! metadata's, both as they streamed in, the metadata's times
//! `engine_rpc::META_WEIGHT_MARGIN` — the most a decoded catalog holds per byte
//! of its encoding. What is here is the rest.
//!
//! Two answers, deliberately independent:
//!
//!   * [`is_precompiled_component`] refuses bytes that are not a composition at
//!     all. The cheaper and the more honest of the two — a zero-length cwasm is
//!     not a small composition, and an entry no child could ever MMAP has no
//!     business holding a descriptor. It is a HEADER read, so it says nothing
//!     about the body: a crafted header passes.
//!   * [`l1_entry_weight`] charges every entry a FLOOR, so the byte budget bounds
//!     the entry count as well. This one covers what the first cannot, and a
//!     crafted header is exactly that case.
//!
//! And what is not an entry YET. A bundle streams in at its sender's pace, and
//! until it has arrived whole it is a staging file, a buffer and a handler. What
//! it will hold is reserved out of the cache's own budget before its first byte
//! — the staged cwasm, which the admission check reads in place (see
//! [`is_precompiled_component`]); the metadata as received, in a buffer grown by
//! doubling; and the metadata decoded — so the cache and the fills streaming
//! into it stay within that one budget together, and each fill is charged at
//! least the floor an entry is, which bounds how many stream at once the way it
//! bounds the entries. An entry a round's child runs from is not evicted until
//! that child has exited, so what the children map is inside the budget too.
//!
//! And the bound on what the cache does not hold at all: the rounds and their
//! children. A child is given memory as it touches it; nothing is reserved for
//! it up front. The kernel holds the children together to [`children_total`] —
//! this guest's memory less the cache, a base, and what the supervisor holds for
//! each child's round — and each child alone to the round's max
//! ([`DEFAULT_ROUND_MAX_BYTES`]), killing a child past either rather than
//! refusing it memory. The rounds waiting for a child are held to
//! [`rounds_held`]. A round that finds no place to wait answers busy at once;
//! one that within the capacity wait ([`DEFAULT_CAPACITY_WAIT_SECS`]) finds no
//! child free, or no room for one more ([`DEFAULT_ROUND_HEADROOM_BYTES`]),
//! answers busy before anything is spawned.
//!
//! The numbers that are choices — how many, how much, how long — are the
//! host's settings, each with a default here; the worker takes them from the
//! host at launch, outside its measurement, and reads them once. The
//! numbers that describe what the code holds are constants.

use hatch_client::{MAX_CLIP_BYTES, SEALED_STATE_PLAINTEXT_BYTES};

/// Bound on L1 ENTRIES unless the host says otherwise (the
/// `bundle-cache-entries` setting), enforced through the charge rather than
/// directly — the budget counts bytes, not entries, so the entry bound is
/// expressed as "no entry may be charged less than a budget's worth divided by
/// this".
///
/// 512 against the 2 GiB default budget puts the floor at 4 MiB, which is under
/// any real cwasm (7–15 MiB), so a legitimate entry is charged its own size and
/// this number never binds. It binds only on the bundles that provoked it. A
/// count that puts the floor above a real cwasm charges every entry the floor,
/// and the cache holds fewer compositions than its bytes would.
///
/// The number is chosen against the DESCRIPTOR table, which is what the entries
/// actually consume, and it is the DOMINANT term in the budget
/// [`fd_budget`] asserts at boot — deliberately, because the cache is the
/// unbounded-by-nature half. It covers the fills streaming in as well: each
/// reserves at least the floor out of the same budget, and holds one
/// descriptor, its staging file, which is the one its entry keeps.
pub const DEFAULT_BUNDLE_CACHE_ENTRIES: u64 = 512;

/// Descriptors a per-round child costs the SUPERVISOR: its half of the
/// socketpair, the pidfd tokio opens per spawn, and headroom for what a spawn
/// holds transiently — the child's end of the pair, the two `/dev/null` opens and
/// the process list of the group made for it, which the child writes itself
/// into, all closed once `exec` has happened. Plus, in a debug build, the one
/// its group's peak is read through, for as long as the child lives.
/// Deliberately generous: the number exists to make the boot assertion
/// conservative, not to be exact.
///
/// Note what is NOT counted here and is counted elsewhere: the cwasm fd handed to
/// a child is the L1 ENTRY's, already counted in the cache's entries. The
/// memory group's files read around a spawn are opened and closed within it, a
/// few at a time, inside [`FD_HEADROOM`].
const FDS_PER_CHILD: u64 = 7;

/// Descriptors the role needs for everything that is neither an L1 entry nor a
/// child: the listener, the health port, one accepted api connection and the
/// runtime's own wakers.
const FD_HEADROOM: u64 = 128;

/// What a running child's round holds in THIS process, reasoned from the code
/// rather than measured: the round's own request until its handler returns —
/// the clip until it is sent, the state frame and the state opened from it,
/// about 15 MiB — a relayed `media_load` blob in both its encodings, the
/// metadata as `prime` encodes it, and the framed state. About 45 MiB, rounded
/// up.
///
/// Reserved rather than held by the kernel. It sits in the supervisor's own
/// memory group, the root, and a limit there would put the kill on the worker
/// and every round in it. Bounded instead by how many rounds the worker holds
/// at once ([`rounds_held`]). The consumer's catalogs are not part of it: a
/// round primes its child from the L1 entry's own, shared rather than copied,
/// and only their encoding is the round's — under half again
/// `MAX_BUNDLE_META_BYTES`, which the worker's re-encoding can grow to, and sent
/// before the round relays anything.
const SUPERVISOR_ROUND_BYTES: u64 = 48 * 1024 * 1024;

/// What the supervisor reserves for each child it may run: that child's round
/// as this process holds it ([`SUPERVISOR_ROUND_BYTES`]), and the
/// `waiting_per_child` rounds waiting behind it ([`QUEUED_ROUND_BYTES`] each).
/// Taken out of the memory before the children's total is set, so a higher
/// child bound is a smaller total.
pub fn supervisor_per_child(waiting_per_child: usize) -> u64 {
    (waiting_per_child as u64)
        .saturating_mul(QUEUED_ROUND_BYTES)
        .saturating_add(SUPERVISOR_ROUND_BYTES)
}

/// What a round's process holds of its own, beside what its composition
/// touches — reasoned from the code rather than measured, about 75 MiB of it
/// named:
///
///   * the clip, held whole: up to `MAX_CLIP_BYTES` (12 MiB) as received, again
///     as the blobs it decodes into, and once more as the copy a host function
///     hands the policy — about 36 MiB;
///   * state frames of 1.25 MiB: the one received, the one returned, the
///     prompt, and the encode `session_change` makes — about 6 MiB;
///   * the engine, the deserialized component's metadata, the async fiber
///     stack, and the process itself — about 30 MiB.
///
/// The rest is for what grows with the composition and what the kernel charges
/// the round besides: the media memo, which keeps every distinct capture the
/// round loads; the consumer's catalogs as decoded, twice — the reference and
/// the registry built from it — which is tens of MiB for catalogs at
/// `MAX_EMBEDDED_SECTION_BYTES` split into tiny keys; page tables, thread stacks
/// and the socket buffers the round sends. Not charged to the round at all: the
/// cwasm's own pages, which the supervisor wrote and every child of one
/// composition maps — only the pages a round writes over become its own.
///
/// A fact about the code, so not a setting: the worker refuses a round max that
/// leaves the composition nothing above it, since every round there would end
/// at the max and be answered as its policy's failure.
pub const ROUND_PROCESS_BYTES: u64 = 128 * 1024 * 1024;

/// The most memory one round may hold, unless the host says otherwise
/// (the `round-max-bytes` setting): every linear memory its
/// composition touches — policy and pinned plugins together, however many
/// there are — and everything else its process holds beside them, counted by
/// the pages it touches rather than by what it reserves.
///
/// Held by the kernel, not by wasmtime. In the measured image each round runs
/// in a process of its own, in a memory group with this as its `memory.max`
/// (`engine_supervisor::Cgroups`), and nothing in that process can
/// step around it — not a plugin count, not a table, not a host structure the
/// policy fills. The kernel does not refuse memory at a limit, it kills: a
/// round past this ends there and is answered as the policy's failure, the same
/// answer a trap gets. A refused `memory.grow` ended the round the same way, so
/// a store-level limiter in front of this one would only be a second number for
/// the same outcome, and one that charged linear memory alone. A build without
/// that group — a developer's machine, every test — holds a round's memory to
/// nothing.
///
/// [`ROUND_PROCESS_BYTES`] of it is the process's; the 256 MiB above that is
/// the composition's, sized so that ML-bearing work (decoded JPEG frames, ONNX
/// intermediates) does not trip on it. An availability setting like the rest:
/// the host choosing it decides how much a round may hold, which is a promise
/// about the service. Set low, it ends rounds as their policy's failure; what
/// the host learns from where they end is set out in `engine_types::limits`.
/// A debug build logs each round's peak as its group empties
/// (`engine_supervisor`, `debug` feature), which is what to set it from.
pub const DEFAULT_ROUND_MAX_BYTES: u64 = ROUND_PROCESS_BYTES + 256 * 1024 * 1024;

/// What must be free before one more child is started — under the children's
/// total, and in the guest's available memory — read before each spawn — unless
/// the host says otherwise (the `round-headroom-bytes` setting).
///
/// About an honest round's own cost with a clip at its bound — the 75 MiB or
/// so of process [`ROUND_PROCESS_BYTES`] names — plus room for the policy's own
/// working memory. Reasoned, not measured; a debug build logs each round's peak
/// as its group empties, which is what to set it from.
///
/// A gate, not a reservation: several children can pass on the same reading,
/// and a round may grow past it once started. The kernel's limits are what
/// hold. What the gate buys is where an overload lands: when rounds run larger
/// than the child bound was chosen for, the round that would not fit answers
/// busy before anything starts, rather than a running one being killed for it.
/// So an availability setting: set low, an overload kills running rounds; set
/// high, rounds answer busy while memory is free. Never above the round's max,
/// which the worker checks at boot.
pub const DEFAULT_ROUND_HEADROOM_BYTES: u64 = 128 * 1024 * 1024;

// The defaults pass the worker's own boot checks: the gate never asks for more
// room than one child may hold, and the max leaves the composition room.
const _: () = assert!(DEFAULT_ROUND_HEADROOM_BYTES <= DEFAULT_ROUND_MAX_BYTES);
const _: () = assert!(DEFAULT_ROUND_MAX_BYTES > ROUND_PROCESS_BYTES);

/// What a round holds in this supervisor while it waits — for a fill slot, for
/// another round's fill of the same composition, or for a child: its request as
/// decoded. A clip at its bound, the state frame and
/// the state opened from it, and the props; about 15 MiB, rounded up.
const QUEUED_ROUND_BYTES: u64 = 16 * 1024 * 1024;

// A waiting round's reserve holds its request's bulk: the clip, and the state
// twice — framed, and opened from the frame.
const _: () = assert!(
    (MAX_CLIP_BYTES + 2 * SEALED_STATE_PLAINTEXT_BYTES) as u64 <= QUEUED_ROUND_BYTES,
    "a waiting round's reserve is under its request's bulk"
);

/// How many rounds may wait behind each child the worker can run, unless the
/// host says otherwise (the `waiting-per-child` setting).
///
/// One: a child that ends finds the next round already here, so the children
/// stay busy under load, and every waiting round is reserved with the child it
/// waits behind (see [`supervisor_per_child`]). Deeper would let more of a
/// burst wait instead of answering busy at once, at a request's memory each;
/// none answers busy whenever every child is running.
pub const DEFAULT_WAITING_PER_CHILD: usize = 1;

/// How many rounds the worker holds at once when it can run `children`: each
/// child's own and the `waiting_per_child` waiting behind it.
///
/// Counted from the moment a round's handler starts, because by then its request
/// is decoded and held, whatever it goes on to wait for. A round past the count
/// answers busy at once and lets its request go. Without the count, what waiting
/// rounds hold would be bounded only by how many their callers send at once —
/// every one held, under exactly the load that keeps the children full.
pub fn rounds_held(children: usize, waiting_per_child: usize) -> usize {
    children.saturating_mul(waiting_per_child.saturating_add(1))
}

/// What the guest needs before it holds a single entry, fill or child: the
/// kernel's own allocations and reserve, the image's files, which live in RAM,
/// and this process at rest — unless the host says otherwise
/// (the `base-reserve-bytes` setting).
///
/// One thing lands here that nothing else reserves, and this worker does not
/// bound it: requests a connection is still receiving, or that a handler is
/// about to refuse, are held before any round counts them — a few per
/// connection, at most the per-item limit each. Small while callers send what
/// api does; when they do not, the guest's available memory runs short, and the
/// room a child needs is read there too ([`DEFAULT_ROUND_HEADROOM_BYTES`]), so
/// the next round answers busy instead.
///
/// An availability setting: set low, the guest's own kernel kills to make room
/// when that grows; set high, the children's total is that much smaller.
pub const DEFAULT_BASE_RESERVE_BYTES: u64 = 256 * 1024 * 1024;

/// What the round children may hold together: `physical` less the L1's
/// `l1_budget` — which holds the fills streaming into the cache as well as its
/// entries — the `base_reserve`, and [`supervisor_per_child`] for each of
/// `children` with `waiting_per_child` behind it. The kernel holds the children
/// to it as one total, and each alone to the round's max.
///
/// Derived from the memory the guest has rather than configured beside it,
/// because the guest's size is chosen where it is launched and is not part of
/// its measurement. Set once, at boot, and never lowered: the kernel meets a
/// lowered limit by killing until what is held fits. Saturating, so a guest
/// smaller than its reserves leaves the children nothing rather than wrapping;
/// a total that cannot hold one child at its max is one the worker refuses to
/// boot with.
pub fn children_total(
    physical: u64,
    l1_budget: u64,
    base_reserve: u64,
    children: u64,
    waiting_per_child: usize,
) -> u64 {
    physical
        .saturating_sub(l1_budget)
        .saturating_sub(base_reserve)
        .saturating_sub(children.saturating_mul(supervisor_per_child(waiting_per_child)))
}

/// How long a round waits for room — in the cache, for another round's fill of
/// the same composition, or a child's slot and room for one more child — before
/// it answers busy, unless the host says otherwise
/// (the `capacity-wait-secs` setting).
///
/// Short against the round's own deadline: rounds turn over in seconds, so past
/// this the worker is saturated, not briefly full. Answering at once costs the
/// applicant a retry, while waiting longer costs them a response that does not
/// start in time, which counts against api at the gateway. A round that brings
/// its bundle waits twice — for its composition in the cache, then for a child's
/// slot — so its child may start up to twice this late, and the round's own
/// deadline runs from there.
pub const DEFAULT_CAPACITY_WAIT_SECS: u64 = 10;

/// The descriptor budget this role must be able to reach, given how many children
/// it may run at once and how many entries its cache may hold
/// ([`DEFAULT_BUNDLE_CACHE_ENTRIES`]). The entries and the fills streaming in are
/// one term.
///
/// Stated as a function rather than a constant because both counts are the
/// host's to set, and they are only meaningful together with the descriptors:
/// raising either without the descriptors to back it turns a capacity knob into
/// a way to wedge the worker at its own peak.
pub fn fd_budget(max_children: u64, cache_entries: u64) -> u64 {
    cache_entries
        .saturating_add(max_children.saturating_mul(FDS_PER_CHILD))
        .saturating_add(FD_HEADROOM)
}

/// What one L1 entry is charged against the cache's byte budget: what it holds
/// (`charged`, which the worker derives from what streamed in), or a floor of the
/// budget divided by the entries it may hold ([`DEFAULT_BUNDLE_CACHE_ENTRIES`]),
/// whichever is larger.
///
/// The floor is the whole point. Charging the true size is right for a real cwasm
/// and is exactly wrong for a degenerate one, because a budget that admits an
/// unbounded number of weightless entries is not a budget. Rounded up, so that a
/// count which does not divide the budget still admits no more than itself. At
/// least 1 in any case, so a caller cannot restore the original behaviour by
/// asking the host for a zero budget, nor by a count of zero.
pub fn l1_entry_weight(charged: u64, budget_bytes: u64, entries: u64) -> u64 {
    charged.max(budget_bytes.div_ceil(entries.max(1)).max(1))
}

/// Whether `cwasm` is a wasmtime-serialized COMPONENT, read off its header.
///
/// A header parse, not a deserialization: it reads the ELF identification
/// wasmtime stamps its own artifacts with and decides nothing about whether the
/// body is well-formed. That is the right depth for this side of the split — the
/// supervisor deliberately never deserializes, because `Component::deserialize` is
/// the unsafe sink the disposable child exists to contain. Refusing here costs a
/// header read and keeps a descriptor; refusing in the child costs a spawn and the
/// entry is already in the cache.
///
/// So it is an ADMISSION check, never a safety one. A caller that wants its bytes
/// run still gets them run, in the child, under the same containment as before.
///
/// A slice, and deliberately not wasmtime's file variant. That one parses through
/// a read cache that copies out every distinct range the ELF headers name and
/// keeps each copy, and the parse reads every `SHT_SYMTAB_SHNDX` section linked to
/// the symbol table however many the headers declare — so a file whose section
/// headers name it a thousand times over would make this process allocate a
/// thousand times its length. Parsing a slice copies nothing, and on a cache fill
/// the slice is a read-only mapping of the sealed file, so the check costs no
/// copy of the cwasm at all.
pub fn is_precompiled_component(cwasm: &[u8]) -> bool {
    matches!(
        wasmtime::Engine::detect_precompiled(cwasm),
        Some(wasmtime::Precompiled::Component)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle the bound was written against: nothing, cached under as many
    /// keys as the caller cares to name.
    #[test]
    fn an_empty_cwasm_is_not_a_composition() {
        assert!(!is_precompiled_component(&[]));
    }

    /// Nor is anything else a caller might send. The positive case is asserted
    /// against a REAL compiled artifact in `tests/happy_path.rs`, where one
    /// already exists — writing the header by hand here would only test this
    /// file's guess at wasmtime's format.
    #[test]
    fn arbitrary_bytes_are_not_a_composition() {
        assert!(!is_precompiled_component(b"cwasm"));
        assert!(!is_precompiled_component(&[0u8; 4096]));
        // A plain (non-precompiled) wasm module's magic — the input most likely to
        // be mistaken for one.
        assert!(!is_precompiled_component(b"\0asm\x01\0\0\0"));
    }

    /// The property the floor exists for: whatever a caller sends, the byte budget
    /// runs out before the entry count does.
    #[test]
    fn the_budget_bounds_the_entry_count() {
        const BUDGET: u64 = 2 * 1024 * 1024 * 1024;
        for entries in [1, 7, DEFAULT_BUNDLE_CACHE_ENTRIES, 100_000] {
            let weightless = l1_entry_weight(0, BUDGET, entries);
            assert!(weightless > 0);
            let admitted = BUDGET / weightless;
            assert!(
                admitted <= entries,
                "a weightless entry admits {admitted}, past the {entries} the fd budget \
                 was sized for"
            );
        }
    }

    /// A real cwasm is above the floor, so the floor never touches it — the cache
    /// still budgets RAM by RAM for every entry that matters.
    #[test]
    fn a_real_cwasm_is_charged_its_own_size() {
        const BUDGET: u64 = 2 * 1024 * 1024 * 1024;
        let real = 12 * 1024 * 1024;
        assert_eq!(
            l1_entry_weight(real, BUDGET, DEFAULT_BUNDLE_CACHE_ENTRIES),
            real
        );
    }

    /// A host that sets the budget or the count to zero must not get the
    /// unbounded behaviour back through the division.
    #[test]
    fn a_zero_budget_still_charges_something() {
        assert!(l1_entry_weight(0, 0, DEFAULT_BUNDLE_CACHE_ENTRIES) > 0);
        assert!(l1_entry_weight(0, 1 << 30, 0) > 0);
    }

    const MIB: u64 = 1024 * 1024;

    const BASE: u64 = DEFAULT_BASE_RESERVE_BYTES;
    const WAITING: usize = DEFAULT_WAITING_PER_CHILD;

    /// What every guest holds before its first child.
    const RESERVES: u64 = 2048 * MIB + BASE;

    /// Each child's share in this process carries the rounds waiting behind it,
    /// however many the host lets wait — and saturates rather than wrapping.
    #[test]
    fn each_childs_share_carries_the_rounds_waiting_behind_it() {
        assert_eq!(supervisor_per_child(0), SUPERVISOR_ROUND_BYTES);
        assert_eq!(
            supervisor_per_child(3),
            SUPERVISOR_ROUND_BYTES + 3 * QUEUED_ROUND_BYTES
        );
        assert_eq!(supervisor_per_child(usize::MAX), u64::MAX);
    }

    /// Below its reserves a guest leaves the children nothing — and at the
    /// extremes the arithmetic saturates rather than wrapping into a large total.
    #[test]
    fn memory_under_the_reserves_leaves_the_children_nothing() {
        assert_eq!(children_total(0, 0, 0, 0, 0), 0);
        // A guest launched with 3 GiB, as its kernel reports it, beside the
        // cache's default budget and twelve children.
        assert_eq!(children_total(2809 * MIB, 2048 * MIB, BASE, 12, WAITING), 0);
        assert_eq!(children_total(u64::MAX, u64::MAX, 0, 0, 0), 0);
        assert_eq!(children_total(u64::MAX, 0, u64::MAX, 0, 0), 0);
        assert_eq!(children_total(u64::MAX, 0, 0, u64::MAX, 0), 0);
        assert_eq!(children_total(u64::MAX, 0, 0, 1, usize::MAX), 0);
    }

    /// Every child the worker may run takes its round's share out of the total
    /// before any child holds a byte — the share is this process's, not the
    /// child's, and nothing would hold it to a share taken later.
    #[test]
    fn each_child_bound_reserves_its_round_in_the_supervisor() {
        let total =
            |children| children_total(RESERVES + 1024 * MIB, 2048 * MIB, BASE, children, WAITING);
        assert_eq!(total(0), 1024 * MIB);
        assert_eq!(total(1), 1024 * MIB - supervisor_per_child(WAITING));
        assert_eq!(total(16), 0);
    }

    /// Every round held beyond the children is one waiting behind a child — and
    /// the count saturates rather than wrapping into a small one.
    #[test]
    fn the_rounds_held_are_the_children_and_those_waiting_behind_them() {
        assert_eq!(rounds_held(0, WAITING), 0);
        assert_eq!(rounds_held(8, 0), 8);
        assert_eq!(rounds_held(8, WAITING), 8 * (1 + WAITING));
        assert_eq!(rounds_held(usize::MAX, WAITING), usize::MAX);
        assert_eq!(rounds_held(2, usize::MAX), usize::MAX);
    }

    /// The descriptor budget moves with the child bound, because the two are only
    /// meaningful together — and saturates rather than wrapping into a small one.
    #[test]
    fn the_fd_budget_covers_the_l1_and_the_children() {
        const ENTRIES: u64 = DEFAULT_BUNDLE_CACHE_ENTRIES;
        assert!(fd_budget(64, ENTRIES) >= ENTRIES + 64 * FDS_PER_CHILD);
        assert!(fd_budget(256, ENTRIES) > fd_budget(64, ENTRIES));
        assert!(fd_budget(64, 2 * ENTRIES) > fd_budget(64, ENTRIES));
        assert_eq!(fd_budget(u64::MAX, ENTRIES), u64::MAX);
        assert_eq!(fd_budget(64, u64::MAX), u64::MAX);
    }
}
