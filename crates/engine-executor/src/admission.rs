//! What may enter the supervisor's L1, and what one entry is charged for its
//! slot.
//!
//! The L1 is a cache the CALLER fills: any attested guest reaching
//! `run_with_bundle` installs an entry under a key it chose, inside its own
//! measurement partition. That partition bounds WHOSE bytes a caller can reach.
//! It bounds nothing about HOW MANY entries a caller installs, and this module is
//! the second bound.
//!
//! It has to be separate from the RAM budget because of two accounting gaps, and
//! they are not the same gap.
//!
//! The first is COUNT. moka enforces `max_capacity` against the weigher's running
//! total, so an entry charged nothing is admitted without limit, and every entry
//! holds an OPEN FILE (its cwasm memfd). What runs out first is then not RAM but
//! the descriptor table, and a worker out of descriptors stops accepting
//! connections and stops spawning children — the whole-worker blast radius the
//! per-round child split exists to bound, reached without escaping anything.
//!
//! The second is WHAT IS WEIGHED. An entry retains its cwasm AND the bundle's
//! `embedded_imports` and `catalogs`, all three taken verbatim from a caller no
//! leaf can identify. Weighing the cwasm alone made the byte budget a cwasm
//! budget: a minimal header with megabytes of catalog was charged almost nothing
//! for memory it kept for the whole idle window. That one is answered in
//! `CompiledBundle::retained_bytes`, which the worker feeds to the weigher; what
//! is here is the rest.
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

/// Ceiling on L1 ENTRIES, enforced through the weigher rather than directly —
/// moka budgets weight, not cardinality, so the entry bound is expressed as "no
/// entry may weigh less than a budget's worth divided by this".
///
/// 512 against the 2 GiB default budget puts the floor at 4 MiB, which is under
/// any real cwasm (7–15 MiB), so a legitimate entry is charged its own size and
/// this number never binds. It binds only on the bundles that provoked it.
///
/// The number is chosen against the DESCRIPTOR table, which is what the entries
/// actually consume, and it is the DOMINANT term in the budget
/// [`fd_budget`] asserts at boot — deliberately, because the cache is the
/// unbounded-by-nature half and the child count is a number the host sets.
pub const L1_MAX_ENTRIES: u64 = 512;

/// Descriptors a live per-round child costs the SUPERVISOR: its half of the
/// socketpair, the pidfd tokio opens per spawn, and headroom for what a spawn
/// holds transiently — the child's end of the pair and the two `/dev/null` opens,
/// all closed once `exec` has happened. Deliberately generous: the number exists
/// to make the boot assertion conservative, not to be exact.
///
/// Note what is NOT counted here and is counted elsewhere: the cwasm fd handed to
/// a child is the L1 ENTRY's, already charged against [`L1_MAX_ENTRIES`].
const FDS_PER_CHILD: u64 = 4;

/// Descriptors the role needs for everything that is neither an L1 entry nor a
/// child: the listener, the health port, one accepted api connection and the
/// runtime's own wakers.
const FD_HEADROOM: u64 = 128;

/// The descriptor budget this role must be able to reach, given how many children
/// it may run at once.
///
/// Stated as a function rather than a constant because the child bound is the
/// host's to set, and the two numbers are only meaningful together: raising
/// `max_children` without the descriptors to back it turns a concurrency knob into
/// a way to wedge the worker at its own peak.
pub fn fd_budget(max_children: u64) -> u64 {
    L1_MAX_ENTRIES + max_children * FDS_PER_CHILD + FD_HEADROOM
}

/// What one L1 entry is charged against the cache's byte budget: its own size, or
/// a floor derived from [`L1_MAX_ENTRIES`], whichever is larger.
///
/// The floor is the whole point. Charging the true size is right for a real cwasm
/// and is exactly wrong for a degenerate one, because a budget that admits an
/// unbounded number of weightless entries is not a budget. At least 1 in any case,
/// so a caller cannot restore the original behaviour by asking the host for a zero
/// budget.
pub fn l1_entry_weight(cwasm_len: u64, budget_bytes: u64) -> u32 {
    let floor = (budget_bytes / L1_MAX_ENTRIES).max(1);
    cwasm_len.max(floor).try_into().unwrap_or(u32::MAX)
}

/// Whether `cwasm` is a wasmtime-serialized COMPONENT, read off its header.
///
/// A header parse, not a deserialization: it reads the ELF identification
/// wasmtime stamps its own artifacts with and decides nothing about whether the
/// body is well-formed. That is the right depth for this side of the split — the
/// supervisor deliberately never deserializes, because `Component::deserialize` is
/// the unsafe sink the disposable child exists to contain. Refusing here costs a
/// header read and keeps a descriptor; refusing in the child costs a spawn and the
/// entry is already installed.
///
/// So it is an ADMISSION check, never a safety one. A caller that wants its bytes
/// run still gets them run, in the child, under the same containment as before.
pub fn is_precompiled_component(cwasm: &[u8]) -> bool {
    matches!(
        wasmtime::Engine::detect_precompiled(cwasm),
        Some(wasmtime::Precompiled::Component)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle the bound was written against: nothing, installed under as many
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
        let weightless = l1_entry_weight(0, BUDGET);
        assert!(weightless > 0);
        let admitted = BUDGET / u64::from(weightless);
        assert!(
            admitted <= L1_MAX_ENTRIES,
            "a weightless entry admits {admitted}, past the {L1_MAX_ENTRIES} the fd budget \
             was sized for"
        );
    }

    /// A real cwasm is above the floor, so the floor never touches it — the cache
    /// still budgets RAM by RAM for every entry that matters.
    #[test]
    fn a_real_cwasm_is_charged_its_own_size() {
        const BUDGET: u64 = 2 * 1024 * 1024 * 1024;
        let real = 12 * 1024 * 1024;
        assert_eq!(u64::from(l1_entry_weight(real, BUDGET)), real);
    }

    /// A host that sets the budget to zero must not get the unbounded behaviour
    /// back through the division.
    #[test]
    fn a_zero_budget_still_charges_something() {
        assert!(l1_entry_weight(0, 0) > 0);
    }

    /// The descriptor budget moves with the child bound, because the two are only
    /// meaningful together.
    #[test]
    fn the_fd_budget_covers_the_l1_and_the_children() {
        assert!(fd_budget(64) > L1_MAX_ENTRIES + 64);
        assert!(fd_budget(256) > fd_budget(64));
    }
}
