//! What a decoded `BundleMeta` holds — per byte of its encoding, the figure
//! `META_WEIGHT_MARGIN` rests on, and for a composition at the section cap, the
//! figure `MAX_DECODED_META_BYTES` rests on.
//!
//! A test binary of its own because it counts allocations: the allocator below
//! is this binary's, and it counts per thread, so a measurement sees only the
//! decode it is measuring.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use engine_rpc::{BundleMeta, CatalogEntry, MAX_DECODED_META_BYTES, META_WEIGHT_MARGIN};
use engine_types::embedded::ComponentDecls;
use engine_types::limits::{MAX_DECLARED_DISCLOSURE_FIELDS, MAX_EMBEDDED_SECTION_BYTES};

thread_local! {
    static LIVE: Cell<u64> = const { Cell::new(0) };
    static PEAK: Cell<u64> = const { Cell::new(0) };
}

/// What an allocation of `size` bytes costs: glibc's allocator, which the
/// measured image links, keeps an 8-byte header on each chunk, rounds it up to
/// 16 bytes and never hands out fewer than 32. Past 128 KiB it starts out
/// mapping a block whole, a page at a time; it raises that threshold as such
/// blocks are freed, so counting every block past it as mapped is the dearer
/// of the two and the one modelled.
fn cost(size: usize) -> u64 {
    const MAPPED_FROM: u64 = 128 * 1024;
    let size = size as u64;
    if size >= MAPPED_FROM {
        (size + 16).next_multiple_of(4096)
    } else {
        (size + 8).next_multiple_of(16).max(32)
    }
}

fn grow(n: u64) {
    let _ = LIVE.try_with(|live| {
        live.set(live.get() + n);
        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(live.get())));
    });
}

fn shrink(n: u64) {
    let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(n)));
}

struct Counting;

// SAFETY: every call is passed to `System` unchanged; the counting beside it
// touches only this thread's two cells, which allocate nothing.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(cost(layout.size()));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        shrink(cost(layout.size()));
        unsafe { System.dealloc(ptr, layout) }
    }

    /// Counted as a move: both blocks live at once, which is what a growing
    /// buffer holds at its peak.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(cost(new_size));
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        shrink(cost(layout.size()));
        moved
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// Decode `encoded`; the most that was live above where it started, at any point
/// of the decode or after it.
fn decode_peak(encoded: &[u8]) -> u64 {
    let before = LIVE.with(Cell::get);
    PEAK.with(|peak| peak.set(before));
    let meta: BundleMeta = ciborium::from_reader(encoded).expect("the shape decodes");
    let peak = PEAK.with(Cell::get) - before;
    drop(meta);
    peak
}

#[track_caller]
fn assert_within_margin(encoded: &[u8]) {
    let peak = decode_peak(encoded);
    let bound = encoded.len() as u64 * META_WEIGHT_MARGIN;
    assert!(
        peak <= bound,
        "{} bytes of metadata held {peak} bytes decoded, {:.1} per byte",
        encoded.len(),
        peak as f64 / encoded.len() as f64
    );
}

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// The `i`th two-character string.
fn two(i: usize) -> String {
    let n = ALPHABET.len();
    [ALPHABET[i / n] as char, ALPHABET[i % n] as char]
        .into_iter()
        .collect()
}

/// `components` copies of a catalog, encoded as this crate encodes metadata.
fn encoded(components: usize, decls: impl Fn() -> ComponentDecls) -> Vec<u8> {
    let catalogs = (0..components as u64)
        .map(|i| {
            let mut hash = [0xFF; 32];
            hash[..8].copy_from_slice(&i.to_le_bytes());
            CatalogEntry {
                hash,
                decls: decls(),
            }
        })
        .collect();
    let mut b = Vec::new();
    ciborium::into_writer(
        &BundleMeta {
            embedded_imports: Vec::new(),
            catalogs,
        },
        &mut b,
    )
    .unwrap();
    b
}

/// The shapes metadata takes as api sends it, at their most expensive: tiny
/// disclosure fields, each a `String` in a hash-table slot, in tables sized one
/// past a growth boundary so half their slots stand empty; and catalogs whose
/// texts are a few bytes each.
#[test]
fn honest_metadata_decodes_within_the_margin() {
    // Disclosure fields one past their table's boundary.
    assert_within_margin(&encoded(64, || ComponentDecls {
        disclosure_fields: (0..225).map(two).collect(),
        ..Default::default()
    }));
    // Texts of one language with nothing in it.
    assert_within_margin(&encoded(2000, || ComponentDecls {
        i18n: b"{\"a\":\"\"}".to_vec(),
        ..Default::default()
    }));
}

/// A composition whose embedded sections fill the cap with the shape that costs
/// most decoded per byte of JSON: disclosure fields of two characters, as many
/// as a component may declare, over as many components as the cap leaves room
/// for. What it decodes to stays under the bound the worker charges metadata at
/// most.
#[test]
fn a_composition_at_the_section_cap_decodes_within_its_bound() {
    // A list's brackets, then each field quoted and followed by a comma.
    let list = |fields: usize| 2 + 5 * fields as u64;
    let full = list(MAX_DECLARED_DISCLOSURE_FIELDS);
    let mut section_bytes = 0u64;
    let mut catalogs = Vec::new();
    for i in 0u64.. {
        let fields = if section_bytes + full <= MAX_EMBEDDED_SECTION_BYTES {
            MAX_DECLARED_DISCLOSURE_FIELDS
        } else {
            let left = MAX_EMBEDDED_SECTION_BYTES - section_bytes;
            let fit = left.saturating_sub(2) / 5;
            if fit == 0 {
                break;
            }
            fit as usize
        };
        section_bytes += list(fields);
        let mut hash = [0xFF; 32];
        hash[..8].copy_from_slice(&i.to_le_bytes());
        catalogs.push(CatalogEntry {
            hash,
            decls: ComponentDecls {
                disclosure_fields: (0..fields).map(two).collect(),
                ..Default::default()
            },
        });
        assert!(i < 10_000, "the cap holds a bounded number of components");
    }
    let mut b = Vec::new();
    ciborium::into_writer(
        &BundleMeta {
            embedded_imports: Vec::new(),
            catalogs,
        },
        &mut b,
    )
    .unwrap();
    let peak = decode_peak(&b);
    assert!(
        peak <= MAX_DECODED_META_BYTES,
        "{section_bytes} bytes of sections decode to {peak}, {:.1} per byte",
        peak as f64 / section_bytes as f64
    );
}
