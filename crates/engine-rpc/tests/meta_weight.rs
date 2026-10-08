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
use engine_types::embedded::{ComponentDecls, Translation};
use engine_types::limits::{MAX_DECLARED_LOCALIZED, MAX_EMBEDDED_SECTION_BYTES};

thread_local! {
    static LIVE: Cell<u64> = const { Cell::new(0) };
    static PEAK: Cell<u64> = const { Cell::new(0) };
}

/// What an allocation of `size` bytes costs: musl's allocator, which the
/// measured image links, hands out 16-byte units and keeps a 4-byte header in
/// each. Its coarser size classes above 160 bytes are not modelled, which moves
/// nothing here: what dominates is strings of a unit or two and tables past
/// 128 KiB, which musl maps whole.
fn cost(size: usize) -> u64 {
    (size as u64 + 4).next_multiple_of(16)
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

/// The `i`th one-character string.
fn one(i: usize) -> String {
    (ALPHABET[i] as char).to_string()
}

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
/// keys, each a `String` in a hash-table slot, in tables sized one past a growth
/// boundary so half their slots stand empty.
#[test]
fn honest_metadata_decodes_within_the_margin() {
    // i18n keys with no translations: a 49-byte bucket each, for four bytes.
    assert_within_margin(&encoded(64, || ComponentDecls {
        localized: (0..3585).map(|i| (two(i), Vec::new())).collect(),
        ..Default::default()
    }));
    // Disclosure fields and icons one past their tables' boundaries.
    assert_within_margin(&encoded(64, || ComponentDecls {
        disclosure_fields: (0..225).map(two).collect(),
        icons: (0..57).map(two).collect(),
        ..Default::default()
    }));
    // Translations into one-character languages with empty texts.
    assert_within_margin(&encoded(1, || ComponentDecls {
        localized: (0..3585)
            .map(|i| {
                let rows = (0..ALPHABET.len())
                    .map(|l| Translation {
                        language: one(l),
                        text: String::new(),
                    })
                    .collect();
                (two(i), rows)
            })
            .collect(),
        ..Default::default()
    }));
}

/// The `i`th short key: one, two or three characters.
fn short(mut i: usize) -> String {
    let n = ALPHABET.len();
    let mut s = String::new();
    loop {
        s.push(ALPHABET[i % n] as char);
        i /= n;
        if i == 0 {
            return s;
        }
    }
}

/// A composition whose embedded sections fill the cap with the shape that costs
/// most decoded per byte of JSON: keys with one tiny translation each, as many as
/// a component may declare, over as many components as the cap leaves room for.
/// What it decodes to stays under the bound the worker charges metadata at most.
#[test]
fn a_composition_at_the_section_cap_decodes_within_its_bound() {
    let entry = |k: &str| format!("\"{k}\":{{\"a\":\"\"}},").len() as u64;
    let mut section_bytes = 0u64;
    let mut catalogs = Vec::new();
    'components: for c in 0u64.. {
        // A component's i18n section is one JSON object: its braces, then entries.
        section_bytes += 2;
        let mut localized = std::collections::HashMap::new();
        for i in 0..MAX_DECLARED_LOCALIZED {
            let key = short(i);
            let cost = entry(&key);
            if section_bytes + cost > MAX_EMBEDDED_SECTION_BYTES {
                if !localized.is_empty() {
                    catalogs.push(localized);
                }
                break 'components;
            }
            section_bytes += cost;
            localized.insert(
                key,
                vec![Translation {
                    language: "a".to_owned(),
                    text: String::new(),
                }],
            );
        }
        catalogs.push(localized);
        assert!(c < 1000, "the cap holds a bounded number of components");
    }
    let mut b = Vec::new();
    ciborium::into_writer(
        &BundleMeta {
            embedded_imports: Vec::new(),
            catalogs: catalogs
                .into_iter()
                .enumerate()
                .map(|(i, localized)| {
                    let mut hash = [0xFF; 32];
                    hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    CatalogEntry {
                        hash,
                        decls: ComponentDecls {
                            localized,
                            ..Default::default()
                        },
                    }
                })
                .collect(),
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
