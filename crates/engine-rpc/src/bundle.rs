//! The compiled-composition artifact — shared by BOTH boundaries.
//!
//! A [`CompiledBundle`] is the compile boundary's OUTPUT and the api L2 cache
//! entry, and it is what the execute boundary caches on a cache miss — split
//! there into the cwasm and a [`BundleMeta`], streamed beside the call. So it is
//! defined ungated (`any(compile, execute)`) and both feature halves name it. It
//! pulls only the wasmtime-free `engine-types` leaf — an execution-worker
//! referencing it links `engine-types` (which it needs anyway: `ComponentDecls`
//! to rebuild the embedded registry, `EmbeddedImport` to register the strict
//! resolvers), but still NO Cranelift.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use engine_types::composition::EmbeddedImport;
use engine_types::embedded::ComponentDecls;
use engine_types::limits::MAX_EMBEDDED_SECTION_BYTES;

/// The longest cwasm the execute hop accepts, in bytes.
///
/// 1.5 GiB: room for embedded model weights, against some 66 MB for the largest
/// composition measured — a componentize-js policy with its plugins. It is also
/// what one cache fill can make the worker write before the digest is checked,
/// and the worker reserves what a fill will write out of its cache budget before
/// the first byte, so this is a bound on RAM and not only on length.
pub const MAX_CWASM_BYTES: u64 = 3 * 512 * 1024 * 1024;

/// What the child's `prime` request carries besides the metadata: the fd path,
/// the field names, CBOR framing and remoc's own envelope.
const PRIME_HEADROOM: u64 = 64 * 1024;

/// How many bytes of metadata one byte of embedded section can become.
///
/// Measured at 2.55 at the cap, in the shape that grows most: translations into
/// one-character languages with empty texts, where `"a":"",` — seven bytes of
/// JSON — is an eighteen-byte `Translation` once its field names are encoded, so
/// no catalog of them passes 18/7. Every other shape shrinks: a key or a set
/// member loses its quotes and comma.
const META_BYTES_PER_SECTION_BYTE: u64 = 3;

/// What the metadata carries that no section accounts for: each component's
/// catalog hash and field names, and the import manifest. About 455 bytes for a
/// component with two routed imports, so this is some two thousand components.
const META_COMPONENT_ROOM: u64 = 1024 * 1024;

/// The longest encoded [`BundleMeta`] the execute hop accepts, in bytes: 7 MiB.
///
/// Set by what the compiler admits. A composition's embedded sections are held
/// to `MAX_EMBEDDED_SECTION_BYTES` before any is parsed, and their catalogs
/// encode to at most [`META_BYTES_PER_SECTION_BYTE`] times that; the rest is
/// [`META_COMPONENT_ROOM`]. Metadata that outgrows it without its sections doing
/// so — thousands of components, or import versions spelled at length — the
/// compile child refuses as well, so no bundle past it is cached.
///
/// It also fits where the metadata goes next. The worker hands it to every
/// round's child inside a [`BundleRef`], and `prime` crosses that seam as ONE
/// remoc item under the same per-item limit as every leg. The worker re-encodes
/// what it decoded, and one form grows on the way: a 32-byte hash, which the
/// decoder takes as a 34-byte byte string and this crate writes as an array of
/// up to 65 — about 1.4 times on entries that hold nothing else. The assertion
/// below keeps half again this bound, and the rest of the request, under the
/// limit.
pub const MAX_BUNDLE_META_BYTES: u64 =
    META_BYTES_PER_SECTION_BYTE * MAX_EMBEDDED_SECTION_BYTES + META_COMPONENT_ROOM;

const _: () = assert!(
    MAX_BUNDLE_META_BYTES * 3 / 2 + PRIME_HEADROOM <= remoc::rch::DEFAULT_MAX_ITEM_SIZE as u64,
    "metadata at its bound, re-encoded, would not fit the child's prime request"
);

/// The most memory a [`BundleMeta`] holds, decoding or decoded, per byte of its
/// encoding as this crate writes it. An execution-worker charges an L1 entry its
/// cwasm's length plus this times its metadata's, never more than
/// [`MAX_DECODED_META_BYTES`].
///
/// Not a few, as a JSON-sized intuition suggests: a tiny key costs more as a
/// hash-table slot than as bytes. An i18n key with no translations is two bytes
/// encoded and a 49-byte bucket decoded, in a table that can stand half empty
/// one past a growth boundary. Measured (`tests/meta_weight.rs`, counting musl's
/// 16-byte unit and 4-byte header): 31.8 at the worst for metadata as this crate
/// encodes it. A realistic catalog decodes to two or three times its encoding.
///
/// An encoding written by hand to size tables for members that then collapse
/// into one can reach about 57. Only a peer other than api writes one, and what
/// such a peer can make this worker hold is availability the host can take from
/// it anyway.
pub const META_WEIGHT_MARGIN: u64 = 32;

/// The most memory the decoded catalogs of one composition hold, in bytes:
/// thirty-two times what the compiler lets its embedded sections carry, 64 MiB.
///
/// What fixes it is the section cap, not the encoding: whatever shape a catalog
/// takes, it is at most `MAX_EMBEDDED_SECTION_BYTES` of JSON. The costliest shape
/// per byte of JSON is a key with one tiny translation — `"ab":{"a":""},`,
/// fourteen bytes, decodes to a hash-table slot, two `String`s and a `Vec` — and
/// a composition whose sections hold nothing else decodes to some twenty-one
/// times their length (`tests/meta_weight.rs`). A realistic catalog decodes to
/// about twice.
pub const MAX_DECODED_META_BYTES: u64 = 32 * MAX_EMBEDDED_SECTION_BYTES;

/// A freshly compiled composition: the wasmtime-serialized fused component
/// (`cwasm`) plus the host-side metadata compile drops (the per-catalog
/// i18n/icons import manifest and the parsed per-component catalogs). This is
/// BOTH the compile RPC return value AND the L2 cache bundle
/// (`enclavid-api::cwasm_cache`) AND what api fills an execution-worker's cache
/// with after a miss — one compiled artifact, three consumers, so a cold
/// compile, an L2 hit, and a worker's cache fill all reconstruct through the
/// same fields. The fill does not carry it whole: the execute door streams the
/// cwasm and a [`BundleMeta`] beside the call (`BundleStream`).
///
/// `deny_unknown_fields` + no `#[serde(default)]` is deliberate: the L2 bundle
/// is written and read by ONE binary version, so any schema drift must
/// fail-closed to a cache miss, never silently default. (The compile reply is
/// between same-version fleet nodes; the same fail-closed shape is correct there
/// too — a version-skewed node should error, not misinterpret.)
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledBundle {
    /// wasmtime-serialized fused component — the amortized Cranelift codegen.
    /// `serde_bytes` so ciborium encodes it as one CBOR byte string, not a
    /// 7M-element integer array (which cost ~hundreds of ms per transfer over the
    /// api hop, the child hop, AND to seal into L2).
    #[serde(with = "serde_bytes")]
    pub cwasm: Vec<u8>,
    /// Per-catalog i18n / icons import manifest (lost in compile; needed to
    /// register the host `Linker` instances at run time).
    pub embedded_imports: Vec<EmbeddedImport>,
    /// Per-component parsed catalogs, composition order (policy first) — the
    /// exact registry-builder inputs.
    pub catalogs: Vec<CatalogEntry>,
}

/// The non-code half of a [`CompiledBundle`]: what the execute hop streams beside
/// the cwasm, and what an L1 entry keeps beside its file.
///
/// `deny_unknown_fields` for the reason [`CompiledBundle`] carries it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleMeta {
    /// Same as [`CompiledBundle::embedded_imports`].
    pub embedded_imports: Vec<EmbeddedImport>,
    /// Same as [`CompiledBundle::catalogs`].
    pub catalogs: Vec<CatalogEntry>,
}

/// A [`BundleMeta`] by reference: the same fields under the same names, so the
/// same bytes, from a bundle that keeps its own.
#[derive(Serialize)]
struct MetaView<'a> {
    embedded_imports: &'a [EmbeddedImport],
    catalogs: &'a [CatalogEntry],
}

impl CompiledBundle {
    /// This bundle's metadata encoded as the execute hop streams it — the bytes
    /// `BundleStream` frames, and that [`MAX_BUNDLE_META_BYTES`] bounds. `None`
    /// if it does not encode.
    pub fn encoded_meta(&self) -> Option<Vec<u8>> {
        let mut meta = Vec::new();
        ciborium::into_writer(
            &MetaView {
                embedded_imports: &self.embedded_imports,
                catalogs: &self.catalogs,
            },
            &mut meta,
        )
        .ok()?;
        Some(meta)
    }
}

/// One component's `(content_hash, parsed catalog)` — a registry-builder input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub hash: [u8; 32],
    pub decls: ComponentDecls,
}

/// The child-`prime` payload for the MMAP delivery path: the 7-15 MiB `cwasm` is
/// NOT shipped over the child hop — the child MMAPs it via
/// `Component::deserialize_file`, so `prime` carries only a host-local PATH to it
/// plus the small metadata. `cwasm_path` names an inherited fd the supervisor
/// installed before exec (`/proc/self/fd/N`, backed by an anonymous cwasm memfd);
/// the child just treats it as a path. Keeps the big blob off remoc AND lets
/// several children of the same composition share its read-only code pages.
///
/// The metadata is shared rather than owned, so the worker builds one for every
/// round from its L1 entry without copying the catalogs: a decoded catalog can
/// hold tens of times its encoding ([`META_WEIGHT_MARGIN`]), and a copy per
/// running round would sit in the supervisor, outside every limit a child is
/// held to. On the wire it is the plain list either way.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRef {
    /// Host-local path the child feeds to `Component::deserialize_file` (mmap) —
    /// its inherited cwasm fd, e.g. `/proc/self/fd/3`.
    pub cwasm_path: String,
    /// Per-catalog i18n/icons import manifest (needed to register the strict
    /// host `Linker` instances) — same as [`CompiledBundle::embedded_imports`].
    pub embedded_imports: Arc<[EmbeddedImport]>,
    /// Per-component parsed catalogs (the registry-builder inputs) — same as
    /// [`CompiledBundle::catalogs`].
    pub catalogs: Arc<[CatalogEntry]>,
}

#[cfg(test)]
pub(crate) fn sample_bundle() -> CompiledBundle {
    use engine_types::composition::EmbeddedIface;
    let mut decls = ComponentDecls::default();
    decls.disclosure_fields.insert("dob".to_string());
    decls.icons.insert("passport".to_string());
    CompiledBundle {
        cwasm: vec![1, 2, 3, 4],
        embedded_imports: vec![EmbeddedImport {
            instance_name: "embedded-slot:abcd/i18n".to_string(),
            catalog_hash: [7u8; 32],
            iface: EmbeddedIface::I18n,
            version: "0.1.0".to_string(),
        }],
        catalogs: vec![CatalogEntry {
            hash: [9u8; 32],
            decls,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_types::composition::EmbeddedIface;
    use engine_types::embedded::Translation;
    use serde::Serialize;
    use std::fmt::Write;

    fn encode<T: Serialize>(v: &T) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    #[test]
    fn bundle_round_trips() {
        let bytes = encode(&sample_bundle());
        let back: CompiledBundle = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(back.cwasm, vec![1, 2, 3, 4]);
        assert_eq!(back.embedded_imports.len(), 1);
        assert_eq!(back.embedded_imports[0].catalog_hash, [7u8; 32]);
        assert_eq!(back.catalogs.len(), 1);
        assert!(back.catalogs[0].decls.disclosure_fields.contains("dob"));
    }

    fn sample_meta() -> BundleMeta {
        let CompiledBundle {
            embedded_imports,
            catalogs,
            ..
        } = sample_bundle();
        BundleMeta {
            embedded_imports,
            catalogs,
        }
    }

    #[test]
    fn meta_round_trips() {
        let back: BundleMeta = ciborium::from_reader(&encode(&sample_meta())[..]).unwrap();
        assert_eq!(back.embedded_imports.len(), 1);
        assert_eq!(back.embedded_imports[0].catalog_hash, [7u8; 32]);
        assert_eq!(back.catalogs.len(), 1);
        assert!(back.catalogs[0].decls.disclosure_fields.contains("dob"));
    }

    /// Same-version peers on both ends: a field this build does not know is skew,
    /// and fails closed rather than caching half of what was meant.
    #[test]
    fn meta_deny_unknown_fields() {
        #[derive(Serialize)]
        struct MetaPlus {
            embedded_imports: Vec<EmbeddedImport>,
            catalogs: Vec<CatalogEntry>,
            future_field: u32,
        }
        let m = sample_meta();
        let plus = MetaPlus {
            embedded_imports: m.embedded_imports,
            catalogs: m.catalogs,
            future_field: 42,
        };
        assert!(ciborium::from_reader::<BundleMeta, _>(&encode(&plus)[..]).is_err());
    }

    /// The import manifest a compiled component carries: one routed i18n and one
    /// routed icons import, named the way the compiler names them.
    fn routed_imports(hash: [u8; 32]) -> Vec<EmbeddedImport> {
        let slug: String = hash[..16].iter().map(|b| format!("{b:02x}")).collect();
        [
            (EmbeddedIface::I18n, "i18n"),
            (EmbeddedIface::Icons, "icons"),
        ]
        .into_iter()
        .map(|(iface, name)| EmbeddedImport {
            instance_name: format!("embedded-slot:h{slug}-0-1-0/{name}"),
            catalog_hash: hash,
            iface,
            version: "0.1.0".to_string(),
        })
        .collect()
    }

    /// The section shape that grows most from JSON to CBOR, a whole i18n section
    /// of it at the cap, encodes within its share of the bound — every printable
    /// ASCII character a language, so the key count stays one the compiler
    /// admits.
    #[test]
    fn catalogs_at_the_section_cap_encode_within_their_share() {
        let languages: Vec<char> = (' '..='~').filter(|c| !matches!(c, '"' | '\\')).collect();
        let cap = MAX_EMBEDDED_SECTION_BYTES as usize;
        let mut json = String::from("{");
        let mut decls = ComponentDecls::default();
        for key in 0.. {
            let mut entry = format!("\"k{key}\":{{");
            for l in &languages {
                write!(entry, "\"{l}\":\"\",").unwrap();
            }
            entry.pop();
            entry.push_str("},");
            if json.len() + entry.len() > cap {
                break;
            }
            json.push_str(&entry);
            let rows = languages
                .iter()
                .map(|l| Translation {
                    language: l.to_string(),
                    text: String::new(),
                })
                .collect();
            decls.localized.insert(format!("k{key}"), rows);
        }
        json.pop();
        json.push('}');
        assert!(json.len() <= cap);
        assert!(decls.localized.len() <= engine_types::limits::MAX_DECLARED_LOCALIZED);
        let encoded = encode(&BundleMeta {
            embedded_imports: Vec::new(),
            catalogs: vec![CatalogEntry {
                hash: [0xFF; 32],
                decls,
            }],
        });
        assert!(
            encoded.len() as u64 <= META_BYTES_PER_SECTION_BYTE * json.len() as u64,
            "{} bytes of section encode to {}",
            json.len(),
            encoded.len()
        );
    }

    /// What a component costs the metadata with no catalog at all fits
    /// [`META_COMPONENT_ROOM`] for two thousand components.
    #[test]
    fn two_thousand_components_fit_the_component_room() {
        let mut embedded_imports = Vec::new();
        let mut catalogs = Vec::new();
        for i in 0..2000u64 {
            let mut hash = [0xFF; 32];
            hash[..8].copy_from_slice(&i.to_le_bytes());
            embedded_imports.extend(routed_imports(hash));
            catalogs.push(CatalogEntry {
                hash,
                decls: ComponentDecls::default(),
            });
        }
        let encoded = encode(&BundleMeta {
            embedded_imports,
            catalogs,
        });
        assert!(
            encoded.len() as u64 <= META_COMPONENT_ROOM,
            "two thousand empty components encode to {} bytes",
            encoded.len()
        );
    }

    /// The bundle's own encoding of its metadata is the metadata's: what the
    /// compile child measures is what the execute hop frames and decodes.
    #[test]
    fn a_bundles_encoded_meta_is_its_meta() {
        let encoded = sample_bundle().encoded_meta().expect("it encodes");
        assert_eq!(encoded, encode(&sample_meta()));
    }

    /// L2 guard: an EXTRA field (bundle written by a newer binary) must fail to
    /// decode → cache miss / version-skew error, not a silent partial read.
    #[test]
    fn deny_unknown_fields_rejects_extra() {
        #[derive(Serialize)]
        struct BundlePlus {
            cwasm: Vec<u8>,
            embedded_imports: Vec<EmbeddedImport>,
            catalogs: Vec<CatalogEntry>,
            future_field: u32,
        }
        let b = sample_bundle();
        let plus = BundlePlus {
            cwasm: b.cwasm,
            embedded_imports: b.embedded_imports,
            catalogs: b.catalogs,
            future_field: 42,
        };
        assert!(ciborium::from_reader::<CompiledBundle, _>(&encode(&plus)[..]).is_err());
    }
}
