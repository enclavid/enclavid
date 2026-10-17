//! The session store's payloads — what [`SessionStoreService`](crate::SessionStoreService)
//! takes and gives:
//!
//! ```text
//! read(id, ReadRequest)             -> ReadResponse
//! write(id, WriteRequest, deadline) -> WriteResponse | SessionError::VersionMismatch
//! exists(id)                        -> bool
//! ```
//!
//! They are NOT the sealed domain types: `SessionMetadata` / `SessionState`
//! are CBOR-encoded TEE-side (see `session-types`) then AEAD-sealed, and the
//! storage-CVM never sees anything but the opaque `value` bytes carried
//! inside these envelopes.

use serde::{Deserialize, Serialize};

// Every byte field below is a CBOR byte string. ciborium writes a bare
// `Vec<u8>` element by element — two bytes for every byte over 0x17 — so
// sealed bytes cost about 1.9x their length on the wire, and on the storage
// leg that was enough to push one round's write past remoc's item limit.

/// `Vec<Vec<u8>>` as a sequence of byte strings: `serde_bytes` covers one
/// buffer, not a list of them.
mod byte_list {
    pub fn serialize<S: serde::Serializer>(items: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(items.iter().map(|item| serde_bytes::Bytes::new(item)))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let items: Vec<serde_bytes::ByteBuf> = serde::Deserialize::deserialize(d)?;
        Ok(items
            .into_iter()
            .map(serde_bytes::ByteBuf::into_vec)
            .collect())
    }
}

/// Scalar fields — one value per (session, field), each AEAD-sealed
/// TEE-side, so opaque ciphertext to the storage-CVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobField {
    Metadata,
    State,
}

/// List fields — a per-(session, field) collection of values. The disclosure
/// field is an UNORDERED SET (see [`ListField::Disclosure`]); the store may
/// return entries in any order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ListField {
    /// Age-sealed disclosure entries (opaque ciphertext to the store), as an
    /// UNORDERED SET — the TEE commits to the set, not the order, so order is
    /// neither preserved nor meaningful.
    Disclosure,
}

/// Selector for one field in a read. Picks scalar, list, or keyed-media
/// shape. (Not `Copy` — the `Media` variant carries its blob-hash key.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldSelector {
    Blob(BlobField),
    List(ListField),
    /// One media blob, keyed by its content hash (32-byte BLAKE3). Lives in
    /// a per-session media table, separate from the scalar fields; reads
    /// return a `Slot::Scalar` (absent → `None`).
    Media(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    /// Fields to read. **Empty = version probe**: the response carries
    /// the current version and no slots (used to read the version
    /// without paying any field bandwidth).
    pub fields: Vec<FieldSelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    /// Same length + order as `ReadRequest.fields`; each slot's variant
    /// matches the selector's kind at that index.
    pub slots: Vec<Slot>,
    /// Current session version; 0 if the session does not exist.
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Slot {
    Scalar(ScalarSlot),
    List(ListSlot),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalarSlot {
    /// `None` = field absent; `Some(empty)` = present-but-empty. The
    /// distinction is load-bearing: a default-valued `SessionMetadata`
    /// serializes to empty bytes, and must not read back as "absent".
    #[serde(with = "serde_bytes")]
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSlot {
    /// All entries. Order is UNSPECIFIED (the disclosure field is a set);
    /// consumers must not rely on position. Empty when absent or never written.
    #[serde(with = "byte_list")]
    pub items: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    /// Ops applied atomically, in one transaction. Mixing scalar writes
    /// and list appends in one call is the common case (state update +
    /// accumulated disclosure entries).
    pub ops: Vec<Op>,
    /// Optimistic-concurrency gate. `Some(v)` applies only if the
    /// session's current version == v (else `VersionMismatch`). `None`
    /// means "the session must not exist yet" (used by session creation).
    pub expected_version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    /// Replace a scalar field's value.
    Blob(BlobWrite),
    /// Append to a list field.
    ListAppend(ListAppend),
    /// Write one media blob under its content-hash key into the per-session
    /// media table. Idempotent — the key IS the content, so a re-write is a
    /// no-op-equivalent overwrite of identical bytes.
    MediaWrite(MediaWrite),
    /// Drop the state, every media blob and every disclosure, keeping the
    /// session's metadata and version — the `/reset` path. In order with the
    /// ops beside it, so under the same version check and in the same commit.
    Reset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobWrite {
    pub field: BlobField,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaWrite {
    /// Content-hash key (32-byte BLAKE3 of the sealed blob's plaintext).
    #[serde(with = "serde_bytes")]
    pub blob_key: Vec<u8>,
    /// Sealed blob bytes (double-AEAD ciphertext).
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAppend {
    pub field: ListField,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResponse {
    /// Session version after the write. Callers chain subsequent writes
    /// by feeding this back as the next `expected_version`.
    pub new_version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes past 0x17, which is nearly every byte of a ciphertext: the ones an
    /// integer array would spend two bytes on.
    fn sealed() -> Vec<u8> {
        vec![0xff; 1 << 16]
    }

    fn encode<T: Serialize>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        buf
    }

    #[test]
    fn a_sealed_byte_crosses_as_one_byte() {
        let write = WriteRequest {
            ops: vec![
                Op::Blob(BlobWrite {
                    field: BlobField::State,
                    value: sealed(),
                }),
                Op::MediaWrite(MediaWrite {
                    blob_key: vec![0xff; 32],
                    value: sealed(),
                }),
                Op::ListAppend(ListAppend {
                    field: ListField::Disclosure,
                    value: sealed(),
                }),
            ],
            expected_version: Some(1),
        };
        assert!(encode(&write).len() < 3 * sealed().len() + 256);

        let read = ReadResponse {
            slots: vec![
                Slot::Scalar(ScalarSlot {
                    value: Some(sealed()),
                }),
                Slot::Scalar(ScalarSlot { value: None }),
                Slot::List(ListSlot {
                    items: vec![sealed(), Vec::new()],
                }),
            ],
            version: 1,
        };
        let wire = encode(&read);
        assert!(wire.len() < 2 * sealed().len() + 256);
        let back: ReadResponse = ciborium::from_reader(wire.as_slice()).unwrap();
        assert_eq!(back.slots, read.slots);
    }
}
