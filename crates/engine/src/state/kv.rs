//! Codec for the policy's `enclavid:host/storage` map ⇄ the opaque sealed
//! `state` blob.
//!
//! The policy's per-round storage is a `BTreeMap<String, Vec<u8>>`; between
//! rounds it is serialized here into the opaque `SessionState::state` bytes
//! the runtime AEAD-seals. The encoding is deterministic (keys sorted, fixed
//! length prefixes) so the plaintext size is content-determined — which is
//! what `POLICY_MAX_STATE_BYTES` and its covert-channel bound reason about.
//! No serde dependency: a handful of length-prefixed records.

use std::collections::BTreeMap;

/// Serialize the storage map into the opaque state blob. Entries are
/// emitted in sorted-key order as `u32 key_len | key | u32 val_len | val`
/// (little-endian lengths).
pub(crate) fn encode(kv: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in kv {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// Encoded byte length of one entry — matches [`encode`]'s per-entry
/// framing (`u32 key_len | key | u32 val_len | val`), i.e. 8 length-prefix
/// bytes plus the key and value.
pub(crate) fn entry_len(key: &str, value: &[u8]) -> usize {
    8 + key.len() + value.len()
}

/// Total encoded length of the map — equal to `encode(kv).len()` without
/// allocating the blob. Lets `storage::set` bound the map incrementally so
/// host memory stays capped DURING a round, not only at commit.
pub(crate) fn encoded_len(kv: &BTreeMap<String, Vec<u8>>) -> usize {
    kv.iter().map(|(k, v)| entry_len(k, v)).sum()
}

/// Parse an opaque state blob back into the storage map. An empty blob
/// (genesis) yields an empty map. A malformed blob (truncated record, bad
/// UTF-8 key) is an error — the host sealed these bytes, so corruption means
/// a broken seal, not policy input.
pub(crate) fn decode(bytes: &[u8]) -> wasmtime::Result<BTreeMap<String, Vec<u8>>> {
    let mut kv = BTreeMap::new();
    let mut i = 0;
    while i < bytes.len() {
        let key_len = take_u32(bytes, &mut i)? as usize;
        let key = take_bytes(bytes, &mut i, key_len)?;
        let key = String::from_utf8(key.to_vec())
            .map_err(|_| wasmtime::Error::msg("storage blob: non-UTF-8 key"))?;
        let val_len = take_u32(bytes, &mut i)? as usize;
        let val = take_bytes(bytes, &mut i, val_len)?.to_vec();
        kv.insert(key, val);
    }
    Ok(kv)
}

fn take_u32(bytes: &[u8], i: &mut usize) -> wasmtime::Result<u32> {
    let end = *i + 4;
    let slice = bytes
        .get(*i..end)
        .ok_or_else(|| wasmtime::Error::msg("storage blob: truncated length prefix"))?;
    *i = end;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn take_bytes<'a>(bytes: &'a [u8], i: &mut usize, len: usize) -> wasmtime::Result<&'a [u8]> {
    let end = *i + len;
    let slice = bytes
        .get(*i..end)
        .ok_or_else(|| wasmtime::Error::msg("storage blob: truncated record"))?;
    *i = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blob_is_empty_map() {
        assert!(decode(&[]).unwrap().is_empty());
        assert!(encode(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn encoded_len_matches_encode() {
        let mut kv = BTreeMap::new();
        kv.insert("step".to_string(), vec![3]);
        kv.insert("addr".to_string(), b"hello world".to_vec());
        kv.insert("empty".to_string(), Vec::new());
        assert_eq!(encoded_len(&kv), encode(&kv).len());
    }

    #[test]
    fn round_trips() {
        let mut kv = BTreeMap::new();
        kv.insert("step".to_string(), vec![3]);
        kv.insert("age_ok".to_string(), b"1".to_vec());
        kv.insert("empty".to_string(), Vec::new());
        let decoded = decode(&encode(&kv)).unwrap();
        assert_eq!(decoded, kv);
    }

    #[test]
    fn deterministic_by_sorted_key() {
        let mut a = BTreeMap::new();
        a.insert("b".to_string(), vec![1]);
        a.insert("a".to_string(), vec![2]);
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), vec![2]);
        b.insert("b".to_string(), vec![1]);
        assert_eq!(encode(&a), encode(&b));
    }

    #[test]
    fn truncated_blob_errors() {
        // Declares a 4-byte key but supplies none.
        let bytes = 4u32.to_le_bytes().to_vec();
        assert!(decode(&bytes).is_err());
    }
}
