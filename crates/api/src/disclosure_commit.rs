//! Order-INDEPENDENT set-commitment over the disclosure ciphertexts. Used by the
//! persister to maintain `SessionMetadata.disclosure_entry_hashes` (the
//! authoritative leaf list) and by the disclosures handler to verify the
//! host-served list.
//!
//! Replaces the v1 sequential hash CHAIN (`disclosure_hash`). The chain committed
//! to APPEND = policy-EMISSION order, which is a policy→consumer covert channel
//! (`log2(M!)` bits, same class as the field-order shuffle in [`crate::shuffle`]).
//! A set-commitment commits to the SET, not the order, so:
//! It still catches host forge / truncate / swap-with-other-session / inject (any
//! membership change alters the commitment); it deliberately DROPS reorder
//! detection (order is now meaningless — attribution is by session_id + each
//! envelope's field keys, never position).
//! It does NOT close full-snapshot rollback (a coherent old metadata+list pair) —
//! the acknowledged stateless-TEE limit; needs an external freshness oracle.
//!
//! Construction (fixed-32-byte leaves ⇒ no inter-leaf framing needed):
//! ```text
//! e_i = SHA256(DOMAIN_ENTRY  || ciphertext_i)                       // per-entry leaf
//! C   = SHA256(DOMAIN_COMMIT || u64le(len(session_id)) || session_id
//!                            || u64le(count) || sorted(e_0..e_{count-1}))
//! ```
//! The leaves are sorted (raw 32-byte lexicographic) so `C` is a pure function of
//! the multiset — storage order is irrelevant. `count` is bound BEFORE the leaves
//! so truncate/extend is caught and the message is closed (length-extension moot,
//! and the host never sees `C` anyway). `session_id` is length-prefixed so a
//! crafted id cannot bleed into the count field (swap-with-other-session defence).
//! Ties are KEPT (multiset, no dedup): a host duplicating a genuine ciphertext is
//! a count mismatch we catch. A SINGLE [`commit`] fn is shared by create-seed /
//! persister-append / pull-verify, so all three are byte-identical by construction.
//!
//! TCB note: this is plain SHA-256 over a canonical serialization — the SAME
//! minimal assumption (collision / second-preimage resistance) as v1, no new
//! dependency and no algebraic accumulator (hence no generalized-birthday grinding
//! surface, unlike an XOR/sum multiset accumulator). A ristretto255 EC-multiset
//! hash (constant-size metadata, true O(1) append) is a possible future drop-in
//! behind this same `commit` seam, at the cost of a DL+RO assumption.

use sha2::{Digest, Sha256};

/// Domain tag for a per-entry leaf. Distinct from [`DOMAIN_COMMIT`], the v1
/// chain domain (`enclavid-disclosure-chain`), and the consent-screen digest, so
/// a value from one context can never be reinterpreted in another.
const DOMAIN_ENTRY: &[u8] = b"enclavid-disclosure-v2-entry";
/// Domain tag for the top-level set commitment.
const DOMAIN_COMMIT: &[u8] = b"enclavid-disclosure-v2-commit";

fn finalize32(h: Sha256) -> [u8; 32] {
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Per-entry leaf hash of one disclosure ciphertext.
pub fn entry_hash(ciphertext: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_ENTRY);
    h.update(ciphertext);
    finalize32(h)
}

/// The order-independent set commitment over the session's disclosure leaves.
/// Sorting a local copy makes this a pure function of the multiset — call sites
/// need not pre-sort. `leaves.len()` is the disclosure count.
pub fn commit(session_id: &str, leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = leaves.to_vec();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    h.update(DOMAIN_COMMIT);
    h.update((session_id.len() as u64).to_le_bytes());
    h.update(session_id.as_bytes());
    h.update((sorted.len() as u64).to_le_bytes());
    for e in &sorted {
        h.update(e);
    }
    finalize32(h)
}

/// Verify-side convenience: commit over ciphertexts (hashes each to a leaf first).
/// The consumer-pull handler recomputes this over the host-served list and
/// compares to [`commit`] over the AEAD-sealed `disclosure_entry_hashes`.
pub fn commit_from_ciphertexts(session_id: &str, ciphertexts: &[Vec<u8>]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = ciphertexts.iter().map(|c| entry_hash(c)).collect();
    commit(session_id, &leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(cts: &[&[u8]]) -> Vec<[u8; 32]> {
        cts.iter().map(|c| entry_hash(c)).collect()
    }

    #[test]
    fn order_independent() {
        let a = leaves(&[b"one", b"two", b"three"]);
        let mut b = a.clone();
        b.reverse();
        let mut c = a.clone();
        c.swap(0, 2);
        let base = commit("sess", &a);
        assert_eq!(base, commit("sess", &b), "reversed set commits identically");
        assert_eq!(base, commit("sess", &c), "swapped set commits identically");
    }

    #[test]
    fn empty_set_stable() {
        let e1 = commit("sess", &[]);
        let e2 = commit("sess", &[]);
        assert_eq!(e1, e2, "empty-set commitment is deterministic");
        // Non-empty differs from empty.
        assert_ne!(e1, commit("sess", &leaves(&[b"x"])));
    }

    #[test]
    fn session_binding() {
        let l = leaves(&[b"a", b"b"]);
        assert_ne!(
            commit("sess-A", &l),
            commit("sess-B", &l),
            "same leaves under different sessions commit differently"
        );
        // Length-prefixing: a crafted id cannot bleed into the count field.
        assert_ne!(commit("ab", &l), commit("a", &l));
    }

    #[test]
    fn count_binding_truncate_and_inject() {
        let full = leaves(&[b"a", b"b", b"c"]);
        let base = commit("s", &full);
        // Truncate one.
        assert_ne!(base, commit("s", &full[..2]));
        // Inject one.
        let mut more = full.clone();
        more.push(entry_hash(b"d"));
        assert_ne!(base, commit("s", &more));
    }

    #[test]
    fn multiset_ties_change_commitment() {
        let one = leaves(&[b"dup"]);
        let mut two = one.clone();
        two.push(one[0]); // duplicate leaf — a host re-serving a genuine ct
        assert_ne!(
            commit("s", &one),
            commit("s", &two),
            "a duplicated entry changes the count/commitment, not silently absorbed"
        );
    }

    #[test]
    fn round_trip_ciphertexts_vs_leaves() {
        let cts: Vec<Vec<u8>> = vec![b"ct1".to_vec(), b"ct2".to_vec()];
        let via_leaves = commit("s", &leaves(&[b"ct1", b"ct2"]));
        let via_cts = commit_from_ciphertexts("s", &cts);
        assert_eq!(via_leaves, via_cts);
    }
}
