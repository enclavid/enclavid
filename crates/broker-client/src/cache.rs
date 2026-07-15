//! L2 compiled-artifact (`cwasm`) cache client.
//!
//! Talks to the broker `/cache/{key}` blob endpoints. Unlike the session
//! store, a cache entry is NOT session- or applicant-scoped: it is a
//! compiled composition shared across every session (and restart) of
//! THIS TEE instance, so it is sealed under a **single** TEE-only key
//! (an HKDF subkey of `tee_seal_key`), never the double-AEAD /
//! applicant-token layering that would pin it to one session.
//!
//! Two HKDF subkeys, domain-separated from each other and from the AEAD
//! usage of `tee_seal_key`:
//!   * **seal key** — AEAD-seals the bundle; the host stores opaque
//!     ciphertext it cannot read.
//!   * **filename key** — labels the blob as `hex(HKDF(filename_key,
//!     cache_id))`, an identity-hiding name so the host can't tie a blob
//!     to a composition by its key (defence-in-depth; the host already
//!     observes composition refs on the OCI pull path).
//!
//! `cache_id` is an OPAQUE string the api layer owns (composition hash +
//! cache-format epoch). This client never parses it — it is the AAD and
//! the filename-label input, so ANY change to it (new composition, bumped
//! format version) yields a different blob name AND a different AAD,
//! cleanly partitioning incompatible entries.
//!
//! Read semantics are **best-effort**: a blob that won't AEAD-open
//! (foreign, stale-epoch, torn write, host tamper) is a MISS
//! (`Ok(None)`), not an error — the compile is always re-derivable from
//! the cold path. Only a genuine transport failure surfaces as `Err`.

use hyper::StatusCode;

use enclavid_crypto::{aead, derive_key};

use crate::boundary::{self, AuthN, AuthZ, Covert, Replay};
use crate::error::BridgeError;
use crate::reason;
use crate::transport::BrokerClient;

/// HKDF info label for the AEAD seal subkey.
const SEAL_INFO: &[u8] = b"enclavid.cwasm-cache.seal.v1";
/// HKDF info label for the blob-name subkey.
const FILENAME_INFO: &[u8] = b"enclavid.cwasm-cache.filename.v1";

/// The two derived subkeys plus the pure crypto/labelling logic — no
/// transport, so it is unit-testable in isolation.
#[derive(Clone, Copy)]
struct CacheKeys {
    seal_key: [u8; 32],
    filename_key: [u8; 32],
}

impl CacheKeys {
    fn from_master(tee_seal_key: &[u8; 32]) -> Self {
        Self {
            seal_key: derive_key(tee_seal_key, SEAL_INFO),
            filename_key: derive_key(tee_seal_key, FILENAME_INFO),
        }
    }

    /// Identity-hiding blob name for `cache_id`: `hex(HKDF(filename_key,
    /// cache_id))`. A keyed PRF, so the host sees only pseudo-random hex
    /// and cannot invert it to the composition. Pure hex ⇒ the broker's
    /// path-traversal guard accepts it.
    fn blob_name(&self, cache_id: &str) -> String {
        hex::encode(derive_key(&self.filename_key, cache_id.as_bytes()))
    }

    /// AEAD-seal `bundle` under the seal subkey with `cache_id` as AAD.
    fn seal_bundle(&self, cache_id: &str, bundle: &[u8]) -> Result<Vec<u8>, BridgeError> {
        aead::seal(bundle, &self.seal_key, cache_id.as_bytes()).map_err(Into::into)
    }

    /// AEAD-open `sealed` under the seal subkey with `cache_id` as AAD.
    /// `None` on any authentication failure — the caller treats that as a
    /// cache miss (foreign / stale / torn / tampered blob).
    fn open_bundle(&self, cache_id: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        aead::open(sealed, &self.seal_key, cache_id.as_bytes()).ok()
    }
}

/// Broker-backed L2 cache client. Cheap to clone (shares the broker
/// connection pool; keys are 64 bytes inline).
#[derive(Clone)]
pub struct CacheStore {
    broker: BrokerClient,
    keys: CacheKeys,
}

impl CacheStore {
    pub fn new(broker: BrokerClient, tee_seal_key: &[u8; 32]) -> Self {
        Self {
            broker,
            keys: CacheKeys::from_master(tee_seal_key),
        }
    }

    /// Seal `bundle` and store it under `cache_id`. Overwrites any
    /// existing blob (content-addressed: same bytes, or a fresh compile
    /// replacing a stale one).
    pub async fn store(&self, cache_id: &str, bundle: Vec<u8>) -> Result<(), BridgeError> {
        let sealed = self.keys.seal_bundle(cache_id, &bundle)?;
        // Cross the outbound boundary: the sealed blob's three concerns
        // are all closed here — see each reason.
        let bytes: Vec<u8> = boundary::outbound::to_untrusted(sealed)
            .vouch_unchecked::<AuthN, _>(reason!(
                "cwasm-cache blob is AEAD-sealed under a TEE-only HKDF subkey of \
                 tee_seal_key; the host stores opaque ciphertext it cannot read"
            ))
            .vouch_unchecked::<AuthZ, _>(reason!(
                "the cache is TEE-internal compile amortization, not a per-consumer \
                 disclosure; there is no recipient-authorization dimension to gate"
            ))
            .vouch_unchecked::<Covert, _>(reason!(
                "blob size is a deterministic function of the consumer-chosen \
                 composition (policy+plugins), which the host already observes via \
                 its OCI pulls; it carries no applicant/covert data"
            ))
            .into_inner();
        let path = format!("/cache/{}", self.keys.blob_name(cache_id));
        let resp = self.broker.post(&path, bytes).await?;
        match resp.status {
            StatusCode::OK => Ok(()),
            s => Err(BridgeError::Transport(format!("cache store: status {s}"))),
        }
    }

    /// Load and open the blob for `cache_id`. `Ok(None)` = miss (404 or a
    /// blob that won't open); `Err` only on genuine transport failure.
    pub async fn load(&self, cache_id: &str) -> Result<Option<Vec<u8>>, BridgeError> {
        let path = format!("/cache/{}", self.keys.blob_name(cache_id));
        let resp = self.broker.get(&path).await?;
        match resp.status {
            StatusCode::OK => match self.keys.open_bundle(cache_id, &resp.body) {
                Some(plain) => {
                    // Inbound boundary: all three concerns closed here.
                    let opened: Vec<u8> = boundary::inbound::from_untrusted(plain)
                        .trust_unchecked::<AuthN, _>(reason!(
                            "AEAD-open under the TEE-only cache seal key just \
                             succeeded — cryptographic authentication that only bytes \
                             this TEE sealed can open"
                        ))
                        .trust_unchecked::<AuthZ, _>(reason!(
                            "cache is TEE-internal compile amortization; no \
                             per-recipient authorization dimension"
                        ))
                        .trust_unchecked::<Replay, _>(reason!(
                            "a stale/replayed blob under this content+format-addressed \
                             key is a prior compile of the SAME composition (identical \
                             meaning) or wasmtime-incompatible and rejected at \
                             deserialize — never a different policy"
                        ))
                        .into_inner();
                    Ok(Some(opened))
                }
                None => Ok(None),
            },
            StatusCode::NOT_FOUND => Ok(None),
            s => Err(BridgeError::Transport(format!("cache load: status {s}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(master: [u8; 32]) -> CacheKeys {
        CacheKeys::from_master(&master)
    }

    #[test]
    fn blob_name_deterministic_and_scoped() {
        let k = keys([1u8; 32]);
        let a = k.blob_name("comp-x.v1");
        // Deterministic (cross-session / cross-restart sharing depends on it).
        assert_eq!(a, k.blob_name("comp-x.v1"));
        assert_eq!(a.len(), 64, "hex sha256 label");
        // A different composition or a bumped format epoch → different name.
        assert_ne!(a, k.blob_name("comp-y.v1"));
        assert_ne!(a, k.blob_name("comp-x.v2"));
        // A different instance master → different name (no cross-instance
        // name collision that could leak which composition is cached).
        assert_ne!(a, keys([2u8; 32]).blob_name("comp-x.v1"));
    }

    #[test]
    fn seal_open_round_trips_and_rejects_foreign() {
        let k = keys([9u8; 32]);
        let sealed = k.seal_bundle("comp.v1", b"cwasm-bundle-bytes").unwrap();
        assert_eq!(
            k.open_bundle("comp.v1", &sealed).as_deref(),
            Some(&b"cwasm-bundle-bytes"[..]),
            "round-trips under the same cache_id"
        );
        // Wrong cache_id (AAD mismatch = stale epoch / other composition) → miss.
        assert!(k.open_bundle("comp.v2", &sealed).is_none());
        // Another instance's key can't open this blob → miss.
        assert!(keys([8u8; 32]).open_bundle("comp.v1", &sealed).is_none());
        // Garbage / torn bytes → miss, never a panic.
        assert!(k.open_bundle("comp.v1", b"garbage").is_none());
        assert!(k.open_bundle("comp.v1", &[]).is_none());
    }

    #[test]
    fn seal_key_and_filename_key_are_independent() {
        // The public filename must not reveal the seal key: they are
        // separate HKDF labels off the master.
        let k = keys([5u8; 32]);
        assert_ne!(k.seal_key, k.filename_key);
    }
}
