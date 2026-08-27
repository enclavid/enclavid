//! VCEK fetch handler: obtains the AMD certificate that endorses a chip at a
//! platform TCB, on behalf of a TEE that has no outbound network.
//!
//! The hatch is untrusted on content here as everywhere else, and unusually
//! little rides on that: the certificate is public, and the TEE verifies the
//! AMD chain over it against a root compiled into its measured image before it
//! endorses anything. A wrong or substituted certificate cannot verify a report
//! the guest's own chip produced, so the guest refuses to start rather than
//! accepting it.
//!
//! The last answer is memoised against the full request tuple. AMD derives and
//! signs per (chip, TCB) on demand and rate-limits, while every CVM on this
//! machine shares both — so one held certificate serves all of them, and a
//! platform firmware update changes the tuple and therefore fetches afresh with
//! no invalidation to get wrong.
//!
//! Reaching this endpoint at all is the authorisation, as it is for the other
//! egress handlers: on the attested build the listener is a vsock, so the
//! callers are the guests of this machine.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use hatch_protocol::{VcekRequest, VcekResponse};

use crate::AppState;
use crate::error::{HatchError, decode_body, encode_body};

/// AMD's key distribution service. Pinned in code rather than configured:
/// there is no precedent here for an env-selected outbound host, and since the
/// certificate is chain-verified TEE-side the pin enforces nothing — it just
/// keeps this from becoming a second general-purpose forwarder.
const KDS_ORIGIN: &str = "https://kdsintf.amd.com";

/// Product lines whose certificates this endpoint will fetch. Enumerated so
/// the value interpolated into the URL path cannot be anything else.
const PRODUCT_LINES: [&str; 3] = ["Milan", "Genoa", "Turin"];

/// Length of a hex chip identity in an attestation report.
const CHIP_ID_HEX_LEN: usize = 128;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The last certificate fetched, with the tuple it answers.
///
/// One slot rather than a map, because this hatch fronts one machine: every CVM
/// on it shares one chip at one platform TCB, so the useful entry count is one.
/// A map would have to be bounded — its key arrives in the request — and every
/// bounding rule is worse here than having no room to begin with. Stop
/// admitting when full and a flood of foreign chip identities locks the real
/// entry out permanently; evict instead and the flood decides what stays. A
/// single slot degrades under the same flood to exactly the behaviour we had
/// before any memo existed, which is the floor, not a failure.
#[derive(Clone, Default)]
pub struct VcekCache {
    held: Arc<RwLock<Option<(CacheKey, Vec<u8>)>>>,
    /// Held across a miss so concurrent misses become one upstream request.
    /// Several guests coming up together otherwise all miss at once, and AMD
    /// throttles per source — turning a cold start into a burst that mostly
    /// gets refused, which each guest then reads as its own failure.
    fetching: Arc<tokio::sync::Mutex<()>>,
}

/// The whole request, so a firmware update cannot be served a stale answer.
/// A partial key would turn a loud failure into a confusing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    product_line: String,
    chip_id: String,
    spls: (u8, u8, u8, u8),
}

impl VcekCache {
    /// The held certificate, if it answers this exact tuple. A platform
    /// firmware update changes the tuple, so a superseded certificate simply
    /// stops matching — there is no invalidation step to get wrong.
    async fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        match &*self.held.read().await {
            Some((held, certificate)) if held == key => Some(certificate.clone()),
            _ => None,
        }
    }

    async fn put(&self, key: CacheKey, certificate: Vec<u8>) {
        *self.held.write().await = Some((key, certificate));
    }
}

impl From<&VcekRequest> for CacheKey {
    fn from(req: &VcekRequest) -> Self {
        Self {
            product_line: req.product_line.clone(),
            chip_id: req.chip_id.clone(),
            spls: (
                req.bootloader_spl,
                req.tee_spl,
                req.snp_spl,
                req.microcode_spl,
            ),
        }
    }
}

/// POST /kds/vcek
pub async fn vcek(State(state): State<AppState>, body: Bytes) -> Result<Vec<u8>, HatchError> {
    let req: VcekRequest = decode_body(&body)?;
    validate(&req)?;
    let key = CacheKey::from(&req);

    if let Some(certificate) = state.vcek.get(&key).await {
        debug!(chip_id = %req.chip_id, "vcek served from memo");
        return encode_body(&VcekResponse { certificate });
    }

    let _fetching = state.vcek.fetching.lock().await;
    // Whoever held the lock may have just filled the slot with this very tuple.
    if let Some(certificate) = state.vcek.get(&key).await {
        debug!(chip_id = %req.chip_id, "vcek served from memo after waiting");
        return encode_body(&VcekResponse { certificate });
    }

    let certificate = fetch(&req).await?;
    state.vcek.put(key, certificate.clone()).await;
    encode_body(&VcekResponse { certificate })
}

/// Reject anything that would not compose into the URL we intend, before any
/// I/O happens. Both values are interpolated into the path, so an enumerated
/// product and a hex-only identity make traversal and query injection
/// impossible by construction rather than by escaping.
fn validate(req: &VcekRequest) -> Result<(), HatchError> {
    if !PRODUCT_LINES.contains(&req.product_line.as_str()) {
        return Err(HatchError::BadRequest(format!(
            "unknown product line: {}",
            req.product_line
        )));
    }
    if req.chip_id.len() != CHIP_ID_HEX_LEN || !req.chip_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(HatchError::BadRequest(format!(
            "chip id must be {CHIP_ID_HEX_LEN} hex characters"
        )));
    }
    Ok(())
}

/// The security version numbers are DECIMAL in the query even though the chip
/// identity is hex — the single easiest thing here to get silently wrong.
fn kds_url(req: &VcekRequest) -> String {
    format!(
        "{KDS_ORIGIN}/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        req.product_line,
        req.chip_id,
        req.bootloader_spl,
        req.tee_spl,
        req.snp_spl,
        req.microcode_spl
    )
}

async fn fetch(req: &VcekRequest) -> Result<Vec<u8>, HatchError> {
    // Explicit timeouts: a guest blocks its entire bring-up on this call, so an
    // unresponsive service must surface as an error rather than as a machine
    // that never finishes starting.
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| HatchError::Internal(format!("vcek client: {e}")))?;

    let resp = client.get(kds_url(req)).send().await.map_err(|e| {
        warn!(chip_id = %req.chip_id, err = %e, "vcek fetch failed");
        HatchError::Internal(format!("vcek fetch: {e}"))
    })?;

    // A 404 is a real answer: the key service does not endorse this chip at
    // this TCB. One attempt only — the TEE is the party that decides whether
    // to wait and retry, and it can only decide that if it sees the failure.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(HatchError::NotFound);
    }
    if !resp.status().is_success() {
        warn!(chip_id = %req.chip_id, status = %resp.status(), "vcek fetch rejected");
        return Err(HatchError::Internal(format!(
            "vcek fetch: status {}",
            resp.status()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| HatchError::Internal(format!("vcek body: {e}")))?;

    // Not a trust check — the hatch is not the authority on this certificate,
    // and a well-formed forgery would pass here and still die TEE-side. It is
    // to keep a body that is plainly NOT a certificate — a maintenance page, an
    // error document — out of the memo, where it would be replayed to every
    // later request and defeat the retry the guest does on its own side.
    if !looks_like_der_certificate(&bytes) {
        warn!(chip_id = %req.chip_id, bytes = bytes.len(), "vcek response is not DER");
        return Err(HatchError::Internal(
            "vcek fetch: response is not a DER certificate".to_string(),
        ));
    }
    Ok(bytes.to_vec())
}

/// A DER certificate is one SEQUENCE spanning the whole body: tag `0x30`, then
/// a long-form length that must account for exactly the remaining bytes.
fn looks_like_der_certificate(bytes: &[u8]) -> bool {
    if bytes.first() != Some(&0x30) {
        return false;
    }
    let Some(&first_len_byte) = bytes.get(1) else {
        return false;
    };
    // Certificates are always well past 127 bytes, so the length is long-form:
    // the low bits count the length-of-length octets that follow.
    if first_len_byte & 0x80 == 0 {
        return false;
    }
    let count = usize::from(first_len_byte & 0x7f);
    if count == 0 || count > 4 || bytes.len() < 2 + count {
        return false;
    }
    let length = bytes[2..2 + count]
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    bytes.len() == 2 + count + length
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> VcekRequest {
        VcekRequest {
            product_line: "Milan".to_string(),
            chip_id: "ab".repeat(64),
            bootloader_spl: 4,
            tee_spl: 0,
            snp_spl: 29,
            microcode_spl: 222,
        }
    }

    /// Zero-padded to two digits, decimal, and three digits when the value
    /// needs them — the shape AMD's service expects.
    #[test]
    fn url_encodes_versions_in_decimal() {
        let url = kds_url(&request());
        assert!(
            url.ends_with("?blSPL=04&teeSPL=00&snpSPL=29&ucodeSPL=222"),
            "{url}"
        );
        assert!(
            url.starts_with("https://kdsintf.amd.com/vcek/v1/Milan/abab"),
            "{url}"
        );
    }

    #[test]
    fn rejects_unknown_product_line() {
        let mut req = request();
        req.product_line = "../../kbs".to_string();
        assert!(matches!(validate(&req), Err(HatchError::BadRequest(_))));
    }

    #[test]
    fn rejects_non_hex_chip_id() {
        let mut req = request();
        req.chip_id = format!("{}?x=", "a".repeat(123));
        assert!(matches!(validate(&req), Err(HatchError::BadRequest(_))));
    }

    #[test]
    fn rejects_short_chip_id() {
        let mut req = request();
        req.chip_id = "ab".repeat(32);
        assert!(matches!(validate(&req), Err(HatchError::BadRequest(_))));
    }

    /// The shape a real VCEK has: SEQUENCE, long-form length covering the body.
    #[test]
    fn accepts_a_der_certificate_shape() {
        let mut der = vec![0x30, 0x82, 0x05, 0x43];
        der.extend(std::iter::repeat_n(0u8, 0x0543));
        assert!(looks_like_der_certificate(&der));
    }

    /// The failure this guards: a 200 carrying something that is not a
    /// certificate would otherwise be memoised and replayed to every guest.
    #[test]
    fn rejects_bodies_that_are_not_certificates() {
        assert!(!looks_like_der_certificate(b"<html>maintenance</html>"));
        assert!(!looks_like_der_certificate(b"{\"error\":\"rate limited\"}"));
        assert!(!looks_like_der_certificate(b""));
        assert!(!looks_like_der_certificate(&[0x30]));
        // SEQUENCE, but the declared length does not span the body.
        assert!(!looks_like_der_certificate(&[0x30, 0x82, 0x05, 0x43, 0x00]));
        // Short-form length: far too small to be a certificate.
        assert!(!looks_like_der_certificate(&[0x30, 0x03, 1, 2, 3]));
    }

    /// The memo answers only the tuple it holds. A request about any other
    /// chip, or the same chip at a different platform TCB, misses.
    #[tokio::test]
    async fn memo_answers_only_its_own_tuple() {
        let cache = VcekCache::default();
        let ours = CacheKey::from(&request());
        cache.put(ours.clone(), vec![1, 2, 3]).await;
        assert_eq!(cache.get(&ours).await, Some(vec![1, 2, 3]));

        let mut foreign = request();
        foreign.chip_id = "cd".repeat(64);
        assert_eq!(cache.get(&CacheKey::from(&foreign)).await, None);

        let mut newer = request();
        newer.microcode_spl = 223;
        assert_eq!(cache.get(&CacheKey::from(&newer)).await, None);
    }

    /// A flood of foreign identities cannot grow anything: the slot holds one
    /// entry whatever happens, and the machine's own guests refetch once.
    #[tokio::test]
    async fn memo_holds_one_entry_under_a_flood() {
        let cache = VcekCache::default();
        let ours = CacheKey::from(&request());
        cache.put(ours.clone(), vec![1, 2, 3]).await;

        for i in 0..64 {
            let mut foreign = request();
            foreign.chip_id = format!("{:0128x}", i + 1);
            cache.put(CacheKey::from(&foreign), vec![9]).await;
        }

        assert_eq!(cache.get(&ours).await, None, "must refetch, not serve junk");
        cache.put(ours.clone(), vec![1, 2, 3]).await;
        assert_eq!(cache.get(&ours).await, Some(vec![1, 2, 3]));
    }

    /// A TCB change must miss: serving the previous certificate would endorse
    /// a key the platform no longer signs with.
    #[test]
    fn cache_key_separates_tcb_versions() {
        let a = CacheKey::from(&request());
        let mut newer = request();
        newer.microcode_spl = 223;
        assert_ne!(a, CacheKey::from(&newer));
    }
}
