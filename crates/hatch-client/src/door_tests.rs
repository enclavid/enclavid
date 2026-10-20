//! The doors end to end: a hatch served at its end over a real connection,
//! brought up as both roles bring the leg up, and called through the typed
//! clients at theirs.

use std::sync::Arc;
use std::time::Duration;

use enclavid_boundary::{AuthN, Exposed, Untrusted};
use enclavid_boundary_macros::boundary;
use fleet_stream::{StreamLen, bin};
use futures::TryStreamExt;
use hatch_rpc::{
    AuthorizeError, AuthorizeRequest, BlobRequest, ClientOperation, HatchLeg, KbsError, KbsRequest,
    KbsResponse, LegSettings, Manifest, ManifestRequest, PullError, RemoteHatchAt, SessionTerms,
    Verdict,
};

use crate::{AuthClient, AuthVerdict, BridgeError, KbsClient, Link, Principal, RegistryClient};

boundary! {
    /// The calling end, for the test: every concern answered.
    Api {
        calls: [hatch_rpc::RemoteHatch],
        observer: Test,
    }
    out (AuthN,) {
        /// test fixture
        _: AuthN::Indifferent,
        AuthorizeRequest,
        ManifestRequest,
        BlobRequest,
        KbsRequest,
    }
    in (AuthN,) {
        /// test fixture
        _: AuthN::Indifferent,
        Verdict,
        AuthorizeError,
        Manifest,
        PullError,
        bin::Receiver,
        KbsResponse,
        KbsError,
    }
}

boundary! {
    /// The serving end, for the test: every concern answered.
    Served {
        serves: [hatch_rpc::RemoteHatch],
        observer: Test,
    }
    in (AuthN,) {
        /// test fixture
        _: AuthN::Indifferent,
        AuthorizeRequest,
        ManifestRequest,
        BlobRequest,
        KbsRequest,
    }
    out (AuthN,) {
        /// test fixture
        _: AuthN::Indifferent,
        Verdict,
        AuthorizeError,
        Manifest,
        PullError,
        bin::Receiver,
        KbsResponse,
        KbsError,
    }
}

/// A hatch that answers from what it is asked: a verdict naming the credential
/// it was handed, or no verdict for `down`; a manifest that is the reference's
/// own bytes, or none for `missing`; a blob of the size asked counting up, or —
/// for the digest `silent` — a stream that starts no message; a broker's answer
/// echoing the leg's body for the path `/answered`, and none for any other.
struct FakeHatch;

impl RemoteHatchAt<Served> for FakeHatch {
    async fn authorize(
        &self,
        req: Untrusted<AuthorizeRequest, (), Served>,
    ) -> Result<Exposed<Verdict, (), Served>, AuthorizeError> {
        let header = req.into_inner().authorization_header;
        if header == "down" {
            return Err(AuthorizeError("the hook did not answer".into()));
        }
        Ok(Served::expose(Verdict::Allowed {
            principal: Some(header),
            terms: SessionTerms::default(),
        }))
    }

    async fn manifest(
        &self,
        req: Untrusted<ManifestRequest, (), Served>,
    ) -> Result<Exposed<Manifest, (), Served>, PullError> {
        let req = req.into_inner();
        if req.reference == "missing" {
            return Err(PullError::NotFound);
        }
        Ok(Served::expose(Manifest(req.reference.into_bytes())))
    }

    async fn blob(
        &self,
        req: Untrusted<BlobRequest, (), Served>,
    ) -> Result<Exposed<bin::Receiver, (), Served>, PullError> {
        let req = req.into_inner();
        let (tx, body) = bin::channel();
        if req.digest == "silent" {
            tokio::spawn(async move { drop(tx.into_inner().await) });
        } else {
            let blob: Vec<u8> = (0..req.size.get()).map(|i| i as u8).collect();
            tokio::spawn(fleet_stream::send(tx, blob));
        }
        Ok(Served::expose(body))
    }

    async fn kbs(
        &self,
        req: Untrusted<KbsRequest, (), Served>,
    ) -> Result<Exposed<KbsResponse, (), Served>, KbsError> {
        let req = req.into_inner();
        if req.path != "/answered" {
            return Err(KbsError("the broker did not answer".into()));
        }
        Ok(Served::expose(KbsResponse {
            status: 200,
            headers: vec![("set-cookie".into(), "kbs-session-id=1".into())],
            body: req.body,
        }))
    }
}

/// The leg, always up.
struct Up(Arc<HatchLeg<Api>>);

impl Link<Api> for Up {
    fn leg(&self) -> Option<Arc<HatchLeg<Api>>> {
        Some(self.0.clone())
    }
}

/// A [`FakeHatch`] served at [`Served`] on one end of a connection, and the link
/// to it from the other, held at [`Api`].
async fn hatch() -> Arc<dyn Link<Api>> {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (a_r, a_w) = tokio::io::split(a);
    let (b_r, b_w) = tokio::io::split(b);
    let leg = LegSettings::default();

    tokio::spawn(async move {
        hatch_rpc::serve_hatch::<Served, _, _, _>(a_r, a_w, FakeHatch, 4, &leg)
            .await
            .unwrap();
    });
    let (hatch, _ended) = hatch_rpc::connect_hatch::<Api, _, _>(b_r, b_w, &leg)
        .await
        .unwrap();
    Arc::new(Up(Arc::new(hatch)))
}

const DEADLINE: Duration = Duration::from_secs(10);

fn blob(digest: &str, size: u64) -> Exposed<BlobRequest, (), Api> {
    Api::expose(BlobRequest {
        reference: "registry/repo@sha256:00".into(),
        digest: digest.into(),
        size: StreamLen::new(size).unwrap(),
        registry_auth: Vec::new(),
    })
}

/// A verdict crosses as the hatch gave it, reshaped for api; no verdict
/// crosses as a hatch that did not give one.
#[tokio::test]
async fn a_verdict_crosses_as_its_hatch_gave_it() {
    let auth = AuthClient::<Api>::new(hatch().await, DEADLINE);
    let ask = |header: &str| {
        Api::expose(AuthorizeRequest {
            authorization_header: header.into(),
            operation: ClientOperation::SessionRead,
        })
    };
    let verdict = auth
        .authorize(ask("Bearer someone"))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        verdict,
        AuthVerdict::Allowed { principal: Some(Principal(p)), .. } if p == "Bearer someone"
    ));
    assert!(matches!(
        auth.authorize(ask("down")).await,
        Err(BridgeError::Transport(_))
    ));
}

/// A broker's answer crosses whole, its cookie with it; a leg that did not
/// happen crosses as no answer.
#[tokio::test]
async fn a_brokers_answer_crosses_whole_and_none_as_no_answer() {
    let kbs = KbsClient::<Api>::new(hatch().await, DEADLINE);
    let leg = |path: &str| {
        Api::expose(KbsRequest {
            endpoint: "https://kbs.example".into(),
            method: "POST".into(),
            path: path.into(),
            headers: Vec::new(),
            body: b"evidence".to_vec(),
        })
    };
    let answer = kbs.relay(leg("/answered")).await.unwrap().into_inner();
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"evidence");
    assert_eq!(
        answer.headers,
        vec![("set-cookie".to_string(), "kbs-session-id=1".to_string())]
    );
    assert!(matches!(
        kbs.relay(leg("/kbs/v0/auth")).await,
        Err(BridgeError::Transport(_))
    ));
}

/// A manifest crosses whole, and an absence as itself, not as a failure.
#[tokio::test]
async fn a_manifest_crosses_whole_and_an_absence_as_one() {
    let registry = RegistryClient::<Api>::new(hatch().await, DEADLINE);
    let manifest = |reference: &str| {
        Api::expose(ManifestRequest {
            reference: reference.into(),
            registry_auth: Vec::new(),
        })
    };
    let got = registry
        .manifest(manifest("registry/repo@sha256:00"), None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got, b"registry/repo@sha256:00");
    assert!(matches!(
        registry.manifest(manifest("missing"), None).await,
        Err(BridgeError::NotFound)
    ));
}

/// A blob streams whole across several chunks; one whose sender starts no
/// message is a first piece that fails, never an empty blob.
#[tokio::test]
async fn a_blob_streams_whole_and_one_never_started_fails_its_first_piece() {
    let registry = RegistryClient::<Api>::new(hatch().await, DEADLINE);
    let size = 300_000;
    let pieces: Vec<_> = registry
        .blob(blob("sha256:00", size), None)
        .await
        .unwrap()
        .into_inner()
        .try_collect()
        .await
        .unwrap();
    let got: Vec<u8> = pieces.concat();
    assert_eq!(got.len() as u64, size);
    assert!(got.iter().enumerate().all(|(i, b)| *b == i as u8));

    let mut silent = registry
        .blob(blob("silent", 1), None)
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        silent.try_next().await,
        Err(BridgeError::Transport(_))
    ));
}
