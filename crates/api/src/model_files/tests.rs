use super::*;

/// A cache under the real store's seal, on a store in memory.
async fn cache() -> CacheStore {
    let disk = Arc::new(storage_client::memory::Disk::default());
    CacheStore::new(disk.connect().await, &[3; 32])
}

fn file(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// `bytes` as a pull yields them, in pieces of `piece` bytes, then `end`.
fn pulled(
    bytes: &[u8],
    piece: usize,
    end: Option<PullError>,
) -> BoxStream<'static, Result<Bytes, PullError>> {
    let mut pieces: Vec<_> = bytes
        .chunks(piece)
        .map(|p| Ok(Bytes::copy_from_slice(p)))
        .collect();
    pieces.extend(end.map(Err));
    futures::stream::iter(pieces).boxed()
}

async fn read(pieces: BlobPieces) -> Vec<u8> {
    pieces
        .try_fold(Vec::new(), |mut all, p| async move {
            all.extend_from_slice(&p);
            Ok(all)
        })
        .await
        .expect("the entry opens")
}

const REFERENCE: &str = "registry.example.com/plugin@sha256:00";

/// An id names its artifact and its digest, and nothing else does: another
/// artifact, another file, or a compile's entry is another id.
#[test]
fn an_id_names_its_artifact_and_its_file() {
    let id = cache_id(REFERENCE, &[7; 32]);
    assert_eq!(
        id,
        format!(
            "model-file.{}.{REFERENCE}.v{MODEL_FILE_FORMAT_VERSION}",
            "07".repeat(32)
        )
    );
    assert_ne!(
        id,
        cache_id("registry.example.com/other@sha256:00", &[7; 32])
    );
    assert_ne!(id, cache_id(REFERENCE, &[8; 32]));
    assert!(id.starts_with("model-file."));
}

/// The longest model file a composition may name, sealed, fits what the
/// storage leg carries.
#[test]
fn the_longest_file_fits_the_storage_leg() {
    assert!(
        enclavid_crypto::sealed_stream::sealed_len(engine_types::limits::MAX_MODEL_FILE_BYTES)
            <= storage_rpc::MAX_CACHE_BLOB_BYTES
    );
}

/// A file that pulls whole is kept, and found kept after.
#[tokio::test]
async fn a_file_that_pulls_whole_is_kept() {
    let cache = cache().await;
    let id = cache_id(REFERENCE, &[7; 32]);
    let bytes = file(200_000);
    assert!(!kept(&cache, &id).await);
    store(&cache, &id, bytes.len() as u64, pulled(&bytes, 9_999, None))
        .await
        .expect("the pull is whole");
    assert!(kept(&cache, &id).await);
    let (length, pieces) = cache.load(&id).await.unwrap().expect("kept");
    assert_eq!(length, bytes.len() as u64);
    assert!(read(pieces).await == bytes);
}

/// A pull that fails is the answer, as what it says of the pins, and nothing
/// of it is kept — even where every byte arrived first, as a digest found wrong
/// at the end does: one that will not pass names its problem, one that may
/// later names none.
#[tokio::test]
async fn a_pull_that_fails_is_the_answer_and_keeps_nothing() {
    let cache = cache().await;
    let id = cache_id(REFERENCE, &[7; 32]);
    let bytes = file(50_000);
    for (end, problem) in [
        (
            PullError::LayerDigest {
                expected: "sha256:00".into(),
                actual: "sha256:11".into(),
            },
            Some(PullProblem::NotAsPinned),
        ),
        (PullError::Refused, Some(PullProblem::Refused)),
        (PullError::Busy, None),
    ] {
        let failed = store(
            &cache,
            &id,
            bytes.len() as u64,
            pulled(&bytes, 4096, Some(end)),
        )
        .await;
        assert_eq!(failed, Err(problem));
        assert!(!kept(&cache, &id).await);
    }
}

fn layer(name: &str, digest: u8) -> ModelLayer {
    ModelLayer {
        name: name.into(),
        sha256: [digest; 32],
        length: u64::from(digest),
    }
}

/// A policy carrying `age`'s graph, then a plugin carrying `face`'s graph and
/// `age`'s again.
fn composition_files() -> [ArtifactModelFiles; 2] {
    [
        ArtifactModelFiles {
            artifact: Artifact::Policy,
            reference: "r/policy@sha256:00".into(),
            layers: vec![layer("age.onnx", 1)],
        },
        ArtifactModelFiles {
            artifact: Artifact::Plugin("p".into()),
            reference: "r/p@sha256:00".into(),
            layers: vec![layer("face.onnx", 2), layer("age.onnx", 1)],
        },
    ]
}

/// A session keeps each file by its artifact's place in the composition, the
/// policy's first, and by the digest and length its manifest declares.
#[test]
fn a_session_keeps_each_file_by_its_artifacts_place() {
    let file = |artifact, digest: u8| CarriedModelFile {
        artifact,
        sha256: [digest; 32],
        length: u64::from(digest),
    };
    assert_eq!(
        carried(&composition_files()),
        vec![file(0, 1), file(1, 2), file(1, 1)]
    );
}

/// A file is found in the first artifact carrying it, in composition order,
/// and a digest no artifact carries is found nowhere.
#[test]
fn a_file_is_found_where_the_composition_carries_it() {
    let carried = carried(&composition_files());
    assert_eq!(find(&carried, &[2; 32]).map(|f| f.artifact), Some(1));
    assert_eq!(find(&carried, &[1; 32]).map(|f| f.artifact), Some(0));
    assert!(find(&carried, &[3; 32]).is_none());
}
