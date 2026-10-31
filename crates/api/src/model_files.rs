//! A composition's model files in L2 — its models' graphs and data files:
//! kept there while a session is prepared, and served from there to the
//! execution-worker when a round first runs a model of one.
//!
//! An artifact carries its model files as layers beside its component
//! ([`policy_pull::layers`]). The compile takes only their names and digests;
//! the bytes go to the execution-worker alone, when a round runs a model whose
//! files the worker has not filled yet ([`RoundModelFiles::serve`]). Preparing
//! a session pulls every file its composition carries that L2 does not hold —
//! one after another, beside the compile — so no round waits on a registry for
//! one, and a file that does not pull is the session's init error before any
//! round runs ([`keep`]); and it records which files those are ([`carried`]),
//! so a round checks a request for one, and finds it, with no registry asked.
//! A file L2 has let go of since is pulled again when a round asks for it, and
//! kept on the way.
//!
//! An entry is the file, raw, under its artifact's ref and its digest
//! ([`cache_id`]), sealed as every L2 entry is: every composition pinning the
//! artifact shares it, as every session pinning a composition shares its
//! compile. What an entry spares is a pull and nothing else — a session's
//! bearers are asked about every artifact it pins before its first round, hit
//! or miss (`crate::init`). Best-effort, as the rest of L2 is: an entry that
//! does not open, or a store that fails, costs a pull.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};

use enclavid_boundary::{Asserted, Exposed, Untrusted};
use engine_rpc::{CallbackError, ModelFileDigest, ModelFileStream};
use engine_types::composition::ModelLayer;
use fleet_stream::{BlobHeader, bin};
use session_types::{Artifact, CarriedModelFile, PullProblem};
use storage_client::{BlobPieces, CacheStore, StoreError};

use crate::boundary::ExecutionWorker;
use crate::compositions::{Composition, Compositions, unavailable};
use crate::init::Unavailable;
use crate::policy_pull::{self, PullError};

/// Bumped whenever what an entry holds changes, so an entry of another layout
/// is never read.
const MODEL_FILE_FORMAT_VERSION: u32 = 1;

/// The L2 id of the model file `sha256` of the artifact `reference`. The
/// digest goes first and is 64 characters, so no two pairs render to one id,
/// and the prefix keeps every id apart from a compile's.
fn cache_id(reference: &str, sha256: &[u8; 32]) -> String {
    format!(
        "model-file.{}.{reference}.v{MODEL_FILE_FORMAT_VERSION}",
        hex::encode(sha256)
    )
}

/// The model files one artifact of a composition carries, as its verified
/// manifest declares them.
pub struct ArtifactModelFiles {
    pub artifact: Artifact,
    pub reference: String,
    pub layers: Vec<ModelLayer>,
}

/// What a session keeps of the model files `carried` names, each by its
/// artifact's place in the composition ([`Composition::artifacts`]): what
/// preparing it records for its rounds
/// ([`session_types::Prepared::model_files`]).
pub fn carried(carried: &[ArtifactModelFiles]) -> Vec<CarriedModelFile> {
    (0u32..)
        .zip(carried)
        .flat_map(|(artifact, files)| {
            files.layers.iter().map(move |layer| CarriedModelFile {
                artifact,
                sha256: layer.sha256,
                length: layer.length,
            })
        })
        .collect()
}

/// Keep in L2 every model file `carried` names that it does not hold yet,
/// pulled one after another on `composition`'s turns and within its terms,
/// each held to the size and digest its manifest declares.
///
/// A file that does not pull is answered as a compile's layer is
/// ([`unavailable`]): the session's init error when asking again will not
/// change that. A file L2 does not keep is let go: a round that runs a model
/// of it pulls it then.
pub async fn keep(
    compositions: &Compositions,
    composition: &Composition,
    carried: &[ArtifactModelFiles],
) -> Result<(), Unavailable> {
    let (turns, within) = composition.pulls(&compositions.consumer_turns);
    let cache = &compositions.cache_store;
    for artifact in carried {
        let bearer = policy_pull::bearer_for_ref(&composition.registry_auth, &artifact.reference);
        for layer in &artifact.layers {
            let id = cache_id(&artifact.reference, &layer.sha256);
            if kept(cache, &id).await {
                continue;
            }
            let pieces = policy_pull::model_file_pieces(
                &compositions.registry,
                &turns,
                &artifact.reference,
                bearer,
                &layer.sha256,
                layer.length,
                within,
            );
            store(cache, &id, layer.length, pieces)
                .await
                .map_err(|problem| unavailable(artifact.artifact.clone(), problem))?;
        }
    }
    Ok(())
}

/// Whether L2 holds `id`: opened and let go at once, which counts as a use.
async fn kept(cache: &CacheStore, id: &str) -> bool {
    matches!(cache.load(id).await, Ok(Some(_)))
}

/// Keep `pieces`, `length` bytes, in L2 under `id` as they are pulled. A pull
/// that fails is the answer, as what it says of the pins ([`PullError::problem`]);
/// a store that fails while the pull did not is let go.
async fn store(
    cache: &CacheStore,
    id: &str,
    length: u64,
    pieces: BoxStream<'static, Result<Bytes, PullError>>,
) -> Result<(), Option<PullProblem>> {
    let pulled = Arc::new(OnceLock::new());
    let failed = pulled.clone();
    let pieces = pieces
        .map_err(move |e| {
            safe_logger::debug!("model files: a file did not arrive as pinned: {e}");
            let _ = failed.set(e.problem());
            StoreError::Transport("a model file did not arrive as pinned; not stored".into())
        })
        .boxed();
    if let Err(e) = cache.store(id, length, pieces).await {
        if let Some(problem) = pulled.get() {
            return Err(*problem);
        }
        safe_logger::debug!("model files: L2 store failed (non-fatal): {e}");
    }
    Ok(())
}

/// What serving a round's model files takes: the composition it runs, and
/// the model files preparing its session found it carries.
pub struct RoundModelFiles {
    compositions: Arc<Compositions>,
    composition: Composition,
    carried: Vec<CarriedModelFile>,
}

impl RoundModelFiles {
    pub fn new(
        compositions: Arc<Compositions>,
        composition: Composition,
        carried: Vec<CarriedModelFile>,
    ) -> Self {
        Self {
            compositions,
            composition,
            carried,
        }
    }

    /// The model file `digest` names, streaming to the worker — when it is
    /// one the round's composition carries, and only then.
    ///
    /// The digest arrives open, and what answers for it is the fact that makes
    /// the reply's `AuthZ` true: a file is served only where the round's own
    /// pins carry it, as their verified manifests said when the session was
    /// prepared, so the worker names an item of what api chose for the round
    /// and never what to fetch. From L2; where L2 does not hold it, pulled
    /// again with the session's bearers and kept on the way. The header is the
    /// manifest's, so the worker holds the bytes to the pins wherever they came
    /// from.
    pub async fn serve(
        &self,
        digest: Untrusted<ModelFileDigest, (Asserted,), ExecutionWorker>,
    ) -> Result<Exposed<ModelFileStream, (), ExecutionWorker>, CallbackError> {
        let Ok(file) = digest.trust_with(Asserted::Bound, |ModelFileDigest(sha256)| {
            find(&self.carried, &sha256).ok_or(())
        }) else {
            safe_logger::debug!(
                "model files: a round asked for a file its composition does not carry"
            );
            return Err(CallbackError);
        };
        let file = file.into_inner();
        let artifacts = self.composition.artifacts();
        let (_, reference, bearer) = usize::try_from(file.artifact)
            .ok()
            .and_then(|at| artifacts.get(at))
            .ok_or(CallbackError)?;
        let header = BlobHeader::new(file.length, file.sha256).ok_or(CallbackError)?;
        let (tx, body) = bin::channel();
        let id = cache_id(reference, &file.sha256);
        let cache = self.compositions.cache_store.clone();
        match cache.load(&id).await {
            Ok(Some((length, pieces))) if length == file.length => {
                tokio::spawn(send_kept(cache, id, tx, pieces));
            }
            _ => {
                let (turns, within) = self.composition.pulls(&self.compositions.consumer_turns);
                let pieces = policy_pull::model_file_pieces(
                    &self.compositions.registry,
                    &turns,
                    reference,
                    bearer,
                    &file.sha256,
                    file.length,
                    within,
                );
                tokio::spawn(send_pulled(cache, id, file.length, tx, pieces));
            }
        }
        Ok(ExecutionWorker::expose(ModelFileStream { header, body }))
    }
}

/// The file of `carried` whose digest is `sha256`: the first in composition
/// order, since two artifacts carrying it carry the same bytes.
fn find<'a>(carried: &'a [CarriedModelFile], sha256: &[u8; 32]) -> Option<&'a CarriedModelFile> {
    carried.iter().find(|file| file.sha256 == *sha256)
}

/// A kept file's `pieces`, to the worker. An entry found bad on the way — a
/// segment that did not open, bytes off its length — is dropped once the send
/// has ended, so the round that asks for the file next pulls it again.
async fn send_kept(cache: CacheStore, id: String, tx: bin::Sender, pieces: BlobPieces) {
    let bad = Arc::new(AtomicBool::new(false));
    let found = bad.clone();
    let pieces = pieces.inspect_err(move |e| {
        if matches!(e, StoreError::Crypto(_) | StoreError::Codec(_)) {
            found.store(true, Ordering::Relaxed);
        }
    });
    if let Err(e) = fleet_stream::send_from(tx, pieces).await {
        safe_logger::debug!("model files: a kept file did not reach the worker: {e:?}");
    }
    if bad.load(Ordering::Relaxed)
        && let Err(e) = cache.remove(&id).await
    {
        safe_logger::debug!("model files: L2 remove failed (non-fatal): {e}");
    }
}

/// A file pulled again, to the worker and into L2 under `id` at once
/// ([`crate::tee`]): a pull that fails ends both, and neither keeps it.
async fn send_pulled(
    cache: CacheStore,
    id: String,
    length: u64,
    tx: bin::Sender,
    pieces: BoxStream<'static, Result<Bytes, PullError>>,
) {
    let pieces = pieces
        .inspect_err(|e| {
            safe_logger::debug!("model files: a file pulled again did not arrive as pinned: {e}")
        })
        .boxed();
    let (feed, to_worker, to_cache) = crate::tee::tee(pieces);
    let to_cache = to_cache
        .map_err(|()| {
            StoreError::Transport("a model file did not arrive as pinned; not stored".into())
        })
        .boxed();
    let (sent, stored, ()) = tokio::join!(
        fleet_stream::send_from(tx, to_worker),
        cache.store(&id, length, to_cache),
        feed,
    );
    if let Err(e) = sent {
        safe_logger::debug!("model files: a file pulled again did not reach the worker: {e:?}");
    }
    if let Err(e) = stored {
        safe_logger::debug!("model files: L2 store failed (non-fatal): {e}");
    }
}

#[cfg(test)]
mod tests;
