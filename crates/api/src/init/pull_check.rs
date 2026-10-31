//! Whether a session's bearers may pull every artifact it pins.

use engine_rpc::MAX_COMPONENTS_BYTES;
use engine_types::limits::MAX_MODEL_FILE_BYTES;
use session_types::{CompileFault, InitError, MAX_MODEL_FILES, Terms};

use crate::compositions::{Composition, Compositions, pull_failure};
use crate::init::Unavailable;
use crate::model_files::ArtifactModelFiles;
use crate::policy_pull;

/// Ask the registry whether this session's bearers may pull every artifact it
/// pins — as part of preparing the session ([`super::prepare`]). A cached
/// compile is served with no pull behind it and its key holds no bearer (see
/// [`composition_key`](crate::compositions::composition_key)), so this is what
/// keeps a session from running an artifact its consumer could not obtain. Once
/// a round's write records the session prepared, this is not asked again: a
/// later round whose composition has left every cache still pulls, with the
/// bearers the session was created with.
///
/// One manifest per artifact, concurrently as far as the consumer's turns
/// allow, each checked against its pin, each pulled within the session's own
/// deadline where its terms name one. An artifact refused is the session's
/// init error, the first such in pin order; otherwise one that got no answer is
/// 503, the same request later ([`pull_failure`]). The answer depends on the
/// pins, the bearers and the registries, never on what the caches hold. The
/// hatch sees the refs and the bearers, and when the session was prepared.
///
/// The manifests also say how large the composition is: its wasm layers
/// together past what the session's terms allow are refused here, hit or miss,
/// as too large — so a composition that some other consumer's session compiled
/// does not run where its consumer's terms would not have compiled it. And what
/// model files each artifact carries, which are returned for preparing the
/// session to keep ([`crate::model_files::keep`]): more of them than the
/// compile pairs with models, or one longer than a model file may be, is
/// refused as too large before a byte of one moves.
pub(super) async fn check_pull(
    compositions: &Compositions,
    session_id: &str,
    composition: &Composition,
) -> Result<Vec<ArtifactModelFiles>, Unavailable> {
    let (turns, within) = composition.pulls(&compositions.consumer_turns);
    let turns = &turns;
    let manifests =
        composition
            .artifacts()
            .into_iter()
            .map(|(artifact, artifact_ref, bearer)| async move {
                let layers = policy_pull::manifest(
                    &compositions.registry,
                    turns,
                    artifact_ref,
                    bearer,
                    within,
                )
                .await
                .and_then(|manifest| policy_pull::layers(&manifest));
                match layers {
                    Ok(layers) => Ok((
                        layers.wasm_size,
                        ArtifactModelFiles {
                            artifact,
                            reference: artifact_ref.to_owned(),
                            layers: layers.model_layers,
                        },
                    )),
                    Err(e) => Err((artifact, artifact_ref, e)),
                }
            });
    let mut failed = None;
    let mut size = 0u64;
    let mut carried = Vec::new();
    for res in futures::future::join_all(manifests).await {
        match res {
            Ok((wasm_size, files)) => {
                size = size.saturating_add(wasm_size);
                carried.push(files);
            }
            Err((artifact, artifact_ref, e)) => {
                safe_logger::debug!(
                    "check_pull: {artifact_ref} failed for session {session_id}: {e}"
                );
                // A refusal stands whatever else went unanswered.
                if !matches!(failed, Some(Unavailable::Init(_))) {
                    failed = Some(pull_failure(artifact, &e));
                }
            }
        }
    }
    if let Some(e) = failed {
        return Err(e);
    }
    if size > Terms::within(composition.terms.components_bytes, MAX_COMPONENTS_BYTES) {
        safe_logger::debug!(
            "check_pull: {size} bytes of components, past the terms of {session_id}"
        );
        return Err(Unavailable::Init(InitError::Compile(
            CompileFault::TooLarge,
        )));
    }
    let mut files = carried.iter().flat_map(|artifact| &artifact.layers);
    if files.clone().count() > MAX_MODEL_FILES
        || files.any(|layer| layer.length > MAX_MODEL_FILE_BYTES)
    {
        safe_logger::debug!("check_pull: model files past the bounds for {session_id}");
        return Err(Unavailable::Init(InitError::Compile(
            CompileFault::TooLarge,
        )));
    }
    Ok(carried)
}
