//! Whether a session's bearers may pull every artifact it pins.

use std::time::Duration;

use axum::http::StatusCode;

use engine_rpc::MAX_COMPONENTS_BYTES;
use session_types::{Artifact, Client, CompileFault, InitError, SessionMetadata, Terms};

use crate::compositions::{Compositions, consumer, pull_failure};
use crate::init::Unavailable;
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
/// does not run where its consumer's terms would not have compiled it.
pub(super) async fn check_pull(
    compositions: &Compositions,
    session_id: &str,
    metadata: &SessionMetadata,
) -> Result<(), Unavailable> {
    let client = metadata.client.as_ref().ok_or_else(|| {
        safe_logger::debug!("check_pull: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let turns = &compositions.consumer_turns.of(consumer(client));
    let within = metadata.terms.pull_deadline_secs.map(Duration::from_secs);
    let artifacts = artifacts_with_bearers(&metadata.policy_ref, client);
    let manifests = artifacts
        .into_iter()
        .map(|(artifact, artifact_ref, bearer)| async move {
            policy_pull::manifest(&compositions.registry, turns, artifact_ref, bearer, within)
                .await
                .and_then(|manifest| policy_pull::wasm_layer_size(&manifest))
                .map_err(|e| (artifact, artifact_ref, e))
        });
    let mut failed = None;
    let mut size = 0u64;
    for res in futures::future::join_all(manifests).await {
        match res {
            Ok(layer) => size = size.saturating_add(layer),
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
    if size > Terms::within(metadata.terms.components_bytes, MAX_COMPONENTS_BYTES) {
        safe_logger::debug!(
            "check_pull: {size} bytes of components, past the terms of {session_id}"
        );
        return Err(Unavailable::Init(InitError::Compile(
            CompileFault::TooLarge,
        )));
    }
    Ok(())
}

/// Every artifact a session pins — the policy, then each plugin — with its ref
/// and the bearer its registry is asked with: [`check_pull`] must leave none
/// out.
fn artifacts_with_bearers<'a>(
    policy_ref: &'a str,
    client: &'a Client,
) -> Vec<(Artifact, &'a str, &'a [u8])> {
    std::iter::once((Artifact::Policy, policy_ref))
        .chain(
            client
                .plugins
                .iter()
                .map(|pin| (Artifact::Plugin(pin.package.clone()), pin.impl_ref.as_str())),
        )
        .map(|(artifact, artifact_ref)| {
            let bearer = policy_pull::bearer_for_ref(&client.registry_auth, artifact_ref);
            (artifact, artifact_ref, bearer)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use session_types::PluginPin;

    fn pin(package: &str, impl_ref: &str) -> PluginPin {
        PluginPin {
            package: package.into(),
            impl_ref: impl_ref.into(),
            key: None,
        }
    }

    /// The pull check asks about the policy and every plugin, in pin order,
    /// each with the bearer kept for its own registry — none left out, none
    /// sent to another registry.
    #[test]
    fn the_pull_check_covers_every_pin_with_its_registrys_bearer() {
        let client = Client {
            registry_auth: HashMap::from([
                ("a.example.com".to_string(), b"bearer-a".to_vec()),
                ("b.example.com".to_string(), b"bearer-b".to_vec()),
            ]),
            plugins: vec![
                pin("p1", "b.example.com/p1@sha256:11"),
                pin("p2", "c.example.com/p2@sha256:22"),
                pin("p3", "a.example.com/p3@sha256:33"),
            ],
            ..Default::default()
        };
        let plugin = |package: &str| Artifact::Plugin(package.into());
        assert_eq!(
            artifacts_with_bearers("a.example.com/policy@sha256:aa", &client),
            vec![
                (
                    Artifact::Policy,
                    "a.example.com/policy@sha256:aa",
                    &b"bearer-a"[..]
                ),
                (plugin("p1"), "b.example.com/p1@sha256:11", &b"bearer-b"[..]),
                (plugin("p2"), "c.example.com/p2@sha256:22", &b""[..]),
                (plugin("p3"), "a.example.com/p3@sha256:33", &b"bearer-a"[..]),
            ]
        );
    }
}
