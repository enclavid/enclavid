//! A composition — a policy and the plugins it is pinned with — and having it
//! compiled: its artifacts pulled through the hatch with the consumer's bearers,
//! compiled by the compile-worker, kept in L2 (`crate::cwasm_cache`).
//!
//! A compile is a pure function of the pinned artifacts and of nothing a session
//! holds, so preparing a session asks for one with no round at all, and every
//! session pinning the same artifacts shares one compile. One compile at a
//! time per composition and consumer ([`Compositions::compile_lock`]): whoever
//! finds its own consumer's compile under way waits for it and reads what it
//! left in L2, rather than compiling the same pins again. What the worker is
//! handed on its miss comes from here ([`Compositions::with_bundle`]).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use axum::http::StatusCode;
use futures::{StreamExt, TryStreamExt};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use engine_rpc::{BundleSource, CompatToken, CompileError, CompileSource, CompositionKey};
use hatch_client::{KbsClient, RegistryClient};
use session_types::{
    Artifact, Client, CompileFault, InitError, Key, PluginPin, PullProblem, SessionMetadata,
};
use storage_client::CacheStore;

use crate::compiler::{Compiled, Compiler};
use crate::cwasm_cache;
use crate::executor::Executor;
use crate::init::Unavailable;
use crate::policy_pull;
use crate::semaphores::Semaphores;
use crate::turns::ConsumerTurns;

/// What a composition is made of, and what reaching its artifacts takes. Holds
/// the decrypt keys and the bearers, so it has no `Debug`.
pub struct Composition {
    pub policy_ref: String,
    pub policy_key: Option<Key>,
    /// In composition order, which fusion fixes.
    pub plugins: Vec<PluginPin>,
    /// The `Authorization` value for each registry host an artifact is pulled
    /// from; a host with none is pulled from anonymously.
    pub registry_auth: HashMap<String, Vec<u8>>,
    /// The consumer whose turns the pulls take ([`crate::turns`]).
    pub consumer: String,
}

impl Composition {
    /// A session's composition, as its sealed metadata pins it. `None` for
    /// metadata with no client block, which a created session always has.
    pub fn of(metadata: &SessionMetadata) -> Option<Self> {
        let client = metadata.client.as_ref()?;
        Some(Self {
            policy_ref: metadata.policy_ref.clone(),
            policy_key: metadata.policy_key.clone(),
            plugins: client.plugins.clone(),
            registry_auth: client.registry_auth.clone(),
            consumer: consumer(client).to_owned(),
        })
    }

    /// Its content address — see [`composition_key`].
    pub fn key(&self) -> CompositionKey {
        composition_key(&self.policy_ref, self.policy_key.as_ref(), &self.plugins)
    }
}

/// The consumer a session's pulls count against ([`crate::turns`]): the
/// organization that created it, as its sealed metadata records.
pub fn consumer(client: &Client) -> &str {
    client
        .access
        .as_ref()
        .and_then(|access| access.principal.as_deref())
        .unwrap_or_default()
}

/// What having a composition ready to run takes — compiling it, keeping it in
/// L2, and the execution-worker that holds it — shared by the rounds that miss
/// and the preparations that ask ahead of them.
pub struct Compositions {
    /// The execution-worker a session is prepared on (`crate::init`).
    pub executor: Arc<Executor>,
    compiler: Arc<Compiler>,
    /// L2 — see [`crate::cwasm_cache`].
    pub cache_store: CacheStore,
    pub registry: RegistryClient,
    pub consumer_turns: ConsumerTurns,
    /// Couriers each Trustee RCAR leg of the `kbs` key path through the hatch.
    kbs: KbsClient,
    /// One permit per composition and consumer — see [`Self::compile_lock`].
    compile_locks: Semaphores<(CompositionKey, String)>,
    /// One warmup at a time per session (`crate::init::warm`): one asked for
    /// while another is under way is that one.
    pub warming: Semaphores<String>,
}

impl Compositions {
    pub fn new(
        executor: Arc<Executor>,
        compiler: Arc<Compiler>,
        cache_store: CacheStore,
        registry: RegistryClient,
        consumer_turns: ConsumerTurns,
        kbs: KbsClient,
    ) -> Self {
        Self {
            executor,
            compiler,
            cache_store,
            registry,
            consumer_turns,
            kbs,
            compile_locks: Semaphores::new(1),
            warming: Semaphores::new(1),
        }
    }

    /// One compile at a time per composition and consumer: the one permit a
    /// compile holds while it runs, which whoever of the same consumer comes for
    /// the composition meanwhile waits on, then finds it in L2.
    ///
    /// Per consumer, not per composition: a compile pulls with its consumer's
    /// bearers and waits on its consumer's turns, so another consumer never
    /// waits on it — one consumer's pulls do not hold up another's. Two
    /// consumers' compiles of one composition run side by side and keep the same
    /// entry.
    pub fn compile_lock(&self, key: &CompositionKey, consumer: &str) -> Arc<Semaphore> {
        self.compile_locks.of(&(key.clone(), consumer.to_owned()))
    }

    /// Resolve the compiled bundle of `composition` for `(key, compat_token)` and
    /// `send` it to the worker — what api does with a worker's cache miss, for a
    /// round and for a preparation alike. This is the ONE place a compile is
    /// triggered: the orchestrator holds no in-memory component cache, so it
    /// opens L2 (or compiles) each time the worker's L1 misses.
    ///
    ///   * L2 hit: the bundle goes to the worker straight from the cache, a piece
    ///     at a time, so api never holds the cwasm. An entry found bad on the way
    ///     — it did not open, or did not hold what its header said — fails this
    ///     call as any infra fault does, and is dropped, so the next miss compiles
    ///     afresh. The call is not retried here: the worker answers a bundle it
    ///     refused as it answers a call that failed after running, so this side
    ///     cannot know that nothing ran.
    ///   * L2 miss, and the same consumer has a compile of the composition under
    ///     way — a preparation's, or a round's: wait for it to end, then look in
    ///     L2 again. Once: a call that still misses after it compiles too.
    ///   * L2 miss otherwise: this call compiles it ([`compile`](Self::compile)),
    ///     and the worker and the cache take the cwasm at once as it streams back
    ///     ([`crate::tee`]), so api never holds it whole here either. Whoever of
    ///     the same consumer comes for the composition meanwhile waits until the
    ///     cache has kept it or failed to. A cache that cannot keep it costs the
    ///     next miss a compile; the call goes on. A cwasm that is not what the
    ///     compiler named reaches both as an abandoned stream, and neither keeps
    ///     it.
    ///
    /// The error is resolution's; what `send` answers is the call's. Compiles
    /// are one at a time per composition and consumer in THIS process; another
    /// consumer's, or another api's, race just re-reads L2 or double-compiles
    /// (idempotent write).
    pub async fn with_bundle<T, F, Fut>(
        &self,
        composition: &Composition,
        key: &CompositionKey,
        compat_token: &CompatToken,
        for_whom: &str,
        send: F,
    ) -> Result<T, Unavailable>
    where
        F: FnOnce(BundleSource) -> Fut,
        Fut: Future<Output = T>,
    {
        let open = || cwasm_cache::open(&self.cache_store, key, compat_token);
        let mut hit = open().await;
        let mut compiling = None;
        if hit.is_none() {
            let lock = self.compile_lock(key, &composition.consumer);
            match lock.clone().try_acquire_owned() {
                // Nobody of this consumer is compiling it: this call does, and
                // holds the lock while it does, so the next to come waits for
                // this compile.
                Ok(held) => compiling = Some(held),
                // Someone is: wait for that compile to end — once — and look
                // again. A call that still misses compiles too, alongside rather
                // than after whoever took the lock next, so calls on a
                // composition that does not compile are answered together, not
                // one after another.
                Err(_) => {
                    drop(lock.acquire().await);
                    hit = open().await;
                }
            }
        }
        if let Some(hit) = hit {
            let cwasm_cache::Hit { source, found_bad } = hit;
            let reply = send(source).await;
            if found_bad.get() {
                cwasm_cache::remove(&self.cache_store, key, compat_token).await;
            }
            return Ok(reply);
        }
        let Compiled {
            meta,
            cwasm_len,
            cwasm_sha256,
            cwasm,
        } = self.compile(composition, for_whom).await?;
        let (feed, to_worker, to_cache) = crate::tee::tee(cwasm);
        let source = BundleSource::streamed(cwasm_len, cwasm_sha256, meta.clone(), to_worker)
            .ok_or_else(|| {
                safe_logger::debug!(
                    "compile: a bundle past the execute hop's bounds for {for_whom}"
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        // The same compile, with the cache's branch of its cwasm.
        let entry = Compiled {
            meta,
            cwasm_len,
            cwasm_sha256,
            cwasm: to_cache,
        };
        // The compile is over for whoever waits on it once the cache has kept
        // it, or failed to — not once this call has been answered, which they
        // need not wait for.
        let keep = async {
            cwasm_cache::store(&self.cache_store, key, compat_token, entry).await;
            drop(compiling);
        };
        let (reply, (), ()) = tokio::join!(send(source), keep, feed);
        Ok(reply)
    }

    /// Pull the policy and its pinned plugins (api owns OCI and the registry
    /// bearers), then hand the bytes to the [`Compiler`], which fuses, compiles
    /// and parses sections into a cwasm and its metadata, the cwasm streaming
    /// back as it comes. `for_whom` names the caller on the debug log.
    ///
    /// Errors:
    ///   * an [`InitError`] — an artifact the pins name could not be pulled, and
    ///     asking again will not change that ([`pull_failure`]); or the compiler
    ///     refused the composition, as it always will the same pins
    ///   * 503 — the registry, the KBS, the hatch or the consumer's turn did not
    ///     answer in time
    ///   * 500 — anything else in the compile, or an infra problem
    pub async fn compile(
        &self,
        composition: &Composition,
        for_whom: &str,
    ) -> Result<Compiled, Unavailable> {
        // Look up the bearer for the policy registry by hostname. Same
        // lookup applies per plugin below. Missing entry collapses to an
        // empty slice ⇒ anonymous pull (host attaches no Authorization
        // header).
        let policy_bearer =
            policy_pull::bearer_for_ref(&composition.registry_auth, &composition.policy_ref);

        // Context for the `kbs` key path: the hatch relay client that
        // couriers each RCAR leg. Shared by the policy and every plugin pull;
        // inline / plaintext artifacts ignore it.
        let kbs_ctx = crate::keyprovider::KbsContext { kbs: &self.kbs };

        // Every fetch below takes one of the consumer's turns, so this compile and
        // the consumer's other sessions together hold no more of the hatch than
        // their share.
        let turns = &self.consumer_turns.of(&composition.consumer);

        // Every manifest first, concurrently, with every key it needs: all that
        // can be refused before a byte of wasm moves, so the /connect critical
        // path waits on the slowest of them rather than on their sum.
        let policy_fut = policy_pull::wasm_layer(
            &self.registry,
            turns,
            &composition.policy_ref,
            policy_bearer,
            composition.policy_key.as_ref(),
            Some(&kbs_ctx),
        );
        let plugin_futs = composition.plugins.iter().map(|pin| {
            let bearer = policy_pull::bearer_for_ref(&composition.registry_auth, &pin.impl_ref);
            let registry = &self.registry;
            let kbs_ctx = &kbs_ctx;
            async move {
                policy_pull::wasm_layer(
                    registry,
                    turns,
                    &pin.impl_ref,
                    bearer,
                    pin.key.as_ref(),
                    Some(kbs_ctx),
                )
                .await
                .map(|layer| (pin.package.clone(), layer))
            }
        });
        let (policy_res, plugin_results) =
            futures::future::join(policy_fut, futures::future::join_all(plugin_futs)).await;

        let policy = policy_res.map_err(|e| {
            safe_logger::debug!(
                "compile: the policy's manifest failed for {for_whom} (policy_ref={}): {e}",
                composition.policy_ref,
            );
            pull_failure(Artifact::Policy, &e)
        })?;
        let mut plugins = Vec::with_capacity(plugin_results.len());
        for (pin, res) in composition.plugins.iter().zip(plugin_results) {
            plugins.push(res.map_err(|e| {
                safe_logger::debug!("compile: a plugin's manifest failed for {for_whom}: {e}");
                pull_failure(Artifact::Plugin(pin.package.clone()), &e)
            })?);
        }

        // Then the layers themselves, one after another in composition order —
        // policy first — as one stream into the COMPILE boundary: each fetched
        // when the one before it has been read, so no fetch waits half-read on
        // another. The compile-worker fuses + compiles + parses sections into a
        // cwasm and its metadata (the i18n/icons import manifest + per-component
        // catalogs, composition order), starting only once every component has
        // arrived whole. The caller passes the cwasm on as it streams back — to
        // L2, and for a round to the execution-worker, which files it in its L1.
        //
        // A layer that does not arrive, or turns out not to be what its manifest
        // pinned, ends the stream in an error, which the compile answers as a
        // failure; marked here, so it is answered as the pull failure it is, as a
        // manifest's would be.
        let policy_length = policy.length();
        let lengths = plugins
            .iter()
            .map(|(package, layer)| (package.clone(), layer.length()))
            .collect();
        let pull_failed = Arc::new(std::sync::OnceLock::new());
        let marked = pull_failed.clone();
        let layers = std::iter::once((Artifact::Policy, policy)).chain(
            plugins
                .into_iter()
                .map(|(package, layer)| (Artifact::Plugin(package), layer)),
        );
        let components = futures::stream::iter(layers)
            .flat_map(|(artifact, layer)| layer.pieces().map_err(move |e| (artifact.clone(), e)))
            .inspect_err(move |(artifact, e)| {
                safe_logger::debug!("compile: a layer did not arrive as pinned: {e}");
                let _ = marked.set((artifact.clone(), e.problem()));
            });
        let source = CompileSource::streamed(policy_length, lengths, components);
        let compiled = match source {
            Some(source) => self.compiler.compile(source).await,
            None => Err(CompileError::Refused(CompileFault::TooLarge)),
        };
        compiled.map_err(|e| match pull_failed.get() {
            Some((artifact, problem)) => unavailable(artifact.clone(), *problem),
            None => classify_compile_error(for_whom, &composition.policy_ref, e),
        })
    }
}

/// What a failed pull of `artifact` makes of the request: the session's
/// [`InitError`] when the answer is the pins' and asking again will not change
/// it — a refusal, an artifact absent, not what its pin names, or not one its
/// keys open — and otherwise 503, the same request later.
pub fn pull_failure(artifact: Artifact, e: &policy_pull::PullError) -> Unavailable {
    unavailable(artifact, e.problem())
}

fn unavailable(artifact: Artifact, problem: Option<PullProblem>) -> Unavailable {
    match problem {
        Some(problem) => Unavailable::Init(InitError::Pull { artifact, problem }),
        None => StatusCode::SERVICE_UNAVAILABLE.into(),
    }
}

/// What a compile that produced no bundle makes of the request: a refusal is
/// the composition's and permanent — the compiler decided it from the pinned
/// bytes alone — so it is the session's [`InitError`], kept as the compiler
/// gave it. Anything else is a 500: what failed may be the pins' or ours, and
/// this side cannot tell which.
fn classify_compile_error(for_whom: &str, policy_ref: &str, e: CompileError) -> Unavailable {
    safe_logger::debug!("compile: failed for {for_whom} (policy_ref {policy_ref}): {e}");
    match e {
        CompileError::Refused(fault) => Unavailable::Init(InitError::Compile(fault)),
        CompileError::Failed => StatusCode::INTERNAL_SERVER_ERROR.into(),
    }
}

/// Content-address of a fused composition: each artifact (policy + ORDERED
/// plugins) as `(ref, decrypt key)`. The compiled bundle is a pure function of
/// the pulled-and-decrypted artifact bytes and nothing session-specific, so it
/// is the right cache key — sessions pinning the same artifacts share one
/// pull + fuse + Cranelift compile.
///
/// **A cache HIT skips the two gates a MISS goes through** (download, then
/// decrypt) — it hands back the already pulled-and-decrypted component. The two
/// are kept in different places:
///   * **Download** is asked of the registry by every session, hit or miss
///     (`check_pull` in `crate::init`), so the OCI bearer is NOT in the key
///     and every consumer the registry lets pull an artifact shares its compile.
///     For a third-party LICENSED plugin the bearer is the license, and that check
///     is the license check. A ref names registry, repository and digest, and a
///     registry grants pull per repository, so a session allowed the ref is
///     allowed exactly the bytes that were compiled.
///   * **Decrypt authority** — the [`Key`] — is in the key ([`Decrypt`]):
///     plaintext shares; an inline key (the owner's secret) only with holders of
///     the same key; a KBS with anyone. Encryption's job is secrecy from the
///     PLATFORM (KBS releases only to the attested TEE), NOT per-client
///     licensing — that is the download gate — so a KBS needs no per-client
///     credential here. (A metered/licensed KBS would be consulted every session
///     as the registry is, never folded into this key: the cache only ever skips
///     the decrypt+compile, never a per-session check.)
///
/// The pins are written as CBOR — every string and list carrying its length,
/// the plugins in fusion order, which fixes merged first-match — and that is
/// hashed. Refs are digest-pinned (session create refuses a tag), so one key
/// never names two different contents.
pub fn composition_key(
    policy_ref: &str,
    policy_key: Option<&Key>,
    plugins: &[PluginPin],
) -> CompositionKey {
    let inputs = Inputs {
        policy: ArtifactInput::new(policy_ref, policy_key),
        plugins: plugins
            .iter()
            .map(|pin| Plugin {
                package: &pin.package,
                artifact: ArtifactInput::new(&pin.impl_ref, pin.key.as_ref()),
            })
            .collect(),
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&inputs, &mut cbor)
        .expect("CBOR into memory fails only on a write, and a Vec refuses none");
    // Handed to the type as a DIGEST, not as a rendering of one. There is no
    // fallible constructor to get this wrong with: what leaves here has the shape
    // the worker's decoder demands because it could not have had another.
    CompositionKey::from_digest(Sha256::digest(&cbor).into())
}

/// What a compile is a function of, and nothing besides — what
/// [`composition_key`] hashes.
#[derive(Serialize)]
struct Inputs<'a> {
    policy: ArtifactInput<'a>,
    /// In fusion order.
    plugins: Vec<Plugin<'a>>,
}

#[derive(Serialize)]
struct Plugin<'a> {
    package: &'a str,
    artifact: ArtifactInput<'a>,
}

/// One artifact: its digest-pinned ref, and what decrypts it.
#[derive(Serialize)]
struct ArtifactInput<'a> {
    reference: &'a str,
    decrypt: Decrypt,
}

impl<'a> ArtifactInput<'a> {
    fn new(reference: &'a str, key: Option<&Key>) -> Self {
        let decrypt = match key {
            None => Decrypt::Nothing,
            Some(Key::Inline(bytes)) => Decrypt::InlineKey(Sha256::digest(bytes).into()),
            Some(Key::Kbs(_)) => Decrypt::Kbs,
        };
        Self { reference, decrypt }
    }
}

/// What decrypts an artifact, as far as sharing its compile goes.
#[derive(Serialize)]
enum Decrypt {
    /// Not encrypted: shared with anyone.
    Nothing,
    /// A key given inline, by its digest — never the key itself, so nothing
    /// hashed holds the secret: shared with its holders alone.
    InlineKey([u8; 32]),
    /// A KBS, which releases to any attested enclave: shared with anyone.
    Kbs,
}

#[cfg(test)]
mod tests;
