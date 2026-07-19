//! Execute boundary — run + mid-call callbacks (the bidirectional case).
//!
//! Gated behind the `execute` feature: an execution-worker built with only
//! this feature links the executor + callback contract + `broker-client`,
//! and NOT the compiler contract or `engine-types` — least-knowledge for
//! its measured image.

use serde::{Deserialize, Serialize};

use broker_client::{Event, SessionState};

/// A run failure or an absorbed RPC transport error.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecError(pub String);

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "run failed: {}", self.0)
    }
}
impl std::error::Error for ExecError {}
impl From<remoc::rtc::CallError> for ExecError {
    fn from(err: remoc::rtc::CallError) -> Self {
        ExecError(format!("run rpc failed: {err}"))
    }
}

/// A callback failure or an absorbed RPC transport error.
#[derive(Debug, Serialize, Deserialize)]
pub struct CallbackError(pub String);

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "callback failed: {}", self.0)
    }
}
impl std::error::Error for CallbackError {}
impl From<remoc::rtc::CallError> for CallbackError {
    fn from(err: remoc::rtc::CallError) -> Self {
        CallbackError(format!("callback rpc failed: {err}"))
    }
}

/// A callback failure surfacing inside a run bubbles up as a run failure — the
/// worker's `?` on a mid-run callback converts here.
impl From<CallbackError> for ExecError {
    fn from(err: CallbackError) -> Self {
        ExecError(format!("callback during run: {}", err.0))
    }
}

/// One reducer round's inputs on the wire.
///
/// `cwasm` / `props` are added with the executor-worker wiring (the worker
/// caches the deserialized component per composition, so cwasm rides only the
/// first run for a composition; `props` needs a serde mirror for the bindgen
/// `Prop`). `session_state` / `event` are the engine's own serde domain types.
#[derive(Serialize, Deserialize)]
pub struct RunRequest {
    pub session_state: SessionState,
    pub event: Event,
}

/// One reducer round's result on the wire.
///
/// The typed `RunStatus` projection (a serde mirror of the borrowed engine enum)
/// is added with the wiring; `done` is the terminal marker used for the
/// bidirectional-pattern proof until then.
#[derive(Serialize, Deserialize)]
pub struct RunReply {
    pub new_state: SessionState,
    pub done: bool,
}

/// The orchestrator-served CALLBACK boundary the keyless execution-worker calls
/// BACK during a run: the worker holds no seal key, so blob rehydration
/// (`media_load`) and state persistence (`session_change`) happen
/// orchestrator-side. A [`CallbackServiceClient`] is passed to the worker as an
/// argument to [`ExecutorService::run`] — remoc multiplexes the callback calls
/// over the SAME connection as the in-flight run, so the key never crosses to
/// the worker and there is no hand-rolled request-id duplex.
#[remoc::rtc::remote]
pub trait CallbackService {
    /// Rehydrate a stored blob by content hash (orchestrator unseals). `None` =
    /// miss (unknown / never-stored ref).
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError>;

    /// Seal + persist the post-round session state. (The consented-disclosure +
    /// captured-media co-commit — the owned form of the engine's borrowed
    /// `SessionChange` — is added with the wiring as additive `#[serde(default)]`
    /// args, keeping this backward-compatible.)
    async fn session_change(&self, new_state: SessionState) -> Result<(), CallbackError>;
}

/// The execute boundary as a remote trait. The execution-worker serves it; the
/// orchestrator calls [`run`](ExecutorService::run), passing a
/// [`CallbackServiceClient`] pointing at its own callback server so the keyless
/// worker can rehydrate media / persist state mid-round without ever holding the
/// seal key.
#[remoc::rtc::remote]
pub trait ExecutorService {
    async fn run(
        &self,
        req: RunRequest,
        callbacks: CallbackServiceClient<remoc::codec::Ciborium>,
    ) -> Result<RunReply, ExecError>;
}

#[cfg(test)]
mod execute_tests {
    use super::*;
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;
    use std::sync::{Arc, Mutex};
    use tokio::io::split;

    /// Orchestrator-side callback target: records the calls it receives and
    /// returns canned media, so the test can assert the worker called BACK with
    /// the right arguments mid-run.
    struct MockCallbacks {
        media_calls: Mutex<Vec<[u8; 32]>>,
        state_calls: Mutex<u32>,
    }

    impl CallbackService for MockCallbacks {
        async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
            self.media_calls.lock().unwrap().push(hash);
            Ok(Some(vec![0xAB, 0xCD]))
        }
        async fn session_change(&self, _new_state: SessionState) -> Result<(), CallbackError> {
            *self.state_calls.lock().unwrap() += 1;
            Ok(())
        }
    }

    /// Worker-side executor: during `run`, calls the passed-in callback client
    /// (media_load + session_change) BACK to the orchestrator, then replies.
    struct MockExecutor;

    impl ExecutorService for MockExecutor {
        async fn run(
            &self,
            req: RunRequest,
            callbacks: CallbackServiceClient<Ciborium>,
        ) -> Result<RunReply, ExecError> {
            let bytes = callbacks.media_load([9u8; 32]).await?;
            if bytes != Some(vec![0xAB, 0xCD]) {
                return Err(ExecError("callback returned wrong media".into()));
            }
            callbacks.session_change(req.session_state.clone()).await?;
            Ok(RunReply {
                new_state: req.session_state,
                done: true,
            })
        }
    }

    type ExecCli = ExecutorServiceClient<Ciborium>;

    /// The bidirectional gate: `run()` crosses to the worker WITH a callback
    /// client argument; the keyless worker invokes `media_load` + `session_change`
    /// BACK to the orchestrator mid-run, all multiplexed over the ONE remoc
    /// connection. This is the pattern that removes the hand-rolled duplex.
    #[tokio::test]
    async fn execute_bidirectional_callbacks_over_remoc() {
        let callbacks = Arc::new(MockCallbacks {
            media_calls: Mutex::new(Vec::new()),
            state_calls: Mutex::new(0),
        });

        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = split(a);
        let (b_r, b_w) = split(b);

        // Worker end: serve the executor.
        let server_task = tokio::spawn(async move {
            let (conn, mut tx, _rx) =
                remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(remoc::Cfg::default(), a_r, a_w)
                    .await
                    .unwrap();
            tokio::spawn(conn);
            let (server, client) =
                ExecutorServiceServerShared::<_, Ciborium>::new(Arc::new(MockExecutor), 4);
            tx.send(client).await.unwrap();
            server.serve(true).await.unwrap();
        });

        // Orchestrator end: receive the executor client, stand up its OWN
        // callback server on the same connection, pass the callback client into
        // run().
        let (conn, _tx, mut rx) =
            remoc::Connect::io::<_, _, ExecCli, ExecCli, Ciborium>(remoc::Cfg::default(), b_r, b_w)
                .await
                .unwrap();
        tokio::spawn(conn);
        let exec_client = rx.recv().await.unwrap().unwrap();

        let (cb_server, cb_client) =
            CallbackServiceServerShared::<_, Ciborium>::new(callbacks.clone(), 4);
        tokio::spawn(async move {
            let _ = cb_server.serve(true).await;
        });

        let reply = exec_client
            .run(
                RunRequest {
                    session_state: SessionState::default(),
                    event: Event::Start,
                },
                cb_client,
            )
            .await
            .unwrap();

        assert!(reply.done);
        assert_eq!(callbacks.media_calls.lock().unwrap().as_slice(), &[[9u8; 32]]);
        assert_eq!(*callbacks.state_calls.lock().unwrap(), 1);

        drop(exec_client);
        server_task.abort();
    }
}
