//! Compile boundary — the `CompilerService` remote trait, what crosses it, and its
//! error.
//!
//! Gated behind the `compile` feature: a compile-worker (or the
//! orchestrator's compile client) built with only this feature links the
//! compiler contract + `engine-types`, and NOT the executor contract or
//! `hatch-client` — least-knowledge for its measured image.
//!
//! Nothing large rides inside a call. A compile's components cross beside its
//! request, as ONE stream — the policy, then each plugin in composition order —
//! with the request naming each one's length; its cwasm crosses beside its reply,
//! named by length and digest. So neither direction is held to remoc's item
//! limit, and one stream rather than one per component keeps a call's ports
//! fixed however many plugins it pins.

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use fleet_stream::{BlobHeader, Incoming, StreamError, StreamLen, bin};
use futures_util::stream::BoxStream;
use futures_util::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};

use engine_types::composition::PluginInstance;

use crate::bundle::MAX_CWASM_BYTES;

/// The most bytes one compile's components may hold together: 1.5 GiB.
///
/// What the hop carries, not what compiles. The compile-worker's memory max for
/// one compile decides that, and refuses a composition past it; this leaves room
/// for model weights carried inside a plugin.
pub const MAX_COMPONENTS_BYTES: u64 = 3 * 512 * 1024 * 1024;

/// How long a compile's components or its cwasm may go without a new byte, on
/// either end of either hop: the patience a leg gives silence by default. Every
/// sender streams from what it holds or what it is passed, and has no reason to
/// pause.
pub const COMPILE_STREAM_IDLE: Duration = Duration::from_secs(20);

/// How long a compile's components or its cwasm may take to cross whole. The
/// idle deadline bounds a stall, not a trickle; this carries a stream at
/// [`MAX_COMPONENTS_BYTES`] at about 13 MiB/s, far below what a leg runs at.
pub const COMPILE_STREAM_DEADLINE: Duration = Duration::from_secs(120);

/// Why a compile produced no bundle: one of two answers, and nothing besides.
///
/// No text crosses. What failed on the far side — a wac or Cranelift message
/// naming the consumer's interfaces, a parser's complaint about a section — stays
/// on the producer's own debug log; what api receives is the one distinction it
/// answers differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompileError {
    /// The composition is one this build does not compile: its embedded
    /// catalogs, summed over the policy and every plugin, are past
    /// `MAX_EMBEDDED_SECTION_BYTES`, one of them breaks the catalog format, or
    /// the metadata it compiles to is past
    /// [`MAX_BUNDLE_META_BYTES`](crate::MAX_BUNDLE_META_BYTES), which no execute
    /// hop would take. Or its components are past [`MAX_COMPONENTS_BYTES`], or
    /// compiling it took more memory than the worker gives one compile, and the
    /// kernel killed it there. Decided from the pinned bytes and the
    /// deployment's own limits, so the same pins are refused every time on it.
    /// api answers it as a failing policy: a 422, for whoever chose the pins to
    /// clear.
    Refused,
    /// Anything else: the composition did not fuse or compile, the child died
    /// other than at its own memory max or overran its deadline, a stream broke,
    /// the leg went away. Some of these the pins decide and some are ours, and
    /// this side does not tell them apart, so api answers 500.
    Failed,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::Refused => f.write_str("the composition was refused"),
            CompileError::Failed => f.write_str("the compile failed"),
        }
    }
}
impl std::error::Error for CompileError {}

impl From<remoc::rtc::CallError> for CompileError {
    fn from(_: remoc::rtc::CallError) -> Self {
        CompileError::Failed
    }
}

/// One plugin as a compile request names it: its package, and its length in
/// the components stream.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginLength {
    pub package: String,
    pub length: StreamLen<MAX_COMPONENTS_BYTES>,
}

/// One compile's inputs on the wire: the consumer's own artifacts, already pulled
/// and digest-verified by the orchestrator against the pinned refs. What they are
/// in the request; their bytes — the policy, then each plugin in composition
/// order — in one stream beside it.
///
/// One struct rather than several arguments because that is what a scope can be
/// carried on — `Exposed` wraps a value, and the concerns this crossing raises are
/// raised about the request, not about each field of it.
///
/// No digest. It would be the sender's word about its own bytes, which the
/// attested channel under the leg already holds it to; what the lengths and the
/// one finished message give is that a compile starts only on components that
/// arrived whole.
///
/// `deny_unknown_fields`: an unknown field means the peer is speaking a contract
/// this image does not have, and failing the decode is the fail-closed answer.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileRequest {
    pub policy: StreamLen<MAX_COMPONENTS_BYTES>,
    pub plugins: Vec<PluginLength>,
    pub components: bin::Receiver,
}

impl CompileRequest {
    /// The components' length together, or `None` past [`MAX_COMPONENTS_BYTES`].
    fn total(&self) -> Option<u64> {
        self.plugins
            .iter()
            .try_fold(self.policy.get(), |sum, p| sum.checked_add(p.length.get()))
            .filter(|&total| total <= MAX_COMPONENTS_BYTES)
    }

    /// The same request toward the next hop, and the future that carries its
    /// components there — read here and written again, never forwarded as an
    /// end. `None` past [`MAX_COMPONENTS_BYTES`].
    ///
    /// The future must run while the onward call is awaited, and fails when the
    /// components do, which abandons them on the next hop too.
    pub fn relay(
        self,
    ) -> Option<(
        CompileRequest,
        impl Future<Output = Result<(), StreamError>> + Send + 'static,
    )> {
        let total = self.total()?;
        let (tx, components) = bin::channel();
        let from = self.components;
        let onward = CompileRequest {
            policy: self.policy,
            plugins: self.plugins,
            components,
        };
        let relay = async move {
            let pieces = Incoming::open(from, total, COMPILE_STREAM_IDLE)
                .await?
                .into_pieces(COMPILE_STREAM_DEADLINE, None);
            fleet_stream::send_from(tx, pieces)
                .await
                .map_err(|e| match e {
                    fleet_stream::SendError::Stream(e) | fleet_stream::SendError::Source(e) => e,
                })
        };
        Some((onward, relay))
    }

    /// Receive the components whole: the policy, and each plugin with its
    /// package. Past [`MAX_COMPONENTS_BYTES`] together they are refused before a
    /// byte is read, as [`StreamError::Long`].
    ///
    /// Each component's room is taken at its declared length, which touches no
    /// memory until its bytes arrive and are held to that length.
    pub async fn receive(self) -> Result<(Vec<u8>, Vec<PluginInstance>), StreamError> {
        let total = self.total().ok_or(StreamError::Long)?;
        let mut pieces = Incoming::open(self.components, total, COMPILE_STREAM_IDLE)
            .await?
            .into_pieces(COMPILE_STREAM_DEADLINE, None);
        let mut parts: Vec<(Option<String>, Vec<u8>, usize)> =
            std::iter::once((None, self.policy.get()))
                .chain(
                    self.plugins
                        .into_iter()
                        .map(|p| (Some(p.package), p.length.get())),
                )
                .map(|(package, len)| (package, Vec::with_capacity(len as usize), len as usize))
                .collect();
        let mut at = 0;
        while let Some(mut piece) = pieces.try_next().await? {
            while !piece.is_empty() {
                // The stream is held to the total, and the parts sum to it, so
                // a piece always has a part with room left to go into.
                while parts[at].1.len() == parts[at].2 {
                    at += 1;
                }
                let (_, bytes, len) = &mut parts[at];
                let take = (*len - bytes.len()).min(piece.len());
                bytes.extend_from_slice(&piece.split_to(take));
            }
        }
        let mut parts = parts.into_iter();
        let (_, policy, _) = parts.next().expect("the policy is always first");
        let plugins = parts
            .map(|(package, wasm, _)| PluginInstance {
                package: package.expect("every part after the policy is a plugin"),
                wasm,
            })
            .collect();
        Ok((policy, plugins))
    }
}

/// One compile's components as the door sends them: their lengths, and their
/// bytes in order as pieces the sender need not hold whole.
pub struct CompileSource {
    policy: StreamLen<MAX_COMPONENTS_BYTES>,
    plugins: Vec<PluginLength>,
    components: BoxStream<'static, Result<Bytes, ()>>,
}

impl CompileSource {
    /// Components held whole. `None` past [`MAX_COMPONENTS_BYTES`] together.
    pub fn whole(policy: Vec<u8>, plugins: Vec<PluginInstance>) -> Option<Self> {
        let total = plugins.iter().try_fold(policy.len() as u64, |sum, p| {
            sum.checked_add(p.wasm.len() as u64)
        })?;
        if total > MAX_COMPONENTS_BYTES {
            return None;
        }
        let policy_length = StreamLen::new(policy.len() as u64)?;
        let lengths = plugins
            .iter()
            .map(|p| {
                Some(PluginLength {
                    package: p.package.clone(),
                    length: StreamLen::new(p.wasm.len() as u64)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let pieces: Vec<Result<Bytes, ()>> = std::iter::once(policy)
            .chain(plugins.into_iter().map(|p| p.wasm))
            .map(|bytes| Ok(Bytes::from(bytes)))
            .collect();
        Some(Self {
            policy: policy_length,
            plugins: lengths,
            components: futures_util::stream::iter(pieces).boxed(),
        })
    }

    /// Components streamed through: the policy's length and each plugin's
    /// package and length, and `components` yielding their bytes in that order,
    /// as they come. `None` past [`MAX_COMPONENTS_BYTES`] together.
    ///
    /// The far side compiles nothing before all of it has arrived, held to the
    /// lengths, so a `components` that fails part-way — a pull that turned out
    /// not to be what it was pinned as — fails the compile and nothing else.
    pub fn streamed<S, E>(policy: u64, plugins: Vec<(String, u64)>, components: S) -> Option<Self>
    where
        S: futures_util::Stream<Item = Result<Bytes, E>> + Send + 'static,
    {
        let total = plugins
            .iter()
            .try_fold(policy, |sum, (_, len)| sum.checked_add(*len))?;
        if total > MAX_COMPONENTS_BYTES {
            return None;
        }
        let plugins = plugins
            .into_iter()
            .map(|(package, len)| {
                Some(PluginLength {
                    package,
                    length: StreamLen::new(len)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            policy: StreamLen::new(policy)?,
            plugins,
            components: components.map(|piece| piece.map_err(|_| ())).boxed(),
        })
    }

    /// Split into the request a call carries and the writer that feeds it.
    ///
    /// The writer must run while the call is awaited: the far side reads inside
    /// the call, so a writer started after it returns has nobody left to write
    /// to. For whoever drives a call on this contract — the door does; the
    /// compile-worker's own hop and its tests drive theirs.
    pub fn split(self) -> (CompileRequest, impl Future<Output = ()> + Send + 'static) {
        let (tx, components) = bin::channel();
        let source = self.components;
        (
            CompileRequest {
                policy: self.policy,
                plugins: self.plugins,
                components,
            },
            async move {
                let _ = fleet_stream::send_from(tx, source).await;
            },
        )
    }
}

/// What a compile gives back: the metadata, encoded as the execute hop streams
/// it, in the reply — at most [`MAX_BUNDLE_META_BYTES`](crate::MAX_BUNDLE_META_BYTES),
/// which the compiler holds it to where it is made — and the cwasm, named by
/// length and digest, in a stream beside it.
///
/// `deny_unknown_fields` for the reason [`CompileRequest`] carries it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileReply {
    #[serde(with = "serde_bytes")]
    pub meta: Vec<u8>,
    pub cwasm: BlobHeader<MAX_CWASM_BYTES>,
    pub body: bin::Receiver,
}

/// The compile boundary as a remote trait. The worker (compile-worker CVM)
/// serves it; the orchestrator reaches it through
/// [`CompilerLeg`](crate::CompilerLeg), never through the generated client, which
/// this crate does not export.
///
/// Given already-pulled artifact bytes (the orchestrator owns the OCI pull +
/// registry auth), the worker fuses + compiles + parses sections, and gives back
/// the cwasm and its metadata.
///
/// `&self` so the client is clonable and the server can run compiles in
/// parallel (`CompilerServiceServerShared`).
#[remoc::rtc::remote]
pub trait CompilerService {
    async fn compile(&self, req: CompileRequest) -> Result<CompileReply, CompileError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use remoc::codec::Ciborium;
    use remoc::rtc::ServerShared;
    use std::sync::Arc;
    use tokio::io::split;

    /// A mock worker that receives the components and answers with a cwasm that
    /// is their lengths, so the test proves the components and the reply's
    /// stream both cross a real connection.
    struct MockCompiler;

    impl CompilerService for MockCompiler {
        async fn compile(&self, req: CompileRequest) -> Result<CompileReply, CompileError> {
            let (policy, plugins) = req.receive().await.map_err(|_| CompileError::Failed)?;
            if policy == b"boom" {
                return Err(CompileError::Refused);
            }
            let cwasm: Vec<u8> = std::iter::once(policy.len() as u8)
                .chain(plugins.iter().map(|p| p.wasm.len() as u8))
                .collect();
            let header = BlobHeader::of(&cwasm).unwrap();
            let (tx, body) = bin::channel();
            tokio::spawn(fleet_stream::send(tx, cwasm));
            Ok(CompileReply {
                meta: plugins.iter().flat_map(|p| p.package.bytes()).collect(),
                cwasm: header,
                body,
            })
        }
    }

    type CompilerCli = CompilerServiceClient<Ciborium>;

    async fn call(
        client: &CompilerCli,
        policy: &[u8],
        plugins: Vec<PluginInstance>,
    ) -> Result<CompileReply, CompileError> {
        let (request, writer) = CompileSource::whole(policy.to_vec(), plugins)
            .unwrap()
            .split();
        let mut call = std::pin::pin!(client.compile(request));
        tokio::select! {
            reply = &mut call => reply,
            () = writer => call.await,
        }
    }

    /// The compile boundary across a real connection: the components arrive
    /// split back into the parts they were sent as, and the reply's cwasm
    /// streams back under its header; the error path crosses too.
    #[tokio::test]
    async fn compiler_service_round_trips_over_remoc() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = split(a);
        let (b_r, b_w) = split(b);

        let server_task = tokio::spawn(async move {
            let (conn, mut tx, _rx) =
                remoc::Connect::io::<_, _, CompilerCli, CompilerCli, Ciborium>(
                    remoc::Cfg::default(),
                    a_r,
                    a_w,
                )
                .await
                .unwrap();
            tokio::spawn(conn);
            let (server, client) =
                CompilerServiceServerShared::<_, Ciborium>::new(Arc::new(MockCompiler), 4);
            tx.send(client).await.unwrap();
            server.serve(true).await.unwrap();
        });

        let (conn, _tx, mut rx) = remoc::Connect::io::<_, _, CompilerCli, CompilerCli, Ciborium>(
            remoc::Cfg::default(),
            b_r,
            b_w,
        )
        .await
        .unwrap();
        tokio::spawn(conn);
        let client = rx.recv().await.unwrap().unwrap();

        let plugins = vec![
            PluginInstance {
                package: "p1".into(),
                wasm: vec![0; 3],
            },
            PluginInstance {
                package: "p2".into(),
                wasm: vec![],
            },
            PluginInstance {
                package: "p3".into(),
                wasm: vec![1; 70_000],
            },
        ];
        let reply = call(&client, b"hello", plugins).await.unwrap();
        assert_eq!(reply.meta, b"p1p2p3");
        let mut cwasm = Vec::new();
        fleet_stream::recv_exact(reply.body, &reply.cwasm, COMPILE_STREAM_IDLE, &mut cwasm)
            .await
            .unwrap();
        // policy_len=5, then each plugin's length (70_000 as u8 = 112).
        assert_eq!(cwasm, vec![5u8, 3, 0, 112]);

        let err = match call(&client, b"boom", vec![]).await {
            Err(e) => e,
            Ok(_) => panic!("expected compile error"),
        };
        assert_eq!(err, CompileError::Refused);

        drop(client);
        server_task.abort();
    }
}
