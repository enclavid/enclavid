//! One stream read by two at once.
//!
//! A cold compile's cwasm goes to the worker that runs the round and to the
//! cache that keeps it, from the one stream the compile-worker sends. Neither is
//! handed it whole, and this process holds a few pieces of it at a time.

use std::future::Future;

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use tokio::sync::mpsc;

/// How far the stream may be read ahead of a reader, in pieces: a few, so the
/// two take it at the pace of the slower without either waiting on every piece.
const AHEAD: usize = 4;

/// What a reader of a [`tee`] is given: the source's pieces, and an error where
/// the source failed.
pub type Branch = BoxStream<'static, Result<Bytes, ()>>;

/// `source`, read once and given to two readers as they read it: the future
/// that reads it, and the two readers.
///
/// The future must run while the readers are read. It reads at the pace of the
/// slower reader; a reader that stops — drops its stream — is left behind, and
/// the other goes on. A failure of `source` reaches both readers as an error,
/// which ends their streams there, so a reader passing them on abandons its own
/// stream rather than finishing it.
pub fn tee<E: Send + 'static>(
    source: BoxStream<'static, Result<Bytes, E>>,
) -> (impl Future<Output = ()> + Send, Branch, Branch) {
    let (a, a_rx) = mpsc::channel(AHEAD);
    let (b, b_rx) = mpsc::channel(AHEAD);
    let feed = async move {
        let mut source = source;
        let mut readers = [Some(a), Some(b)];
        while readers.iter().any(Option::is_some) {
            // A clean end drops the senders, which ends both readers' streams.
            let Some(next) = source.next().await else {
                break;
            };
            let failed = next.is_err();
            let piece = next.map_err(|_| ());
            for reader in &mut readers {
                let gone = match reader {
                    Some(tx) => tx.send(piece.clone()).await.is_err(),
                    None => false,
                };
                if gone {
                    *reader = None;
                }
            }
            if failed {
                break;
            }
        }
    };
    (feed, branch(a_rx), branch(b_rx))
}

fn branch(rx: mpsc::Receiver<Result<Bytes, ()>>) -> Branch {
    futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|piece| (piece, rx))
    })
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(pieces: Vec<Result<&'static [u8], ()>>) -> BoxStream<'static, Result<Bytes, ()>> {
        futures::stream::iter(
            pieces
                .into_iter()
                .map(|p| p.map(Bytes::from_static))
                .collect::<Vec<_>>(),
        )
        .boxed()
    }

    async fn read(branch: Branch) -> Vec<Result<Bytes, ()>> {
        branch.collect().await
    }

    #[tokio::test]
    async fn both_readers_get_every_piece() {
        let pieces: Vec<Result<&[u8], ()>> = (0..20).map(|_| Ok(&b"abc"[..])).collect();
        let (feed, a, b) = tee(source(pieces));
        let ((), a, b) = tokio::join!(feed, read(a), read(b));
        assert_eq!(a.len(), 20);
        assert_eq!(a, b);
    }

    /// A reader that stops does not stop the other.
    #[tokio::test]
    async fn a_reader_that_stops_leaves_the_other_reading() {
        let pieces: Vec<Result<&[u8], ()>> = (0..50).map(|_| Ok(&b"abc"[..])).collect();
        let (feed, a, b) = tee(source(pieces));
        drop(a);
        let ((), b) = tokio::join!(feed, read(b));
        assert_eq!(b.len(), 50);
    }

    /// The source's failure reaches both, and nothing after it does.
    #[tokio::test]
    async fn a_failure_reaches_both_readers_and_ends_them() {
        let (feed, a, b) = tee(source(vec![Ok(b"one"), Err(()), Ok(b"after")]));
        let ((), a, b) = tokio::join!(feed, read(a), read(b));
        assert_eq!(a, vec![Ok(Bytes::from_static(b"one")), Err(())]);
        assert_eq!(a, b);
    }
}
