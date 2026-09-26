//! How long a caller's request body may take.
//!
//! A request holds one of its member's places until api's answer starts, and
//! api reads a body whole before it answers. So a body that arrives slowly
//! holds that place for as long as it takes — and a caller with a live session
//! could hold every place a member has with a few bodies it never finishes,
//! shutting every other caller out of that member.
//!
//! Two bounds, because either alone can be walked around: a pause between two
//! frames (`request_body_pause`), and the whole body from the request's head
//! (`request_body_timeout`). A caller sending a byte just inside every pause
//! trips the second; one that stalls outright trips the first, long before.
//!
//! Both are layers of the stack each request is answered by — see
//! `crate::listener`: `tower-http`'s `MapRequestBodyLayer` wraps the body in a
//! [`Deadline`], and its `RequestBodyTimeoutLayer` bounds the pauses in that.
//!
//! A body past either is cut off: the request to api is reset, and the caller
//! is answered as for any request that failed behind this role.
//!
//! ## No trailers
//!
//! Trailers are headers sent after a body, so anything `crate::route` takes off
//! a request's head could travel there instead and reach api untouched. None go
//! on at all — see [`untrailed`]. Nothing a browser sends has them.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::MapFrame;
use hyper::body::{Body, Frame, SizeHint};
use tower::BoxError;

/// A body with its trailers taken off — see [`untrailed`].
pub type Untrailed<B> = MapFrame<B, fn(Frame<Bytes>) -> Frame<Bytes>>;

/// `body` with its trailers taken off.
///
/// Trailers are a body's last frame, so the frame that held them becomes an
/// empty one of data and the body ends as it would have.
pub fn untrailed<B>(body: B) -> Untrailed<B>
where
    B: Body<Data = Bytes>,
{
    body.map_frame(|frame| match frame.into_trailers() {
        Ok(_) => Frame::data(Bytes::new()),
        Err(frame) => frame,
    })
}

/// A bounded body, boxed into what a leg carries.
pub fn boxed<B>(body: B) -> crate::upstream::member::Sent
where
    B: Body<Data = bytes::Bytes, Error = BoxError> + Send + Sync + 'static,
{
    http_body_util::BodyExt::boxed(body)
}

/// A body that must end within a deadline set when it was made.
pub struct Deadline<B> {
    body: B,
    ends: Pin<Box<tokio::time::Sleep>>,
    ended: bool,
}

impl<B> Deadline<B> {
    pub fn new(body: B, within: Duration) -> Deadline<B> {
        Deadline {
            body,
            ends: Box::pin(tokio::time::sleep(within)),
            ended: false,
        }
    }
}

/// A body past its deadline. Says nothing of what did arrive.
#[derive(Debug)]
pub struct TooSlow;

impl std::fmt::Display for TooSlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the request body did not arrive in time")
    }
}

impl std::error::Error for TooSlow {}

impl<B> Body for Deadline<B>
where
    B: Body + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<B::Data>, BoxError>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        if this.ends.as_mut().poll(cx).is_ready() {
            this.ended = true;
            return Poll::Ready(Some(Err(Box::new(TooSlow))));
        }
        match Pin::new(&mut this.body).poll_frame(cx) {
            Poll::Ready(None) => {
                this.ended = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(frame)) => Poll::Ready(Some(frame.map_err(Into::into))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended || self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use http_body_util::BodyExt;
    use http_body_util::channel::Channel;
    use tower_http::timeout::TimeoutBody;

    /// Both bounds around a body a test controls, composed as the listener's
    /// layers compose them: the deadline inside, the pause around it.
    fn bounded_test(
        body: Channel<Bytes, BoxError>,
        pause: Duration,
        whole: Duration,
    ) -> impl Body<Data = Bytes, Error = BoxError> {
        TimeoutBody::new(pause, Deadline::new(body, whole))
    }

    /// A body that arrives in time arrives whole.
    #[tokio::test]
    async fn a_body_in_time_arrives_whole() {
        let (mut tx, body) = Channel::<Bytes, BoxError>::new(1);
        tokio::spawn(async move {
            for _ in 0..3 {
                tx.send_data(Bytes::from_static(b"part")).await.unwrap();
            }
        });
        let got = bounded_test(body, Duration::from_secs(1), Duration::from_secs(5))
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&got[..], b"partpartpart");
    }

    /// A body that stops sending is cut off after the pause, long before the
    /// whole body's deadline.
    #[tokio::test]
    async fn a_body_that_stalls_is_cut_off_after_the_pause() {
        let (mut tx, body) = Channel::<Bytes, BoxError>::new(1);
        tx.send_data(Bytes::from_static(b"start")).await.unwrap();
        let started = std::time::Instant::now();
        let got = bounded_test(body, Duration::from_millis(100), Duration::from_secs(10))
            .collect()
            .await;
        assert!(got.is_err());
        assert!(started.elapsed() < Duration::from_secs(2), "by the pause");
        drop(tx);
    }

    /// A body's trailers are taken off, and its data arrives whole.
    #[tokio::test]
    async fn a_body_arrives_without_its_trailers() {
        let (mut tx, body) = Channel::<Bytes, BoxError>::new(2);
        tx.send_data(Bytes::from_static(b"part")).await.unwrap();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        tx.send_trailers(trailers).await.unwrap();
        drop(tx);

        let got = untrailed(body).collect().await.unwrap();
        assert!(got.trailers().is_none());
        assert_eq!(&got.to_bytes()[..], b"part");
    }

    /// A body that never pauses long but never ends is cut off at the whole
    /// body's deadline — which the pause alone would never do.
    #[tokio::test]
    async fn a_body_that_trickles_is_cut_off_at_the_deadline() {
        let (mut tx, body) = Channel::<Bytes, BoxError>::new(1);
        tokio::spawn(async move {
            while tx.send_data(Bytes::from_static(b".")).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });
        let started = std::time::Instant::now();
        let got = bounded_test(body, Duration::from_millis(100), Duration::from_millis(400))
            .collect()
            .await;
        assert!(got.is_err());
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(400) && took < Duration::from_secs(2),
            "at the deadline, took {took:?}"
        );
    }
}
