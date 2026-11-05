use std::io::Cursor;

use serde::Deserialize;

use super::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum Message {
    Number(u32),
    Text(String),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Other {
    number: u32,
}

fn sent(message: &impl Serialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    send(&mut bytes, message).expect("it sends");
    bytes
}

/// A message of `body` as it is, whatever it holds.
fn framed(body: &[u8]) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

/// Messages read back as they were sent, one after another, and a socket
/// closed before the next is none.
#[test]
fn messages_read_back_as_sent() {
    let mut bytes = sent(&Message::Number(7));
    bytes.extend(sent(&Message::Text("frame".into())));
    let mut from = Cursor::new(bytes);
    assert_eq!(
        receive::<Message>(&mut from, 64).unwrap(),
        Some(Message::Number(7))
    );
    assert_eq!(
        receive::<Message>(&mut from, 64).unwrap(),
        Some(Message::Text("frame".into()))
    );
    assert_eq!(receive::<Message>(&mut from, 64).unwrap(), None);
}

/// A message longer than its reader takes is refused from its length alone:
/// nothing of its body is read, or allocated for.
#[test]
fn a_message_past_its_bound_is_refused_before_its_body() {
    let head = (65u32).to_be_bytes().to_vec();
    assert!(matches!(
        receive::<Message>(&mut Cursor::new(head), 64),
        Err(ChannelError::TooLong(65))
    ));
}

/// A body is one value of the type asked for and nothing else: another type,
/// a value with bytes after it and one cut short are all refused.
#[test]
fn a_body_that_is_not_one_value_is_refused() {
    let other = sent(&Other { number: 7 });
    assert!(matches!(
        receive::<Message>(&mut Cursor::new(other), 64),
        Err(ChannelError::Malformed)
    ));

    let mut body = sent(&Message::Number(7)).split_off(4);
    body.push(0);
    assert!(matches!(
        receive::<Message>(&mut Cursor::new(framed(&body)), 64),
        Err(ChannelError::Malformed)
    ));

    let mut short = framed(&sent(&Message::Text("frame".into()))[4..]);
    short.pop();
    assert!(matches!(
        receive::<Message>(&mut Cursor::new(short), 64),
        Err(ChannelError::Io(_))
    ));
}

/// A byte string that claims more than its body holds is refused, not
/// reserved for.
#[test]
fn a_byte_string_claiming_more_than_its_body_is_refused() {
    // CBOR: a byte string of 2^32 - 1 bytes, and none of them.
    let body = [0x5a, 0xff, 0xff, 0xff, 0xff];
    assert!(matches!(
        receive::<serde_bytes::ByteBuf>(&mut Cursor::new(framed(&body)), 64),
        Err(ChannelError::Malformed)
    ));
}

#[cfg(feature = "tokio")]
mod round {
    use std::os::unix::net::UnixStream;

    use super::*;

    /// A coprocess's end, on a thread of its own: writes `response` of each
    /// request, until the round lets go — closing the socket, or, on Linux,
    /// resetting it where it closes with a response left unread.
    fn coprocess(
        mut socket: UnixStream,
        response: impl Fn(Message) -> Vec<u8> + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            while let Ok(Some(request)) = receive::<Message>(&mut socket, 64) {
                if socket.write_all(&response(request)).is_err() {
                    return;
                }
            }
        })
    }

    /// The round asks, and reads the response to each request in turn.
    #[tokio::test]
    async fn the_round_reads_each_response() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let served = coprocess(theirs, |request| match request {
            Message::Number(n) => sent(&Message::Number(n + 1)),
            Message::Text(t) => sent(&Message::Text(t.to_uppercase())),
        });
        let mut channel = Channel::new(ours).unwrap();
        let first: Message = channel.ask(&Message::Number(1), 64).await.unwrap();
        let second: Message = channel.ask(&Message::Text("x".into()), 64).await.unwrap();
        assert_eq!(first, Message::Number(2));
        assert_eq!(second, Message::Text("X".into()));
        drop(channel);
        served.join().unwrap();
    }

    /// A response longer than the round takes is refused from its length, and
    /// a coprocess that closes the socket instead of responding is an error.
    #[tokio::test]
    async fn a_response_past_its_bound_or_none_is_an_error() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let served = coprocess(theirs, |_| sent(&Message::Text("x".repeat(100))));
        let mut channel = Channel::new(ours).unwrap();
        let long = channel.ask::<Message>(&Message::Number(1), 64).await;
        assert!(matches!(long, Err(ChannelError::TooLong(_))));
        drop(channel);
        served.join().unwrap();

        let (ours, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        let mut channel = Channel::new(ours).unwrap();
        let none = channel.ask::<Message>(&Message::Number(1), 64).await;
        assert!(matches!(none, Err(ChannelError::Io(_))));
    }
}
