//! The channel between a round and a coprocess it started: the socket the
//! supervisor paired them with, carrying one message at a time — a serde value
//! in CBOR, after its length as a big-endian `u32`. The round asks and awaits
//! the response; the coprocess reads a request and writes its response.
//!
//! Each end reads what the other wrote and trusts none of it: a message's
//! length is held to the most its reader takes before anything is allocated
//! for it, and its body must be exactly one value of the type asked for. CBOR
//! decodes a byte string by reading it, never by reserving the length it
//! claims, so no body makes its reader hold more than the body.
//!
//! A coprocess's end, [`send`] and [`receive`], blocks on its socket and links
//! no runtime: a coprocess keeps itself to reading and writing that socket.
//! The round's end, [`Channel`] behind the `tokio` feature, awaits it.

use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

#[cfg(feature = "tokio")]
mod round;
#[cfg(feature = "tokio")]
pub use round::Channel;

#[cfg(test)]
mod tests;

/// Why a message could not be sent or read.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("the socket: {0}")]
    Io(#[from] io::Error),
    #[error("a message of {0} bytes, more than its reader takes")]
    TooLong(usize),
    #[error("a message that is not one value of the type asked for")]
    Malformed,
    #[error("a message that does not encode")]
    Unencodable,
}

/// Write `message`: its length, then its body.
pub fn send(to: &mut impl Write, message: &impl Serialize) -> Result<(), ChannelError> {
    let (head, body) = encode(message)?;
    to.write_all(&head)?;
    to.write_all(&body)?;
    to.flush()?;
    Ok(())
}

/// Read a message of at most `max` bytes, as a `T`; `None` where the other
/// end closed the socket before starting one.
pub fn receive<T: DeserializeOwned>(
    from: &mut impl Read,
    max: usize,
) -> Result<Option<T>, ChannelError> {
    let mut head = [0u8; 4];
    if from.read(&mut head[..1])? == 0 {
        return Ok(None);
    }
    from.read_exact(&mut head[1..])?;
    let mut body = vec![0u8; length(head, max)?];
    from.read_exact(&mut body)?;
    decode(&body).map(Some)
}

/// `message` as it is written: the head that gives its length, and its body.
fn encode(message: &impl Serialize) -> Result<([u8; 4], Vec<u8>), ChannelError> {
    let mut body = Vec::new();
    ciborium::into_writer(message, &mut body).map_err(|_| ChannelError::Unencodable)?;
    let length = u32::try_from(body.len()).map_err(|_| ChannelError::TooLong(body.len()))?;
    Ok((length.to_be_bytes(), body))
}

/// The length a message's `head` gives, held to `max`.
fn length(head: [u8; 4], max: usize) -> Result<usize, ChannelError> {
    let length = u32::from_be_bytes(head) as usize;
    if length > max {
        return Err(ChannelError::TooLong(length));
    }
    Ok(length)
}

/// The value `body` holds: exactly one `T`, and nothing after it.
fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ChannelError> {
    let mut rest = body;
    let value = ciborium::from_reader(&mut rest).map_err(|_| ChannelError::Malformed)?;
    if !rest.is_empty() {
        return Err(ChannelError::Malformed);
    }
    Ok(value)
}
