//! The round's end of a channel, awaited on the round's runtime.

use std::os::unix::net;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::{ChannelError, decode, encode, length};

/// The round's end of its channel to a coprocess.
pub struct Channel(UnixStream);

impl Channel {
    /// The round's end of `socket`, whose other end a coprocess holds.
    pub fn new(socket: net::UnixStream) -> std::io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self(UnixStream::from_std(socket)?))
    }

    /// Send `request`, and read the response: one `R`, of at most `max`
    /// bytes. An ask dropped before its response leaves the channel in the
    /// middle of a message, so a round that drops one is done with the
    /// channel.
    pub async fn ask<R: DeserializeOwned>(
        &mut self,
        request: &impl Serialize,
        max: usize,
    ) -> Result<R, ChannelError> {
        let (head, body) = encode(request)?;
        self.0.write_all(&head).await?;
        self.0.write_all(&body).await?;
        let mut head = [0u8; 4];
        self.0.read_exact(&mut head).await?;
        let mut body = vec![0u8; length(head, max)?];
        self.0.read_exact(&mut body).await?;
        decode(&body)
    }
}
