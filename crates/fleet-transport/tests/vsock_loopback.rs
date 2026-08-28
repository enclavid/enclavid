//! The vsock arm carrying real bytes, over the kernel's loopback CID.
//!
//! Ignored by default: it needs the `vsock_loopback` module loaded, which is an
//! environment fact rather than a property of this code, and a machine without
//! it would report a failure that means nothing about the crate. Run it where
//! that holds:
//!
//! ```text
//! sudo modprobe vsock_loopback
//! cargo test -p fleet-transport --features vsock -- --ignored --nocapture
//! ```
//!
//! What it proves is narrow and worth proving: that `bind` and `dial` name the
//! same socket, and that a stream from this crate carries bytes both ways. The
//! two-hop splice a real fleet leg needs is host-relay's job, not this crate's.

#![cfg(all(feature = "vsock", target_os = "linux"))]

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// `VMADDR_CID_LOCAL` — the kernel talking to itself, so no guest is needed.
const CID_LOCAL: u32 = 1;

/// A port unlikely to collide with anything else on the machine running this.
const PORT: u32 = 60123;

#[tokio::test]
#[ignore = "needs the vsock_loopback kernel module"]
async fn a_dialed_stream_carries_bytes_both_ways() {
    let mut listener = fleet_transport::bind(&PORT.to_string())
        .await
        .expect("bind vsock listener");

    let server = tokio::spawn(async move {
        let (mut stream, peer) = listener.accept().await.expect("accept");
        println!("accepted from {peer}");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.expect("server read");
        assert_eq!(&buf, b"hello");
        stream.write_all(b"world").await.expect("server write");
        stream.flush().await.unwrap();
    });

    let mut client = fleet_transport::dial(&format!("vsock://{CID_LOCAL}:{PORT}"))
        .await
        .expect("dial vsock");
    client.write_all(b"hello").await.expect("client write");
    client.flush().await.unwrap();
    let mut buf = [0u8; 5];
    client.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"world");

    server.await.unwrap();
}
