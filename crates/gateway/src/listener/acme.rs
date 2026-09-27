//! The connections an ACME validator opens, carried unopened to whatever
//! answers them.
//!
//! ## Why they reach this role at all
//!
//! TLS-ALPN-01 (RFC 8737) is validated on port 443 of the name, and behind port
//! 443 of every public name is this role: the host carries TLS through to it
//! and terminates none. A validator proves the name with a handshake and
//! nothing more — it offers one protocol, `acme-tls/1`, reads the certificate
//! and closes — so answering it takes the challenge, which the host's ACME
//! client holds and this role does not.
//!
//! So this role answers none of it. A connection that offers `acme-tls/1` and
//! nothing else is carried, with its bytes as they arrived, to the address the
//! push gives under `acme.tls-alpn-01`, and whatever listens there completes
//! the handshake. This role opens none of it and knows nothing of ACME beyond
//! that one protocol name.
//!
//! ## Which connections, and who says
//!
//! Which connections are a validator's is decided here, by what each one
//! offers, and never by the push — the push says only where they go. A browser
//! never offers `acme-tls/1`, let alone that alone, so no connection that could
//! carry an applicant's data leaves this role this way. A caller that offers it
//! anyway sends its own connection to the host, which is where its bytes came
//! from in the first place.
//!
//! Nor does the host gain anything it did not hold. Everything carried reached
//! this role through the host, which read the hello in the clear on the way
//! and could have routed the connection itself.
//!
//! ## A handshake, and bounded as one
//!
//! A validator's connection is nothing but a handshake, so the whole of it —
//! the hello, the dial, and every byte both ways — is bounded by
//! `handshake_timeout`, as a handshake is. It holds its place and its source's
//! share for as long, and a second descriptor for the leg it is carried on,
//! which the push's check already allows for: a connection may open a leg for
//! each of its streams, and it has at least one.
//!
//! ## The hello is read by rustls, as it arrives
//!
//! rustls reads the hello, for this role and for the handshake that follows
//! it, so the hello is parsed once, by rustls, and nothing of it by this role.
//! Whatever has arrived is handed over, up to as much as rustls itself takes at
//! once, and rustls judges each record's header as soon as it has one — so
//! what is not a record at all, another protocol or a second PROXY header, and
//! a length past what a record may hold, are refused with rustls's alert on
//! their first bytes, and a hello cut into many small records costs no more
//! here than it does inside rustls. What rustls took past the hello stays in
//! its buffer, which the handshake carries on from.
//!
//! What was read is kept beside only while there is somewhere to carry a
//! validator, and only until it is known whose connection this is.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::rustls::server::{Accepted, Acceptor};

/// The one protocol a TLS-ALPN-01 validator offers.
const ACME_TLS: &[u8] = b"acme-tls/1";

/// The most read at a time: as much as rustls takes into its buffer at once.
const AT_ONCE: usize = 4096;

/// A caller's hello, as rustls read it, and what that took if it was kept.
pub struct Hello {
    /// What rustls made of it, which a handshake carries on from.
    pub accepted: Accepted,
    /// Every byte read, as it arrived — or nothing, when it was not kept.
    pub read: Vec<u8>,
}

impl Hello {
    /// Whether the caller is a TLS-ALPN-01 validator: it offers `acme-tls/1`
    /// and nothing else.
    pub fn validates(&self) -> bool {
        let Some(mut offered) = self.accepted.client_hello().alpn() else {
            return false;
        };
        offered.next() == Some(ACME_TLS) && offered.next().is_none()
    }
}

/// Read a caller's hello off `stream`, keeping every byte read if `keep`.
///
/// A hello rustls refuses is answered with whatever alert rustls gives for it.
pub async fn hello<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    keep: bool,
) -> io::Result<Hello> {
    let mut acceptor = Acceptor::default();
    let mut read = Vec::new();
    let mut arrived = vec![0u8; AT_ONCE];
    loop {
        let n = stream.read(&mut arrived).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if keep {
            read.extend_from_slice(&arrived[..n]);
        }
        if let Some(accepted) = handed(&mut acceptor, stream, &arrived[..n]).await? {
            return Ok(Hello { accepted, read });
        }
    }
}

/// Hand `bytes` to rustls, and the hello if it now has it whole. What rustls
/// refuses is answered with its alert.
async fn handed<S: AsyncWrite + Unpin>(
    acceptor: &mut Acceptor,
    stream: &mut S,
    mut bytes: &[u8],
) -> io::Result<Option<Accepted>> {
    while !bytes.is_empty() {
        // rustls takes bytes in pieces as its buffer grows, and refuses what
        // is past what it allows a hello rather than taking nothing.
        if acceptor.read_tls(&mut bytes)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a hello rustls took none of",
            ));
        }
    }
    match acceptor.accept() {
        Ok(accepted) => Ok(accepted),
        Err((e, mut alert)) => {
            let mut said = Vec::new();
            if alert.write_all(&mut said).is_ok() {
                let _ = stream.write_all(&said).await;
            }
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }
}

/// Carry a validator's connection to `to`: what was read of it first, then
/// every byte both ways, until both ends have closed — or `handshake_timeout`
/// ends it, which bounds all of this.
pub async fn carry<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    read: &[u8],
    to: &str,
) -> io::Result<()> {
    let Some(_descriptor) = crate::budget::take() else {
        return Err(io::Error::other("no descriptor to spare for the leg"));
    };
    let mut answering = fleet_transport::dial(to).await?;
    answering.write_all(read).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut answering).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::ServerName;

    /// The hello a client offering `protocols` sends first, in the records it
    /// sends it in.
    fn sent_by(protocols: &[&[u8]]) -> Vec<u8> {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("verify.example.com").unwrap(),
        )
        .unwrap();
        let mut sent = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut sent).unwrap();
        }
        sent
    }

    /// `sent`, arriving on a connection, then `after`, then nothing more.
    async fn arriving(sent: &[u8], after: &[u8]) -> tokio::io::DuplexStream {
        let (near, mut far) = tokio::io::duplex(64 << 10);
        far.write_all(sent).await.unwrap();
        far.write_all(after).await.unwrap();
        drop(far);
        near
    }

    /// A validator is one that offers `acme-tls/1` alone — never one that
    /// offers it beside something else, and never one that offers nothing.
    #[tokio::test]
    async fn a_validator_offers_acme_tls_alone() {
        let offers: [(&[&[u8]], bool); 5] = [
            (&[ACME_TLS], true),
            (&[ACME_TLS, b"h2"], false),
            (&[b"h2", ACME_TLS], false),
            (&[b"h2", b"http/1.1"], false),
            (&[], false),
        ];
        for (protocols, validates) in offers {
            let sent = sent_by(protocols);
            let mut stream = arriving(&sent, b"").await;
            let hello = hello(&mut stream, true).await.unwrap();
            assert_eq!(hello.validates(), validates, "{protocols:?}");
            assert_eq!(hello.read, sent, "every byte taken is kept");
        }
    }

    /// A hello cut into many small records is read whole, as one in a single
    /// record is.
    #[tokio::test]
    async fn a_hello_in_many_small_records_is_read_whole() {
        let sent = sent_by(&[ACME_TLS]);
        // One record as the client sent it: its header, then the handshake.
        let (header, body) = sent.split_at(5);
        let mut cut = Vec::new();
        for piece in body.chunks(16) {
            cut.extend_from_slice(&header[..3]);
            cut.extend_from_slice(&(piece.len() as u16).to_be_bytes());
            cut.extend_from_slice(piece);
        }
        let mut stream = arriving(&cut, b"").await;
        let hello = hello(&mut stream, true).await.unwrap();
        assert!(hello.validates());
        assert_eq!(hello.read, cut);
    }

    /// What arrives together with the hello is not lost: it is kept for a
    /// connection that is carried, and in rustls's hands for one that is not —
    /// which here refuses it, as it is no record. Nothing is kept when there is
    /// nowhere to carry it.
    #[tokio::test]
    async fn what_arrives_with_the_hello_is_not_lost() {
        let sent = sent_by(&[b"h2"]);
        let after: &[u8] = b"what came next";

        let mut stream = arriving(&sent, after).await;
        let kept = hello(&mut stream, true).await.unwrap();
        assert_eq!(kept.read, [&sent[..], after].concat());

        let mut stream = arriving(&sent, after).await;
        let hello = hello(&mut stream, false).await.unwrap();
        assert!(hello.read.is_empty());
        let key = rcgen::KeyPair::generate().unwrap();
        let own = rcgen::CertificateParams::new(vec!["verify.example.com".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![own.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let mut connection = hello
            .accepted
            .into_connection(Arc::new(config))
            .map_err(|(e, _)| e)
            .unwrap();
        assert!(
            connection.process_new_packets().is_err(),
            "what came after the hello reached rustls"
        );
    }

    /// What is not a record at all, and a record longer than one may be, are
    /// refused on their first bytes, with rustls's alert — not waited on for
    /// the length their header would announce.
    #[tokio::test]
    async fn what_is_not_a_record_is_refused_on_its_header() {
        let starts: [(&str, &[u8]); 3] = [
            ("plain HTTP", b"GET / HTTP/1.1\r\n"),
            ("a second PROXY header", b"\r\n\r\n\x00\r\nQUIT\n"),
            ("a record past the largest", &[0x16, 0x03, 0x01, 0xff, 0xff]),
        ];
        for (what, start) in starts {
            // The far end stays open, so a read waiting on a length would wait.
            let (mut near, mut far) = tokio::io::duplex(4096);
            far.write_all(start).await.unwrap();
            let refused =
                tokio::time::timeout(std::time::Duration::from_secs(2), hello(&mut near, true))
                    .await
                    .unwrap_or_else(|_| panic!("{what}: waited on, not refused"));
            assert!(refused.is_err(), "{what}");
            drop(near);
            let mut said = Vec::new();
            far.read_to_end(&mut said).await.unwrap();
            assert_eq!(
                said.first(),
                Some(&0x15),
                "{what}: an alert record: {said:?}"
            );
        }
    }

    /// A hello rustls cannot read is refused, with the alert rustls gives it.
    #[tokio::test]
    async fn a_hello_that_does_not_read_is_refused_with_an_alert() {
        // A handshake record holding a ClientHello with nothing in it.
        let (mut near, mut far) = tokio::io::duplex(4096);
        far.write_all(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00])
            .await
            .unwrap();
        assert!(hello(&mut near, true).await.is_err());
        drop(near);
        let mut said = Vec::new();
        far.read_to_end(&mut said).await.unwrap();
        assert_eq!(said.first(), Some(&0x15), "an alert record: {said:?}");
    }
}
