//! End-to-end mutual RA-TLS handshake over an in-memory duplex, on the software backend
//! — the only one that runs with NO SEV-SNP hardware. Proves the whole chain: mint
//! attested certs → tokio-rustls mutual handshake → each side's custom verifier pulls the
//! peer quote, rebinds the SPKI, and the shared dev identity accepts it → data flows.
//! Also proves a wrong measurement pin ABORTS the handshake.

use std::sync::Arc;

use enclavid_attestation::{Attestor, DEV_FLEET_MEASUREMENT, MockAttestor};
use enclavid_ra_tls::{MeasurementPolicy, RaTlsError, client_config, server_config, server_name};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn dev_attestor() -> Arc<dyn Attestor> {
    Arc::new(MockAttestor::dev_fleet())
}

fn dev_policy() -> MeasurementPolicy {
    MeasurementPolicy::Pinned(vec![DEV_FLEET_MEASUREMENT.to_string()])
}

fn dev_server() -> Result<tokio_rustls::rustls::ServerConfig, RaTlsError> {
    server_config(dev_attestor(), dev_policy())
}

fn dev_client() -> Result<tokio_rustls::rustls::ClientConfig, RaTlsError> {
    client_config(dev_attestor(), dev_policy())
}

#[tokio::test]
async fn mutual_ratls_handshake_and_data() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(Arc::new(dev_server().unwrap()));
    let connector = TlsConnector::from(Arc::new(dev_client().unwrap()));

    let server = tokio::spawn(async move {
        // `accept` completes only after the server has ATTESTED the client's cert too
        // (mutual): a plain TLS peer with no quote extension would be rejected here.
        let mut tls = acceptor
            .accept(server_io)
            .await
            .expect("server accept (mutual RA-TLS)");
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.expect("server read");
        assert_eq!(&buf, b"hello");
        tls.write_all(b"world").await.expect("server write");
        tls.flush().await.unwrap();
    });

    // `connect` completes only after the client has ATTESTED the server's cert.
    let mut tls = connector
        .connect(server_name(), client_io)
        .await
        .expect("client connect (mutual RA-TLS)");
    tls.write_all(b"hello").await.expect("client write");
    tls.flush().await.unwrap();
    let mut buf = [0u8; 5];
    tls.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"world");

    server.await.unwrap();
}

#[tokio::test]
async fn wrong_measurement_pin_aborts_handshake() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = TlsAcceptor::from(Arc::new(dev_server().unwrap()));
    // Same shared dev identity (so the quote signature is valid) but pin a measurement
    // the server's attested cert does NOT carry — the client's verifier must refuse.
    let bad = client_config(
        dev_attestor(),
        MeasurementPolicy::Pinned(vec!["ff".repeat(32)]),
    )
    .unwrap();
    let connector = TlsConnector::from(Arc::new(bad));

    let server = tokio::spawn(async move {
        let _ = acceptor.accept(server_io).await; // will error when the client aborts
    });
    let res = connector.connect(server_name(), client_io).await;
    assert!(
        res.is_err(),
        "handshake must fail when the server measurement isn't pinned"
    );
    let _ = server.await;
}
