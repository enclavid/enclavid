//! The servers this guest keeps its clock by, and the roots their key exchanges
//! are checked against. Both are compiled in, so both are part of the
//! measurement: the host can keep a server from answering, never swap one in.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

/// The list, as written beside this crate's manifest — where deploy/ reads it
/// too, to start the relays that reach each server.
const LIST: &str = include_str!("../servers");

/// The roots a key exchange may chain to. Every server on the list chains to
/// one of them today: Let's Encrypt's two (ISRG) for all but one, SSL.com's for
/// Cloudflare.
///
/// Three, not the hundred-odd of a browser's store, because a root here is a
/// party that can put its own server in place of one on the list. That does
/// not buy diversity — five of the six operators share ISRG, and no public NTS
/// server set avoids it — but it does rule out every other authority.
const ROOTS: [&str; 3] = [
    include_str!("../roots/isrg-root-x1.pem"),
    include_str!("../roots/isrg-root-x2.pem"),
    include_str!("../roots/ssl-com-root-ecc.pem"),
];

/// How many servers have to agree before the clock is taken. Three: no one
/// operator can move the clock, since the list has one server per operator.
pub const AGREEING: usize = 3;

/// One NTS server, and where on the host the guest reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Server {
    /// What TLS checks the key exchange against, and what the server has to
    /// name back as the one to send time packets to.
    pub name: &'static str,
    /// The host's vsock port for its key exchange. Its time packets take the
    /// next one up.
    pub port: u32,
}

impl Server {
    pub fn time_port(&self) -> u32 {
        self.port + 1
    }
}

/// Every server on the list. The list is a constant of the build, and the tests
/// below read it, so a list that does not parse never ships.
pub fn all() -> Vec<Server> {
    parse(LIST).expect("the server list is checked by this crate's tests")
}

/// The roots, parsed. Like the list, a constant the tests read.
pub fn roots() -> Arc<[CertificateDer<'static>]> {
    ROOTS
        .iter()
        .map(|pem| {
            CertificateDer::from_pem_slice(pem.as_bytes())
                .expect("the roots are checked by this crate's tests")
        })
        .collect()
}

fn parse(text: &'static str) -> Result<Vec<Server>, String> {
    let mut servers: Vec<Server> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(port), Some(name), None) = (words.next(), words.next(), words.next()) else {
            return Err(format!("expected `<port> <server>`, got `{line}`"));
        };
        let port: u32 = port
            .parse()
            .map_err(|_| format!("`{port}` is not a vsock port"))?;
        let valid_name = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        if !valid_name {
            return Err(format!("`{name}` is not a server name"));
        }
        // Each server takes two ports; two servers sharing one would send one
        // server's traffic to the other.
        let taken = |p: u32| servers.iter().any(|s| s.port == p || s.time_port() == p);
        if port == u32::MAX || taken(port) || taken(port + 1) {
            return Err(format!("port {port} or the one after it is taken"));
        }
        if servers.iter().any(|s| s.name == name) {
            return Err(format!("`{name}` is listed twice"));
        }
        servers.push(Server { name, port });
    }
    if servers.len() < AGREEING {
        return Err(format!(
            "{} servers cannot make an agreement of {AGREEING}",
            servers.len()
        ));
    }
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_parses() {
        let servers = all();
        assert!(servers.len() >= AGREEING);
    }

    #[test]
    fn the_roots_parse() {
        assert_eq!(roots().len(), ROOTS.len());
    }

    /// Decoding a PEM checks its base64, not the certificate inside; the
    /// verifier drops a root it cannot use as an anchor without a word, and the
    /// guest has no other store to fall back on. So each is taken as one here.
    #[test]
    fn every_root_is_an_anchor() {
        let mut store = rustls::RootCertStore::empty();
        for root in roots().iter() {
            store
                .add(root.clone())
                .expect("each root is a certificate webpki can anchor to");
        }
        assert_eq!(store.len(), ROOTS.len());
    }

    #[test]
    fn every_server_is_a_dns_name() {
        for server in all() {
            assert!(
                matches!(
                    rustls::pki_types::ServerName::try_from(server.name),
                    Ok(rustls::pki_types::ServerName::DnsName(_))
                ),
                "{} is not a name TLS can check a certificate against",
                server.name
            );
        }
    }

    #[test]
    fn a_port_that_overlaps_is_refused() {
        assert!(parse("7100 a.example\n7101 b.example\n7104 c.example").is_err());
    }

    #[test]
    fn a_name_listed_twice_is_refused() {
        assert!(parse("7100 a.example\n7102 a.example\n7104 c.example").is_err());
    }

    #[test]
    fn too_few_to_agree_is_refused() {
        assert!(parse("7100 a.example\n7102 b.example").is_err());
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let servers =
            parse("# x\n\n7100 a.example\n  7102   b.example \n7104 c.example\n").unwrap();
        assert_eq!(
            servers[1],
            Server {
                name: "b.example",
                port: 7102
            }
        );
    }
}
