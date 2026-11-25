//! Where the hatch sends what a consumer names — a webhook, a broker's leg, a
//! registry's pull — and the client the first two go out through.
//!
//! Held to the public internet, as the attested build holds it, the hatch
//! checks every host it is to send to by [`Hosts::check`], the same for all
//! three: a host written as an address must be a public one, and a name must
//! have addresses, every one of them public. The client for webhooks and broker
//! legs holds its connections to the same, by the same resolver: it connects
//! only to the public addresses a name resolves to, so a name that answers the
//! check one way and the connection another gets nowhere, and it follows no
//! redirect, which would take it to a host no check saw. A registry is pulled
//! from by a client the hatch cannot hold so: past the check, where a registry
//! redirects to and the realm it names for a token are the registry's own. A
//! developer's build sends where it is told, loopback included.
//!
//! Names are looked up for their IPv4 addresses alone: the hatch has no IPv6,
//! so an IPv6 address a name has is one no connection of its could use.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{GOOGLE, LookupIpStrategy, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use reqwest::{Method, RequestBuilder};
use url::{Host, Url};

use hatch_rpc::{is_public, public_as_written};

/// Whether this build holds what it sends to the public internet.
pub const PUBLIC_ONLY: bool = cfg!(feature = "sev-snp");

/// Why a resolver or a client could not be made.
pub type BuildError = Box<dyn std::error::Error + Send + Sync>;

/// Why a host is not one the hatch sends to.
#[derive(Debug, PartialEq, Eq)]
pub enum NotReached {
    /// Written as an address that is not public, or as localhost; a name with
    /// such an address; or no host at all.
    NotPublic,
    /// A name the resolver had no answer for, which it may have later.
    NoAnswer,
}

/// The hosts the hatch sends to.
#[derive(Clone)]
pub struct Hosts {
    /// What names are looked up by, for every check and for every connection
    /// the clients made with these hosts open; none where the hatch does not
    /// hold to public addresses.
    resolver: Option<TokioResolver>,
}

impl Hosts {
    /// The hosts of a hatch held to public addresses where `public_only`.
    pub fn new(public_only: bool) -> Result<Self, BuildError> {
        let resolver = if public_only { Some(resolver()?) } else { None };
        Ok(Self { resolver })
    }

    /// Whether the hatch sends to the host `url` names.
    pub async fn check(&self, url: &str) -> Result<(), NotReached> {
        let Some(resolver) = &self.resolver else {
            return Ok(());
        };
        if !public_as_written(url) {
            return Err(NotReached::NotPublic);
        }
        let url = Url::parse(url).map_err(|_| NotReached::NotPublic)?;
        let Some(Host::Domain(name)) = url.host() else {
            return Ok(());
        };
        let found = resolver
            .lookup_ip(name)
            .await
            .map_err(|_| NotReached::NoAnswer)?;
        let mut addresses = found.iter().peekable();
        if addresses.peek().is_some() && addresses.all(is_public) {
            Ok(())
        } else {
            Err(NotReached::NotPublic)
        }
    }
}

/// A resolver as reqwest's own — hickory, from the system's configuration or,
/// where that does not read, a public resolver's — for IPv4 alone.
fn resolver() -> Result<TokioResolver, BuildError> {
    let mut builder = TokioResolver::builder_tokio().unwrap_or_else(|_| {
        TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&GOOGLE),
            TokioRuntimeProvider::default(),
        )
    });
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
    Ok(builder.build()?)
}

/// An HTTP client for the hosts consumers name: through no proxy, following no
/// redirect, and to no host its [`Hosts`] does not send to.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    hosts: Hosts,
}

impl Client {
    /// A client held to `hosts`, whose connections open within `connect` and
    /// whose every request ends within `total`. It makes its reqwest client
    /// itself, so nothing given it can follow a redirect or answer a name
    /// another way.
    pub fn new(hosts: Hosts, connect: Duration, total: Duration) -> Result<Self, BuildError> {
        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(connect)
            .timeout(total);
        let builder = match &hosts.resolver {
            Some(resolver) => builder.dns_resolver(PublicNames(resolver.clone())),
            None => builder,
        };
        Ok(Self {
            http: builder.build()?,
            hosts,
        })
    }

    /// A request to `url` where this client sends to it — an http(s) URL whose
    /// host its [`Hosts`] sends to — or none.
    pub async fn request(&self, method: Method, url: &str) -> Option<RequestBuilder> {
        let parsed = Url::parse(url).ok()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        self.hosts.check(url).await.ok()?;
        Some(self.http.request(method, parsed))
    }
}

/// A name's addresses with every one that is not public dropped: a name left
/// with none does not resolve.
struct PublicNames(TokioResolver);

impl Resolve for PublicNames {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.0.clone();
        Box::pin(async move {
            let found = resolver.lookup_ip(name.as_str()).await?;
            let public: Vec<SocketAddr> = found
                .iter()
                .filter(|ip| is_public(*ip))
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            if public.is_empty() {
                return Err(format!("{} has no public address", name.as_str()).into());
            }
            let addrs: Addrs = Box::new(public.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::post;

    use super::*;

    fn hosts(public_only: bool) -> Hosts {
        Hosts::new(public_only).unwrap()
    }

    fn client(public_only: bool) -> Client {
        let (connect, total) = (Duration::from_secs(5), Duration::from_secs(15));
        Client::new(hosts(public_only), connect, total).unwrap()
    }

    /// Held to public addresses, a host written as any other address — in
    /// whatever spelling — or named localhost is not sent to, and an address
    /// of the internet is; not held, every host is.
    #[tokio::test]
    async fn a_host_is_sent_to_only_where_it_is_public() {
        let held = hosts(true);
        for refused in [
            "http://127.0.0.1:8080/hook",
            "http://2130706433/hook",
            "http://0x7f.1/hook",
            "http://[::1]/hook",
            "https://169.254.169.254/latest",
            "https://10.0.0.5:5000/",
            "http://localhost:5000/",
        ] {
            assert_eq!(
                held.check(refused).await,
                Err(NotReached::NotPublic),
                "{refused}"
            );
        }
        assert_eq!(held.check("https://1.1.1.1/hook").await, Ok(()));
        assert_eq!(hosts(false).check("http://127.0.0.1:8080/").await, Ok(()));
    }

    /// The client holds to its hosts, and to http(s): a URL it does not send
    /// to gets no request.
    #[tokio::test]
    async fn the_client_makes_no_request_its_hosts_refuse() {
        let held = client(true);
        for refused in [
            "http://127.0.0.1:8080/hook",
            "ftp://1.1.1.1/hook",
            "not a url",
        ] {
            assert!(
                held.request(Method::POST, refused).await.is_none(),
                "{refused}"
            );
        }
        assert!(
            held.request(Method::POST, "https://1.1.1.1/hook")
                .await
                .is_some()
        );
        let open = client(false);
        assert!(
            open.request(Method::POST, "http://127.0.0.1:8080/hook")
                .await
                .is_some()
        );
    }

    /// A redirect is the answer, not a place the client goes: the host it
    /// names is one no check saw.
    #[tokio::test]
    async fn the_client_follows_no_redirect() {
        let reached = Arc::new(AtomicBool::new(false));
        let seen = reached.clone();
        let app = Router::new()
            .route(
                "/first",
                post(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/second")]) }),
            )
            .route(
                "/second",
                post(move || async move { seen.store(true, Ordering::SeqCst) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });

        let answer = client(false)
            .request(Method::POST, &format!("{origin}/first"))
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(answer.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(!reached.load(Ordering::SeqCst));
    }

    /// A connection's name resolves to its public addresses alone: a name with
    /// none does not resolve at all.
    #[tokio::test]
    async fn a_connection_resolves_to_public_addresses_alone() {
        let names = PublicNames(resolver().unwrap());
        assert!(
            names
                .resolve(Name::from_str("localhost").unwrap())
                .await
                .is_err()
        );
    }
}
