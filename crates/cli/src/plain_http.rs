//! Where a request may go over plain http: to this machine alone. Anywhere
//! else, what it carries — a bearer, a session token, registry credentials,
//! the artifact pushed — would cross a network in the clear.

use url::Host;

/// Whether `host` is this machine: `localhost`, or a loopback address.
pub fn is_this_machine(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => *name == "localhost",
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn here(url: &str) -> bool {
        is_this_machine(&url::Url::parse(url).unwrap().host().unwrap())
    }

    #[test]
    fn this_machine_is_localhost_and_the_loopback_alone() {
        for url in [
            "http://localhost:8001",
            "http://LOCALHOST",
            "http://127.0.0.1:8001",
            "http://127.1.2.3",
            "http://[::1]:8001",
        ] {
            assert!(here(url), "{url}");
        }
        for url in [
            "http://localhost.example.com",
            "http://127.0.0.1.example.com",
            "http://api.enclavid.com",
            "http://10.0.0.1",
            "http://[::2]",
        ] {
            assert!(!here(url), "{url}");
        }
    }
}
