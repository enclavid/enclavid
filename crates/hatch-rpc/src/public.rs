//! Which hosts are of the public internet: the only ones the attested hatch
//! sends a webhook, a broker's leg or a registry's pull to, and the only ones
//! api takes in what a consumer names for those.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

/// The IPv4 ranges out of reach: those of the IANA special-purpose registry that
/// are not globally reachable — this network, private, shared, loopback,
/// link-local, protocol assignments, documentation, the 6to4 relay, benchmarking
/// — then multicast and the reserved rest, broadcast among it.
const NOT_PUBLIC_V4: [(Ipv4Addr, u8); 15] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// Global unicast: the only IPv6 range in reach.
const GLOBAL_V6: (Ipv6Addr, u8) = (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);

/// The parts of global unicast out of reach all the same: protocol assignments
/// (Teredo among them), documentation, 6to4, whose address carries an IPv4 one,
/// and the newer documentation range.
const NOT_PUBLIC_V6: [(Ipv6Addr, u8); 4] = [
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
];

/// Names under which no public host is: localhost's own, and the reverse-lookup
/// tree, whose loopback names a resolver answers itself.
const NOT_PUBLIC_ZONES: [&str; 2] = ["localhost", "arpa"];

const fn mask_v4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

const fn mask_v6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    }
}

fn in_v4(ip: Ipv4Addr, (net, len): (Ipv4Addr, u8)) -> bool {
    ip.to_bits() & mask_v4(len) == net.to_bits()
}

fn in_v6(ip: Ipv6Addr, (net, len): (Ipv6Addr, u8)) -> bool {
    ip.to_bits() & mask_v6(len) == net.to_bits()
}

// Every range is one: its length within its family's width, and no bit of its
// address past that length — one that is not would match nothing, and refuse
// nothing, without a sound.
const _: () = {
    let mut i = 0;
    while i < NOT_PUBLIC_V4.len() {
        let (net, len) = NOT_PUBLIC_V4[i];
        assert!(len <= 32 && net.to_bits() & !mask_v4(len) == 0);
        i += 1;
    }
    let mut i = 0;
    while i < NOT_PUBLIC_V6.len() {
        let (net, len) = NOT_PUBLIC_V6[i];
        assert!(len <= 128 && net.to_bits() & !mask_v6(len) == 0);
        i += 1;
    }
    let (net, len) = GLOBAL_V6;
    assert!(len <= 128 && net.to_bits() & !mask_v6(len) == 0);
};

/// Whether `ip` is an address of the public internet. An IPv6 address that
/// carries an IPv4 one — mapped, translated, 6to4 — is out with the rest of
/// IPv6 outside global unicast, whatever the IPv4 one is.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !NOT_PUBLIC_V4.iter().any(|range| in_v4(ip, *range)),
        IpAddr::V6(ip) => {
            in_v6(ip, GLOBAL_V6) && !NOT_PUBLIC_V6.iter().any(|range| in_v6(ip, *range))
        }
    }
}

/// Whether `url` is an http(s) URL that writes its host as one that may be
/// public — a public address, in whatever spelling, or a name with no empty
/// label outside localhost's and the reverse-lookup tree — before any name is
/// looked up. Whether a name is public its addresses say, which only the hatch
/// looks up.
pub fn public_as_written(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    // Only the http(s) schemes have their hosts read as addresses.
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    match url.host() {
        Some(Host::Ipv4(ip)) => is_public(ip.into()),
        Some(Host::Ipv6(ip)) => is_public(ip.into()),
        Some(Host::Domain(name)) => {
            let name = name.strip_suffix('.').unwrap_or(name);
            let under = |zone: &str| {
                name == zone
                    || name
                        .strip_suffix(zone)
                        .is_some_and(|rest| rest.ends_with('.'))
            };
            !name.split('.').any(str::is_empty) && !NOT_PUBLIC_ZONES.iter().any(|zone| under(zone))
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The addresses a request could be turned on to reach this host or its
    /// network are out, each family's way of writing them included; an address
    /// of the internet is in, at the very edges of the ranges around it.
    #[test]
    fn only_an_address_of_the_internet_is_public() {
        for out in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::7f00:1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            assert!(!is_public(out.parse().unwrap()), "{out}");
        }
        for public in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450:4001::200e",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    /// A URL that writes an address other than a public one, in whatever
    /// spelling, names localhost or the reverse-lookup tree, has an empty label,
    /// or is not http(s), names no host that may be public; a name otherwise
    /// may be, until its addresses say.
    #[test]
    fn a_host_is_judged_as_written() {
        for refused in [
            "https://127.0.0.1/hook",
            "https://2130706433/hook",
            "https://0x7f.1/hook",
            "https://user@127.0.0.1/hook",
            "https://[::1]/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://10.0.0.1:5000/",
            "https://169.254.169.254/latest",
            "https://localhost/hook",
            "https://LOCALHOST./hook",
            "https://api.localhost/hook",
            "https://localhost../hook",
            "https://1.0.0.127.in-addr.arpa/hook",
            "https://127.in-addr.arpa./hook",
            "https://arpa/hook",
            "https://127.0.0.1../hook",
            "https://hooks..example/hook",
            "foo://127.0.0.1/",
            "ftp://1.1.1.1/",
            "not a url",
        ] {
            assert!(!public_as_written(refused), "{refused}");
        }
        for may_be in [
            "https://hooks.example/enclavid",
            "https://hooks.example./enclavid",
            "HTTPS://Hooks.Example/enclavid",
            "https://registry.example:5000/",
            "https://notarpa.example/",
            "https://1.1.1.1/hook",
            "https://[2606:4700:4700::1111]/hook",
        ] {
            assert!(public_as_written(may_be), "{may_be}");
        }
    }
}
