//! `host-relay` — one link, one process.
//!
//! ```text
//! # inbound, from a front-end that brings TLS to the host without terminating it
//! host-relay --listen unix:/run/enclavid/in.sock \
//!            --to     hybrid:/run/enclavid/api.vsock:443
//!
//! # the api CVM -> one execution-worker CVM (one instance per worker = the fan-out)
//! host-relay --listen unix:/run/enclavid/api.vsock_1027 \
//!            --to     hybrid:/run/enclavid/exec-1.vsock:1024
//!
//! # the api CVM -> host-hatch, the semantic egress gateway
//! host-relay --listen unix:/run/enclavid/api.vsock_1024 \
//!            --to     tcp:127.0.0.1:8000
//!
//! # the same links on a VMM that gives the host real AF_VSOCK, the second
//! # taking only the api guest's calls
//! host-relay --listen tcp:127.0.0.1:8443 --to vsock:3:443
//! host-relay --listen vsock:1027 --from 3 --to vsock:4:1024
//!
//! # inbound, accepting callers itself, so it names each one to the guest
//! host-relay --listen tcp:0.0.0.0:443 --proxy-protocol --to vsock:5:443
//!
//! # a guest's NTS server: its key exchange, and its time packets as datagrams;
//! # every guest on the host shares these, so none may hold more than its share
//! host-relay --listen vsock:7100 --per-guest 8 --to tcp:time.cloudflare.com:4460
//! host-relay --listen vsock:7101 --per-guest 8 --to udp:time.cloudflare.com:123
//! ```
//!
//! Everything topological — how many workers, what reaches what — is decided by
//! which instances are started with which arguments. See the crate docs for why
//! the process holds no map of its own.

use std::collections::HashMap;
use std::io;
use std::process::ExitCode;

use clap::Parser;
use host_relay::{Accepted, Destination, Endpoint, proxy_header, serve_connection};

#[derive(Parser)]
#[command(
    name = "host-relay",
    about = "Blind byte splice between two endpoints, one of which may be a CVM"
)]
struct Args {
    /// Where to accept: `unix:<path>`, `tcp:<addr>` or `vsock:<port>`.
    ///
    /// Under cloud-hypervisor a guest's outbound connections arrive as
    /// `unix:<vm-socket>_<port>` — the VMM dials that path, so the relay listens
    /// on it.
    #[arg(long, value_parser = Endpoint::parse)]
    listen: Endpoint,

    /// Where to send it: `hybrid:<path>:<port>` (cloud-hypervisor guest),
    /// `vsock:<cid>:<port>` (real AF_VSOCK guest), `tcp:<addr>`, or `udp:<addr>`
    /// for a caller that frames datagrams on its stream.
    #[arg(long, value_parser = Destination::parse)]
    to: Destination,

    /// Permission bits for a `unix:` listen socket. These decide who can reach the
    /// destination at all, so the default is restrictive: widen it only when the
    /// peer genuinely runs as another uid. Ignored for `tcp:` and `vsock:`.
    #[arg(long, default_value = "0600", value_parser = parse_octal)]
    socket_mode: u32,

    /// How long to let in-flight splices finish after SIGTERM before exiting.
    /// Keep it under whatever stop timeout the supervisor enforces, or the drain
    /// is cut short by SIGKILL and the grace is moot.
    #[arg(long, default_value = "10")]
    drain_secs: u64,

    /// Write a PROXY protocol v2 header naming who dialled, ahead of anything
    /// the caller sends. For an instance that accepts callers itself; behind a
    /// front that writes its own header, leave it off and that header is
    /// carried like any other byte. Needs a `tcp:` listener — nothing else has
    /// a caller's address to name.
    #[arg(long)]
    proxy_protocol: bool,

    /// At most this many connections open at once from any one guest; one
    /// past that is closed as it arrives. For a relay every guest on the host
    /// shares, so that none can take the others' turns. Needs a `vsock:`
    /// listener — nothing else says which guest dialled. Unset, no limit.
    #[arg(long)]
    per_guest: Option<usize>,

    /// Take calls only from this guest, by its context ID; given again, from
    /// each one named. A call from any other is closed as it arrives. Needs a
    /// `vsock:` listener — nothing else says which guest dialled. Unset, from
    /// any.
    #[arg(long, value_parser = host_relay::parse_guest)]
    from: Vec<u32>,
}

fn parse_octal(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s.trim_start_matches("0o"), 8)
        .map_err(|_| format!("expected octal permission bits, got `{s}`"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    if host_relay::is_self_referential(&args.listen, &args.to) {
        eprintln!("host-relay: --listen and --to name the same address; that dials itself");
        return ExitCode::FAILURE;
    }
    if args.proxy_protocol && !matches!(args.listen, Endpoint::Tcp(_)) {
        eprintln!(
            "host-relay: --proxy-protocol needs a tcp: listener; nothing else has a caller's address to name"
        );
        return ExitCode::FAILURE;
    }
    if args.proxy_protocol && matches!(args.to, Destination::Udp(_)) {
        eprintln!(
            "host-relay: --proxy-protocol writes a header ahead of a stream, and a udp: destination is not one"
        );
        return ExitCode::FAILURE;
    }
    if args.per_guest.is_some() && !matches!(args.listen, Endpoint::Vsock(_)) {
        eprintln!(
            "host-relay: --per-guest needs a vsock: listener; nothing else says which guest dialled"
        );
        return ExitCode::FAILURE;
    }
    if !args.from.is_empty() && !matches!(args.listen, Endpoint::Vsock(_)) {
        eprintln!(
            "host-relay: --from needs a vsock: listener; nothing else says which guest dialled"
        );
        return ExitCode::FAILURE;
    }

    let listener = match args.listen.bind(args.socket_mode).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("host-relay: bind {:?}: {e}", args.listen);
            return ExitCode::FAILURE;
        }
    };
    eprintln!("host-relay: {:?} -> {:?}", args.listen, args.to);

    // SIGTERM is the conventional stop signal, and its default action would kill
    // in-flight splices on every restart. The connections this carries are whole
    // applicant TLS sessions — dropping one mid-verification costs a person a
    // redo, so stop ACCEPTING on the signal and let what is already open finish.
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("host-relay: install SIGTERM handler: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Recreating `ctrl_c()` inside the loop would rearm the handler on every
    // iteration, leaving gaps in which a SIGINT lands on tokio's already-installed
    // disposition and is swallowed. Build both streams once.
    let mut sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("host-relay: install SIGINT handler: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut inflight = tokio::task::JoinSet::new();
    // How many connections each guest has open, under --per-guest. A task
    // returns its guest when it ends, which is what reaping it counts down.
    let mut open: HashMap<u32, usize> = HashMap::new();
    loop {
        tokio::select! {
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            accepted = listener.accept() => {
                let Accepted { stream: inbound, ends, guest } = match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        // Per-connection failures are not fatal — staying up matters
                        // more than any single client — but the descriptor-exhaustion
                        // family does not dequeue the pending connection, so retrying
                        // straight away burns a core and floods the log until the fd
                        // table drains. Yield briefly for those; spin freely for the
                        // ones where the connection really was consumed.
                        eprintln!("host-relay: accept: {e}");
                        if !matches!(
                            e.kind(),
                            io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                        ) {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        continue;
                    }
                };
                // Reap what has finished. A JoinSet only releases a task's
                // allocation when it is joined, so without this every connection
                // ever served is retained for the process lifetime — a slow climb
                // to the OOM killer, which would tear down exactly the live
                // sessions the drain below exists to protect. It also keeps
                // `len()` meaning "in flight" rather than "served since boot",
                // and the counts below meaning what is still open.
                while let Some(ended) = inflight.try_join_next() {
                    if let Ok(Some(guest)) = ended
                        && let Some(count) = open.get_mut(&guest)
                    {
                        *count -= 1;
                        if *count == 0 {
                            open.remove(&guest);
                        }
                    }
                }
                // Dropping it closes it, as the guest will see.
                if !args.from.is_empty() && !guest.is_some_and(|g| args.from.contains(&g)) {
                    let named = guest.map_or_else(|| "unnamed".to_owned(), |g| g.to_string());
                    eprintln!("host-relay: refused a call from guest {named}");
                    continue;
                }
                let counted = guest.filter(|_| args.per_guest.is_some());
                if let (Some(most), Some(guest)) = (args.per_guest, counted) {
                    let count = open.entry(guest).or_default();
                    if *count >= most {
                        // Dropping it closes it, as the guest will see.
                        continue;
                    }
                    *count += 1;
                }
                let dest = args.to.clone();
                let header = ends.filter(|_| args.proxy_protocol).map(proxy_header);
                inflight.spawn(async move {
                    if let Err(e) = serve_connection(inbound, &dest, header).await {
                        eprintln!("host-relay: splice: {e}");
                    }
                    counted
                });
            }
        }
    }

    // Dropping the listener first refuses new work immediately; a client that
    // arrives during the drain fails fast and retries against the replacement
    // rather than hanging on a socket about to disappear.
    drop(listener);
    if !inflight.is_empty() {
        eprintln!("host-relay: draining {} connection(s)", inflight.len());
        let grace = std::time::Duration::from_secs(args.drain_secs);
        if tokio::time::timeout(grace, async {
            while inflight.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            eprintln!("host-relay: drain timed out, {} still open", inflight.len());
        }
    }

    // Deliberately no unlink here. The next start reclaims a stale socket, which
    // is the only path that also covers SIGKILL and power loss — and unlinking on
    // the way out would race a fast restart, deleting the socket this process's
    // own replacement had already bound.
    ExitCode::SUCCESS
}
