//! Which member of a group takes a request, which members may be given one,
//! and how that is kept current.
//!
//! ## The state machine is the library's, the question is ours
//!
//! Choosing among interchangeable members, remembering which of them are
//! answering, and running the checks on a schedule are all solved problems, and
//! the solution is beside the proxy this role already runs. What is NOT general
//! is the check itself: liveness here means "would an attested leg open", and
//! only a real handshake answers that — see [`Attested`]. So the loop, the
//! thresholds and the enable flag come from `pingora-load-balancing`, and the
//! one method that decides anything is this file's.
//!
//! ## A set of members owns its check, and a task runs it
//!
//! This is the library's ordinary shape, the one its own examples use: the
//! check and its frequency are set on the set of members, and a task started
//! against that set runs the schedule. What differs per group — the build to
//! prove, the part to agree with — lives in that group's checker, which is
//! where it belongs.
//!
//! The examples register those tasks with a pingora `Server`, which this role
//! does not run: its listener is vsock and the accept loop is its own. That
//! costs nothing here, because `background_service` only wraps the same
//! `BackgroundService::start` that [`check_forever`] awaits directly.
//!
//! What the examples also assume is that the sets are fixed at startup. Ours
//! arrive by push and are replaced, so the tasks are replaced with them — see
//! [`check_forever`]. The price is that each push discards what the checks had
//! found and starts asking again, and it is the right price: a push is rare and
//! deliberate, while the thing it must not disturb — connections in flight — is
//! not touched by any of this.
//!
//! ## Nothing is learned from a failed request, and why that is affordable
//!
//! A request that could not reach a member is the fastest signal there is, and
//! this role does not act on it. The library's enable flag is what such a
//! signal would set, and nothing in the library ever clears it: the checks own
//! HEALTH, which is a separate flag read alongside it. Lifting the veto would
//! therefore need a timer of this role's own, racing the library's schedule.
//!
//! What makes that affordable is the schedule: every member is asked every
//! [`INTERVAL`] and one refusal is enough to take it out, so a member that dies
//! is out within a pass. Between the death and the pass, requests meet it and
//! fail — and that is what retrying on a sibling is for. If the window ever
//! matters more than the simplicity, the shape to reach for is a veto that
//! EXPIRES, checked in [`pick`], rather than a flag something has to clear.
//!
//! ## Why a member carries an address it is never dialled by
//!
//! [`Backend`] is modelled as something one connects TO, so it holds a
//! `SocketAddr`. In this role nothing reads it: the library's own checks are
//! replaced by [`Attested`], ketama — the one selection that hashes an address
//! — is never chosen, and the peer a request is sent on is built by hand
//! against `custom_l4` in `crate::proxy`. What the field is used for here is
//! IDENTITY.
//!
//! A fleet address is `vsock://CID:PORT` in the attested build, which is
//! neither of the two shapes that type offers. It is carried in the `Unix`
//! variant, whose payload is an arbitrary string — not because it names a
//! socket in a filesystem, but because it is the only shape that holds ours
//! whole and hands it back unchanged. Both builds do this, so there is one
//! behaviour to reason about rather than one per transport.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_core::services::background::BackgroundService;
use pingora_load_balancing::discovery::Static;
use pingora_load_balancing::health_check::HealthCheck;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::{Backend, Backends, Extensions, LoadBalancer};
use safe_logger::debug;
use tokio::sync::watch;

use crate::upstream::{Part, Tls, Upstreams};

/// One group's members under one name, and the health of each.
pub type Balancer = LoadBalancer<RoundRobin>;

/// How long one check may take before the member is treated as not answering.
const TIMEOUT: Duration = Duration::from_secs(5);

/// How often every member of the current table is asked.
///
/// Every member is dialled each pass, well or not, so this is the rate at which
/// this role spends attested handshakes on members that are answering perfectly
/// well. It is the one knob on that cost.
#[cfg(not(test))]
const INTERVAL: Duration = Duration::from_secs(10);
#[cfg(test)]
const INTERVAL: Duration = Duration::from_millis(20);

/// Ask the members of a pass at once rather than one after another.
///
/// A member that is gone takes [`TIMEOUT`] to say so, and sequentially one such
/// member would delay every member after it.
const AT_ONCE: bool = true;

/// How many checks in a row flip a member out of service, and how many flip it
/// back.
///
/// Leaving is fast and returning is slow, deliberately. One refused handshake
/// is enough to stop sending work, because a request that meets a member that
/// is not there costs a caller; two passes are asked for before it is trusted
/// again, because a member that answers once and then fails would otherwise
/// flap in and out at the rate of the check.
const OUT: usize = 1;
const BACK: usize = 2;

/// A member, identified by the address this role would dial it at.
///
/// `None` if the address cannot be carried — it is checked when a push is
/// accepted, so this is a shape no table should hold.
pub fn member(addr: &str) -> Option<Backend> {
    let identity = std::os::unix::net::SocketAddr::from_pathname(addr).ok()?;
    Some(Backend {
        addr: SocketAddr::Unix(identity),
        weight: 1,
        ext: Extensions::new(),
    })
}

/// The address a member was declared at, as this role dials it.
pub fn addr_of(member: &Backend) -> Option<&str> {
    member.addr.as_unix()?.as_pathname()?.to_str()
}

/// What one group's members are checked against.
///
/// Per group, because what a member has to prove is its group's: the build the
/// host declared for that label, and the part the group settled on. A set of
/// members and the question asked of them therefore live together.
struct Attested {
    measurement: String,
    part: Arc<Part>,
    tls: Tls,
}

#[async_trait::async_trait]
impl HealthCheck for Attested {
    /// One attested handshake and nothing else. Nothing is sent on the
    /// connection; it is opened and dropped.
    ///
    /// This is the same call a request's own leg makes, which is why the answer
    /// means what a request needs it to. A cheaper check would answer a
    /// different question: a plain connection succeeds while the host is
    /// carrying bytes, and a member returned to service on that answer would
    /// fail its next request.
    async fn check(&self, target: &Backend) -> pingora_core::Result<()> {
        let refuse = |kind| Err(pingora_core::Error::new(kind));
        let Some(addr) = addr_of(target) else {
            // A member this role built carries one — see `member`.
            return refuse(pingora_core::ErrorType::InternalError);
        };
        match tokio::time::timeout(
            TIMEOUT,
            crate::upstream::connect(addr, &self.measurement, &self.part, &self.tls),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => {
                debug!("checking {addr}: {e}");
                refuse(pingora_core::ErrorType::ConnectError)
            }
            Err(_) => {
                debug!("checking {addr}: did not answer within the timeout");
                refuse(pingora_core::ErrorType::ConnectTimedout)
            }
        }
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success { BACK } else { OUT }
    }

    /// Nothing about a member reaches a log line through the library. It builds
    /// this from `Debug`, which would put the address in a record whose rate
    /// the host chooses.
    fn backend_summary(&self, _target: &Backend) -> String {
        "a member".to_owned()
    }
}

/// The members of one group under one name, with the check they answer to and
/// the rate it is asked at.
///
/// The ordinary shape from the library's own examples: the check and its
/// frequency belong to the set, and a task started against it runs the
/// schedule — see [`check_forever`].
pub async fn balancer(
    members: BTreeSet<Backend>,
    measurement: &str,
    part: &Arc<Part>,
    tls: &Tls,
) -> Balancer {
    let mut balancer = Balancer::from_backends(Backends::new(Static::new(members)));
    balancer.set_health_check(Box::new(Attested {
        measurement: measurement.to_owned(),
        part: part.clone(),
        tls: tls.clone(),
    }));
    balancer.health_check_frequency = Some(INTERVAL);
    balancer.parallel_health_check = AT_ONCE;
    // The set is already known, so this only publishes it. It cannot fail for a
    // static membership, and a table that failed to publish one would route
    // nowhere.
    let _ = balancer.update().await;
    balancer
}

/// Ask every member of a table once, before anything routes against it.
///
/// The schedule [`check_forever`] starts also asks immediately, so a push pays
/// for one extra pass. That is the price of the table being CURRENT only once
/// the answers are in: the schedule cannot hold publication back, because it is
/// started against a table that must already exist.
pub async fn first_pass<'a>(sets: impl Iterator<Item = &'a Arc<Balancer>>) {
    let mut asking = tokio::task::JoinSet::new();
    for set in sets {
        let set = set.clone();
        asking.spawn(async move { set.backends().run_health_check(AT_ONCE).await });
    }
    while asking.join_next().await.is_some() {}
}

/// Keep every member of the CURRENT table checked, for ever.
///
/// One task per set of members, because that is where the check and its
/// schedule live — and they are replaced together whenever a push replaces the
/// table. Dropping the previous `JoinSet` is what ends the previous generation:
/// a check the library is midway through is cancelled, which it is written to
/// tolerate, and nothing can outlive the table it was asking about.
///
/// What a push costs is therefore the health of every member: a new set starts
/// with each of them counted able to take work, so one the previous checks had
/// found absent is given requests again until this schedule's first pass dials
/// it. That window is at most [`INTERVAL`], and the requests that meet an
/// absent member in it fail. A push is a rare, deliberate act, so that is
/// cheaper than keeping health alive across a change to the very thing it
/// described.
///
/// Await this on the role's own task rather than spawning it: a role that
/// stopped asking would keep every member it ever took out of service out of
/// it, and slide into refusing new sessions with no way back.
pub async fn check_forever(mut table: watch::Receiver<Arc<Upstreams>>) -> ! {
    // Held across the whole loop so a generation's services never see their
    // shutdown watch close; ending one is dropping its tasks.
    let (_never, shutdown) = watch::channel(false);
    loop {
        let mut generation = tokio::task::JoinSet::new();
        for set in table.borrow().balancers() {
            let shutdown = shutdown.clone();
            generation.spawn(async move {
                BackgroundService::start(&*set, shutdown).await;
            });
        }
        debug!("checking {} set(s) of members", generation.len());

        if table.changed().await.is_err() {
            // The sender lives as long as the process, so this cannot happen
            // while anything is still serving.
            std::future::pending::<()>().await;
        }
        // Dropping it aborts the generation that was asking about the table
        // this push has just replaced.
        drop(generation);
    }
}

/// One member of a group, preferring those that can be given work.
///
/// Readiness is a PREFERENCE and not a filter. The session this request belongs
/// to lives in this group and nowhere else, so a group whose members all look
/// unwell is still the only place it could go — refusing every request until
/// something proves otherwise would turn one bad answer into an outage. The
/// nginx rule, and for the same reason.
///
/// ONE selection, whichever of the two questions is being asked, and that is
/// what keeps the turn even. Round robin takes its cursor once per selection —
/// `RoundRobin::next` is a single `fetch_add`, and the iteration bound does not
/// touch it — so asking twice moves the cursor twice. A group with nothing
/// usable would then advance by two per request, and every request in a group
/// of two would land on the same member.
pub fn pick(balancer: &Balancer) -> Option<Backend> {
    let backends = balancer.backends();
    let members = backends.get_backend();
    // Settled before the selection rather than during it, because the answer
    // decides which question is asked and the question may only be asked once.
    let any_usable = members.iter().any(|member| backends.ready(member));
    balancer.select_with(b"", members.len(), |_, usable| usable || !any_usable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both shapes a fleet address takes, carried whole and handed back
    /// unchanged. The vsock one is the reason this file exists: it is neither
    /// of the two things the library's address type is for, and it is the shape
    /// the attested build uses — which is the build that cannot be compiled on
    /// a developer's machine, so it is pinned here instead.
    #[test]
    fn an_address_of_either_shape_comes_back_as_it_went_in() {
        for addr in ["vsock://3:9000", "127.0.0.1:1000", "vsock://4294967295:1"] {
            let member = member(addr).unwrap_or_else(|| panic!("`{addr}` could not be carried"));
            assert_eq!(addr_of(&member), Some(addr));
        }
    }

    /// Two addresses are two members, and one address is one — which is the
    /// whole of what the library needs this field for.
    #[test]
    fn the_address_is_what_tells_two_members_apart() {
        assert_eq!(member("vsock://3:9000"), member("vsock://3:9000"));
        assert_ne!(member("vsock://3:9000"), member("vsock://3:9001"));
        assert_ne!(member("vsock://3:9000"), member("vsock://4:9000"));
    }
}
