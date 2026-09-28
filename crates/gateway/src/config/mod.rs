//! What the host may tell this role, the check a push has to pass, and the port
//! it arrives on.
//!
//! ## Why this is not on the command line
//!
//! The command line is measured, so anything on it is part of this role's
//! digest. What arrives here is the fleet's SHAPE — which api builds run and at
//! which addresses — and it changes whenever a machine is added or a build is
//! rolled. On the command line it would make the digest a function of the
//! deployment, and a caller, which verifies THIS role and then trusts it to
//! check api, would have nothing stable to verify against.
//!
//! ## Why it may come from the host at all
//!
//! Every value here says WHERE this role may go, or HOW MUCH it may spend —
//! never WHETHER to check what it finds there. A group's measurement is a
//! routing hint the connector proves at the handshake, so a lie about one is a
//! route that fails, not a route that is taken. There is deliberately no field
//! that could say otherwise.
//!
//! How much is `tuning`: every timeout, limit and retry count this role runs
//! by. On the command line each would change the measurement callers verify, so
//! a tweak would be a release. Here each is availability only — a bad value
//! makes this role slower or refuse more, which the host could cause anyway by
//! not carrying bytes — and each is bounded by what this build allows. Each
//! also has a default, so a push says only the numbers it wants changed.
//!
//! ## A group, not a machine
//!
//! api seals a session's state under a key derived from the chip and the
//! measurement, so every instance of one build on one part can serve any
//! session of that build. The unit this role routes to is therefore that set —
//! a GROUP — and its members are interchangeable. A label names the group, so a
//! link survives the loss of any one machine, and a request whose
//! member has gone before any of it was sent is served by another.
//!
//! The host declares which instances form a group, and this role does not take
//! that on trust: every leg proves a chip and a measurement at the handshake,
//! and a member that proves something other than its group's is refused — see
//! `crate::upstream::connect`. So is one whose key domain another label already
//! holds, and a push that lists one address under two groups: a domain is one
//! group, or a label no other session shares would tag the session placed on it.
//! Those two are all a leg proves of api's key, which the guest policy goes
//! into as well — so they are necessary for a group, not sufficient; see
//! `crate::upstream`.
//!
//! ## The shape
//!
//! Groups are declared once and the names refer to them, which is how a
//! reverse proxy's configuration has always read: what a backend IS, then which
//! of them each served name may reach. A group's addresses differ per name
//! because one api process serves the two on two ports.
//!
//! ```text
//! groups: one -> the build it runs
//! names:  verify.example.com -> one -> the addresses of its members there
//!         api.example.com    -> one -> the addresses of its members there
//! routes: api.example.com -> POST /api/v1/sessions         -> reject_named_group,
//!                                                             refusing the builds it closes
//!                         -> /api/v1/sessions/{*rest}      -> require_named_group
//! certificates: chains an issuer signed for this role's key, if any
//! acme:   tls-alpn-01 -> where a validator's connection is carried, if anywhere
//! ```
//!
//! The certificates are what a browser is shown, in place of this role's
//! self-signed one: each for the names it covers, and together for every name.
//! They are not a setting either: they are presented only if they are for this
//! role's own key, so a wrong one is a certificate refused, never a caller
//! answered by someone else — see `crate::config::push`.
//!
//! `acme` is where the host's ACME client answers a validator, for a challenge
//! that has to be answered on the public names' own port. Only where: which
//! connections are a validator's this role tells from each connection itself,
//! and no push can send an applicant's there — see `crate::listener::acme`. Nor
//! is it an upstream. Nothing there is attested, and nothing is carried there
//! that did not come from the host in the first place.
//!
//! The routes are what a name's requests are held to, by method and path, as a
//! reverse proxy's locations are: where a request may name its group and where
//! it must. Which of api's requests create a session is api's business, and
//! only the host can say it without this role holding a copy of api's routes —
//! see `crate::route::Rules`. A path is written as api writes its own routes,
//! so the host can copy them. Like everything else here, they say where a
//! request may go, never whether what it reaches is checked.
//!
//! A rule that places may also refuse builds: a release being retired takes no
//! new session, and a caller that names it is told it is gone, while the
//! sessions it holds finish through their links — see
//! `crate::config::Route::refuse_measurements`.
//!
//! ## The type is the grammar
//!
//! JSON decoded into structs with `deny_unknown_fields`: an unknown or misspelt
//! key is a refusal rather than a line quietly ignored, and nothing beyond what
//! the structs spell can be expressed.
//!
//! What the grammar cannot say is whether a value could do its job — a label
//! that survives a URL, a measurement a quote could carry, an address something
//! could dial, a group named in one place and declared in none. That is the
//! second step, and it is a type rather than a habit: a decoded table is one
//! type, [`ValidatedConfig`] is what routing is given, and the only way between
//! them is [`ValidatedConfig::parse`].
//!
//! Both live in `table`, a module of their own that nothing else in this build
//! is inside of — not even the port beside it. Rust lets a module see into its
//! parent's private items, so a port declared inside the module that held the
//! decoded table could build a checked one without the check. Kept apart, it
//! cannot: an unchecked table is a thing that cannot exist anywhere else in
//! this build.
//!
//! A push is refused WHOLE if any part of it is wrong, and the response says
//! which. There is a sender to tell, and a table missing one declared build is
//! a quieter failure than a push that did not apply.

pub mod push;
mod table;
#[cfg(test)]
pub(crate) mod testing;

pub use table::{
    Flag, ListenerTuning, MOST_DESCRIPTORS, OWN_DESCRIPTORS, Route, Tuning, UpstreamTuning,
    ValidatedConfig,
};
