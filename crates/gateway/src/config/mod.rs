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
//! link and a token survive the loss of any one machine, and a request whose
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
//! ```
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
// Its users are the tests that stand api up on TCP, which a vsock build has no
// place for.
#[cfg(all(test, not(feature = "vsock")))]
pub(crate) mod testing;

pub use table::{
    ListenerTuning, MOST_DESCRIPTORS, OWN_DESCRIPTORS, Tuning, UpstreamTuning, ValidatedConfig,
};
