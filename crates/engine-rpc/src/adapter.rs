//! Where the compile leg's argument gets wrapped on its way into the server.
//!
//! The leg has two views of its contract: the RAW trait remoc generated the wire
//! form from, and a second whose argument arrives as
//! [`Untrusted`](enclavid_boundary::Untrusted) under a scope the serving role
//! named. [`Untrusting`] is the bridge — it takes an implementation of the second
//! and presents it as the first, so remoc still sees what it generated from and
//! the role still writes what it actually judges. The execute leg's two servers
//! get theirs from `#[protocol]`, which writes the same bridge per contract.
//!
//! `pub(crate)` on purpose. No caller should ever reach for it: the door in
//! [`crate::leg`] applies it itself, and no raw server type is exported, so
//! there is no unwrapped shape outside this crate to implement by mistake.

pub(crate) struct Untrusting<T>(pub T);
