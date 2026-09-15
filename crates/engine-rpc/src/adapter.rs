//! The one place an argument gets wrapped on its way into a server.
//!
//! Each leg has two views of its contract: the RAW trait remoc generated the wire
//! form from, and a second whose arguments arrive as
//! [`Untrusted`](enclavid_boundary::Untrusted) under a scope the serving role
//! named. [`Untrusting`] is the bridge — it takes an implementation of the second
//! and presents it as the first, so remoc still sees what it generated from and
//! the role still writes what it actually judges.
//!
//! One type rather than one per leg, because there is one idea here and it is
//! mechanical: the judgement lives in the implementor's `Scope` and in how it
//! discharges, never in the wrapping. Each leg's trait impl sits with that leg's
//! view; what they share is this.
//!
//! `pub(crate)` on purpose. No caller should ever reach for it: the doors in
//! [`crate::leg`] apply it themselves, and no raw server type is exported, so
//! there is no unwrapped shape outside this crate to implement by mistake.

pub(crate) struct Untrusting<T>(pub T);
