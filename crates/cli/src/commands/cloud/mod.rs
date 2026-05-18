//! `enclavid cloud ...` — anything that talks to the Enclavid SaaS:
//! authentication (login/logout/token) and workspace selection. The
//! grouping isolates Logto / platform-specific commands from the
//! registry-agnostic policy tooling under `enclavid policy ...`.

pub mod login;
pub mod logout;
pub mod token;
pub mod workspace;
