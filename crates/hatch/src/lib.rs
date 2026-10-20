//! The hatch-CVM: the fleet's one way out.
//!
//! It is the only guest with a network interface, and it holds no applicant
//! data and no seal key. api pins its measurement and reaches it over RA-TLS
//! (`hatch-rpc`); it reaches outside through its interface, and the operator's
//! hooks (`hooks.openapi.yaml`) through a relay on the host.
//!
//!   * [`hooks`] — who a request to the consumer API is from, and what a
//!     consumer may do, asked of the hooks the launch switched on;
//!   * [`oci`] and [`kbs`] — what api names outside: a registry's pulls, a key
//!     broker's legs;
//!   * [`service`] — the `RemoteHatch` all of that is served as, at this role's
//!     end of the leg, which [`boundary`] declares.
//!
//! The interface carries what consumers name and nothing of the operator's: in
//! the measured build the hooks are reached over vsock, so no address a
//! consumer writes — a name, a literal, a redirect — leads to one.

pub mod boundary;
pub mod hooks;
pub mod kbs;
pub mod oci;
pub mod service;
