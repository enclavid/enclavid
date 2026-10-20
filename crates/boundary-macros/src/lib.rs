//! The macros that write a boundary's types.
//!
//! [`boundary!`] declares one end of a boundary — the type a wrapper's `B`
//! names — and writes, for every type crossing it, a `Sends` / `Receives` impl
//! whose `Open` is what its direction opens less what the declaration answers.
//!
//! [`macro@protocol`] sits on a remoc contract and writes what its two ends must
//! declare, and the contract as its server sees it at a declared end.

use proc_macro::TokenStream;

mod end;
mod protocol;

/// Declare one end of a boundary, as the role holding it judges what crosses.
///
/// ```ignore
/// boundary! {
///     /// The execution-worker, over one RA-TLS leg api pins and the host splices.
///     pub ExecutionWorker {
///         calls: [RemoteExecutor],
///         serves: [RemoteCallbacks],
///         observer: HostSplices,
///     }
///
///     out (AuthN, AuthZ, Covert) {
///         /// One compile-time-pinned measurement; any other peer fails the handshake.
///         _: AuthN::Identified,
///         /// The props every round of this session hands the same peer.
///         PrepareRequest: AuthZ::NoSecret,
///         RunRequest,
///     }
///
///     in (Asserted,) {
///         /// A prompt goes to the applicant, its sole auditor.
///         RunOutcome: Asserted::Contained,
///         PrepareOutcome,
///     }
/// }
/// ```
///
/// The header names the end and what it talks over: the protocols it `calls`
/// and `serves` (each must have every type it carries declared here, which the
/// compiler checks on this declaration) and who sees the bytes on the way.
///
/// Each `out` / `in` block opens the concerns in its tuple on every type it
/// lists: at least one, each once, and each a marker of the block's direction
/// (`InboundConcern` / `OutboundConcern`). A line `Type: Marker::Kind` answers
/// that concern for every value of the type, once, with the `///` above it as
/// the reason, which it must have; `_: Marker::Kind` answers it for every type in
/// the block; a bare `Type` only says it crosses, and takes no `///`. Whatever no
/// line answers stays open on the value, for the site that holds it. An answer
/// here must be an argued kind: a declaration does no work.
///
/// It writes the end's type, with `expose` — which opens a value to leave it —
/// and `expose_as`, which opens the parts a value is built from as that value
/// (`enclavid_boundary::Parts`); a `Sends` / `Receives` impl per type; and, in
/// the crate's test build, the declaration as data (`DECLARATION`).
#[proc_macro]
pub fn boundary(input: TokenStream) -> TokenStream {
    end::expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Read a remoc contract, placed above its `#[remoc::rtc::remote]`. A contract
/// is named `Remote*` after what it fronts — `RemoteExecutor`, `RemoteCallbacks`
/// — so the names written from it read as roles of that.
///
/// For `trait Name`, it writes:
///
///   * `NameCalls` / `NameServes` — what an end that calls it / serves it must
///     declare: every argument, answer and error, as supertraits, so a bound on
///     either brings them all along. An error crosses fully answered.
///   * `NameAt<B>` — the contract as its server sees it at end `B`: each
///     argument arrives `Untrusted` with what `B` left open, each answer leaves
///     `Exposed` and answered, an error leaves bare.
///   * `NameAdapter<T, B>` — serves a `NameAt<B>` as the raw `Name`.
///
/// An argument marked `#[capability(Door)]` is a remoc client handed over, not a
/// value: the server gets it as `Door<B>`, built with `From`, so that what the
/// server sends back through it goes through its end's declaration too. A reply,
/// error or argument of `()` — or of an alias of it — is refused: an end's
/// declaration answers for a type, and `()` would be every unit one at once.
#[proc_macro_attribute]
pub fn protocol(attr: TokenStream, item: TokenStream) -> TokenStream {
    protocol::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
