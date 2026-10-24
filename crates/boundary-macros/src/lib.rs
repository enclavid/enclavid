//! The macros that write a boundary's types.
//!
//! [`boundary!`] declares one end of a boundary — the type a wrapper's `B`
//! names — and writes, for every type crossing it, a `Sends` / `Receives` impl
//! whose `Open` is what its direction opens less what the declaration answers.
//!
//! [`macro@protocol`] sits on a remoc contract and writes what its serving end
//! must declare, and the contract as its server sees it at a declared end.
//!
//! [`macro@calls`] sits on the doors a calling end reaches a contract through,
//! and writes what that end must declare: what the doors take and hand back.

use proc_macro::TokenStream;
use proc_macro2::{Delimiter, TokenTree};
use quote::{ToTokens, format_ident};
use syn::{Path, PathSegment};

mod calls;
mod end;
mod protocol;

/// A type or path as one comparable string, as the macros write it into data:
/// no spaces, but one between two words, so `&'static crate::Name` stays three.
fn key(t: &impl ToTokens) -> String {
    fn write(tokens: proc_macro2::TokenStream, out: &mut String) {
        let mut word = false;
        for token in tokens {
            match token {
                TokenTree::Group(g) => {
                    let (open, close) = match g.delimiter() {
                        Delimiter::Parenthesis => ("(", ")"),
                        Delimiter::Bracket => ("[", "]"),
                        Delimiter::Brace => ("{", "}"),
                        Delimiter::None => ("", ""),
                    };
                    out.push_str(open);
                    write(g.stream(), out);
                    out.push_str(close);
                    word = false;
                }
                TokenTree::Punct(p) => {
                    out.push(p.as_char());
                    word = false;
                }
                TokenTree::Ident(_) | TokenTree::Literal(_) => {
                    if word {
                        out.push(' ');
                    }
                    out.push_str(&token.to_string());
                    word = true;
                }
            }
        }
    }
    let mut out = String::new();
    write(t.to_token_stream(), &mut out);
    out
}

/// `path` with `suffix` on its last segment: `a::Contract` → `a::ContractCalls`.
fn with_suffix(path: &Path, suffix: &str) -> Path {
    let mut path = path.clone();
    if let Some(last) = path.segments.last_mut() {
        let ident = format_ident!("{}{}", last.ident, suffix, span = last.ident.span());
        *last = PathSegment::from(ident);
    }
    path
}

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
/// and `serves`, and who sees the bytes on the way. Each protocol must have
/// what it asks of the end declared here, which the compiler checks on this
/// declaration: for one it calls, what its doors take and hand back
/// ([`macro@calls`]); for one it serves, every type it carries
/// ([`macro@protocol`]).
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
/// and `expose_builder`, which starts building a value to leave it from what it
/// is built from (`enclavid_boundary::ExposedBuilder`); a `Sends` / `Receives`
/// impl per type; and, in the crate's test build, the declaration as data
/// (`DECLARATION`) and a test that the end declares nothing it never holds
/// (`<end>_declares_nothing_it_never_holds`, from `End::unheld`).
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
///   * `NameServes` — what an end that serves it must declare: every argument,
///     answer and error, as supertraits, so a bound on it brings them all along.
///     An error crosses fully answered. It carries the contract as data,
///     `PROTOCOL`, which the declaration of an end that serves it holds.
///   * `NameAt<B>` — the contract as its server sees it at end `B`: each
///     argument arrives `Untrusted` with what `B` left open, each answer leaves
///     `Exposed` and answered, an error leaves bare.
///   * `NameAdapter<T, B>` — serves a `NameAt<B>` as the raw `Name`.
///   * `NameWire` — the contract as data, each method and what crosses for it,
///     which [`macro@calls`] builds the calling end's `PROTOCOL` from.
///
/// What an end that calls it declares is not written here: a calling end holds
/// what its doors take and hand back, not what crosses, and [`macro@calls`]
/// reads that off the doors.
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

/// Read the doors a calling end reaches a contract through, placed on their
/// `impl<B> Leg<B>` block, generic over the end alone: `#[calls(path::Contract)]`.
///
/// Each `pub async fn` in the block is a door, one for each method of the
/// contract, by name. From their signatures it writes `ContractCalls` — what an
/// end that calls the contract must declare — and bounds the block on it:
///
///   * an argument `Exposed<X, _, B>`: the end sends `X`;
///   * a `<B as Receives<Y>>` in what a door hands back: the end receives `Y`;
///   * the error of its `Result`: received, answered in full;
///   * a door's `where` on `B`, such as `Sends<X, Open = ()>`: asked as written.
///
/// `B` in any of them is the end, and `Self` in the trait. The trait carries the
/// contract as data, `PROTOCOL`, each method with what its door takes and hands
/// back. A door named for no method, or a method left without one, is refused by
/// the compiler.
#[proc_macro_attribute]
pub fn calls(attr: TokenStream, item: TokenStream) -> TokenStream {
    calls::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
