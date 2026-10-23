//! `#[calls]` — what an end that calls a protocol declares, read off the doors it
//! calls through.

use std::collections::BTreeSet;

use proc_macro2::{Group, TokenStream, TokenTree};
use quote::{ToTokens, format_ident, quote};
use syn::visit::Visit;
use syn::{
    Error, FnArg, GenericArgument, GenericParam, Ident, ImplItem, ImplItemFn, ItemImpl, Path,
    PathArguments, Result, Type, TypeParamBound, TypePath, Visibility, WherePredicate,
};

use crate::protocol::{is_unit, not_unit, refuse_unit, result_types};
use crate::{key, with_suffix};

/// One door, read off its signature.
struct Door {
    name: Ident,
    /// What it takes, answered at the end.
    sends: Vec<Type>,
    /// What it hands back, open on what the end left open on it.
    receives: Vec<Type>,
    error: Type,
    /// What else it asks of the end, as its `where` says.
    asks: Vec<TypeParamBound>,
}

/// Whether `ty` is the end itself.
fn is_end(ty: &Type, end: &Ident) -> bool {
    matches!(ty, Type::Path(p) if p.qself.is_none() && p.path.is_ident(end))
}

/// Whether `tokens` hold the identifier `name` anywhere.
fn mentions(tokens: TokenStream, name: &str) -> bool {
    tokens.into_iter().any(|t| match t {
        TokenTree::Ident(i) => i == name,
        TokenTree::Group(g) => mentions(g.stream(), name),
        _ => false,
    })
}

/// `tokens` with the end named as `Self`, as the trait the end implements reads
/// them.
fn as_self(tokens: TokenStream, end: &Ident) -> TokenStream {
    tokens
        .into_iter()
        .map(|t| match t {
            TokenTree::Ident(i) if i == *end => TokenTree::Ident(Ident::new("Self", i.span())),
            TokenTree::Group(g) => {
                let mut renamed = Group::new(g.delimiter(), as_self(g.stream(), end));
                renamed.set_span(g.span());
                TokenTree::Group(renamed)
            }
            other => other,
        })
        .collect()
}

/// Whether `path` ends in a segment named `name`.
fn last_is(path: &Path, name: &str) -> bool {
    path.segments.last().is_some_and(|s| s.ident == name)
}

/// The type arguments `path`'s last segment is given, as `X` in `Sends<X>` or
/// `X, S, B` in `Exposed<X, S, B>`.
fn type_args(path: &Path) -> Vec<&Type> {
    match path.segments.last().map(|s| &s.arguments) {
        Some(PathArguments::AngleBracketed(a)) => a
            .args
            .iter()
            .filter_map(|g| match g {
                GenericArgument::Type(t) => Some(t),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// `ty` as `Exposed<X, S, E>`: what it carries, and the end it was answered at.
fn exposed(ty: &Type) -> Option<(&Type, &Type)> {
    let Type::Path(p) = ty else { return None };
    if p.qself.is_some() || !last_is(&p.path, "Exposed") {
        return None;
    }
    match type_args(&p.path).as_slice() {
        [x, _, at] => Some((x, at)),
        _ => None,
    }
}

/// Whether `bound` is `Sends<_, Open = ()>`: what crosses, answered in full by
/// the end's declaration.
fn answered_in_full(bound: &TypeParamBound) -> bool {
    let TypeParamBound::Trait(t) = bound else {
        return false;
    };
    let Some(PathArguments::AngleBracketed(a)) = t.path.segments.last().map(|s| &s.arguments)
    else {
        return false;
    };
    last_is(&t.path, "Sends")
        && a.args.iter().any(|g| {
            matches!(g, GenericArgument::AssocType(open) if open.ident == "Open" && is_unit(&open.ty))
        })
}

/// The first type argument of each bound among `asks` on `relation`, as the
/// end's trait reads it: what a door's `where` says crosses.
fn asked(asks: &[TypeParamBound], relation: &str, end: &Ident) -> Vec<TokenStream> {
    asks.iter()
        .filter_map(|bound| match bound {
            TypeParamBound::Trait(t) if last_is(&t.path, relation) => type_args(&t.path)
                .first()
                .map(|ty| as_self(ty.to_token_stream(), end)),
            _ => None,
        })
        .collect()
}

/// Every `<end as Receives<Y>>` in what a door hands back: what arrives, open on
/// what the end left open on it.
struct Handed<'a> {
    end: &'a Ident,
    found: Vec<Type>,
}

impl<'ast> Visit<'ast> for Handed<'_> {
    fn visit_type_path(&mut self, tp: &'ast TypePath) {
        if let Some(q) = &tp.qself
            && is_end(&q.ty, self.end)
            && let Some(relation) = tp.path.segments.iter().take(q.position).next_back()
            && relation.ident == "Receives"
            && let PathArguments::AngleBracketed(a) = &relation.arguments
            && let Some(GenericArgument::Type(y)) = a.args.first()
        {
            self.found.push(y.clone());
        }
        syn::visit::visit_type_path(self, tp);
    }
}

/// Read one door, refusing what it cannot say is answered.
fn read_door(f: &ImplItemFn, end: &Ident) -> Result<Door> {
    if let Some(cfg) = f
        .attrs
        .iter()
        .find(|a| a.path().is_ident("cfg") || a.path().is_ident("cfg_attr"))
    {
        return Err(Error::new_spanned(
            cfg,
            "a door is in every build of its block: a `cfg` goes on the block, so no \
             method is ever left without its door",
        ));
    }
    if f.sig.asyncness.is_none() {
        return Err(Error::new_spanned(&f.sig, "a door is a `pub async fn`"));
    }
    // `Self` in a door is the leg it is a method of; in the trait written from
    // it, `Self` is the end. A door names its end as its block does.
    let mut signature = TokenStream::new();
    for input in &f.sig.inputs {
        if let FnArg::Typed(pt) = input {
            pt.ty.to_tokens(&mut signature);
        }
    }
    f.sig.output.to_tokens(&mut signature);
    f.sig.generics.where_clause.to_tokens(&mut signature);
    if mentions(signature, "Self") {
        return Err(Error::new_spanned(
            &f.sig,
            format!(
                "a door names its end `{end}`: `Self` in it is the leg, and would be the end \
                 in the trait written from it"
            ),
        ));
    }

    let asks: Vec<TypeParamBound> = f
        .sig
        .generics
        .where_clause
        .iter()
        .flat_map(|w| &w.predicates)
        .filter_map(|p| match p {
            WherePredicate::Type(p) if is_end(&p.bounded_ty, end) => Some(p.bounds.iter()),
            _ => None,
        })
        .flatten()
        .cloned()
        .collect();
    let builds = asks.iter().any(answered_in_full);
    let generics: Vec<&Ident> = f.sig.generics.type_params().map(|p| &p.ident).collect();

    let mut sends = Vec::new();
    for input in &f.sig.inputs {
        let FnArg::Typed(pt) = input else { continue };
        let ty = &*pt.ty;
        if let Some((part, at)) = exposed(ty) {
            if !is_end(at, end) {
                return Err(Error::new_spanned(
                    ty,
                    format!("a door takes what its end `{end}` answered, not another end"),
                ));
            }
            refuse_unit(part, "part")?;
            sends.push(part.clone());
        } else if matches!(ty, Type::Path(p) if p.qself.is_none()
            && generics.iter().any(|g| p.path.is_ident(*g)))
        {
            // A server or a capability the door is handed, judged where it is used.
        } else if !builds {
            return Err(Error::new_spanned(
                ty,
                format!(
                    "a door takes what its end answered — `Exposed<_, _, {end}>` — or, building \
                     what crosses from a value of its own, says so: \
                     `where {end}: Sends<_, Open = ()>`"
                ),
            ));
        }
    }

    let (ok, error) = result_types(&f.sig.output, "door")?;
    refuse_unit(&error, "error")?;
    let mut handed = Handed {
        end,
        found: Vec::new(),
    };
    handed.visit_type(&ok);
    if handed.found.is_empty() {
        return Err(Error::new_spanned(
            &ok,
            format!(
                "a door hands back what arrived open on what its end left open: an \
                 `Untrusted<_, <{end} as Receives<_>>::Open, {end}>` in what it returns"
            ),
        ));
    }
    for part in &handed.found {
        refuse_unit(part, "part")?;
    }
    Ok(Door {
        name: f.sig.ident.clone(),
        sends,
        receives: handed.found,
        error,
        asks,
    })
}

pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    if attr.is_empty() {
        return Err(Error::new(
            proc_macro2::Span::call_site(),
            "`#[calls(Contract)]` names the contract these are the doors of",
        ));
    }
    let contract: Path = syn::parse2(attr)?;
    let mut block: ItemImpl = syn::parse2(item)?;
    if let Some((_, path, _)) = &block.trait_ {
        return Err(Error::new_spanned(
            path,
            "doors are a type's own methods, not a trait's",
        ));
    }
    let end = match block.generics.params.iter().collect::<Vec<_>>().as_slice() {
        [GenericParam::Type(end)] => end.ident.clone(),
        _ => {
            return Err(Error::new_spanned(
                &block.generics,
                "a door block is generic over the end it is held at, and nothing else",
            ));
        }
    };
    let name = &contract
        .segments
        .last()
        .ok_or_else(|| Error::new_spanned(&contract, "a contract's path"))?
        .ident;
    let calls = format_ident!("{}Calls", name);
    let wire = with_suffix(&contract, "Wire");

    let mut doors = Vec::new();
    for item in &block.items {
        let ImplItem::Fn(f) = item else { continue };
        if matches!(f.vis, Visibility::Public(_)) {
            doors.push(read_door(f, &end)?);
        }
    }
    if doors.is_empty() {
        return Err(Error::new_spanned(
            &block.self_ty,
            "a door block holds its contract's doors: a `pub async fn` for each method",
        ));
    }

    // What the end declares: each part every door takes or hands back, each
    // error answered in full, and what each door's `where` asks of it.
    let mut bounds = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |bound: TokenStream| {
        if seen.insert(bound.to_string()) {
            bounds.push(bound);
        }
    };
    for door in &doors {
        for ty in &door.sends {
            let ty = as_self(ty.to_token_stream(), &end);
            push(quote!(::enclavid_boundary::Sends<#ty>));
        }
        for ty in &door.receives {
            let ty = as_self(ty.to_token_stream(), &end);
            push(quote!(::enclavid_boundary::Receives<#ty>));
        }
        let error = as_self(door.error.to_token_stream(), &end);
        push(quote!(::enclavid_boundary::Receives<#error, Open = ()>));
        for ask in &door.asks {
            push(as_self(ask.to_token_stream(), &end));
        }
    }

    // Each part and error held to being a type of its own by the compiler too,
    // where it names no end: one that does is checked by spelling alone.
    let mut checks = Vec::new();
    let mut checked = BTreeSet::new();
    for ty in doors
        .iter()
        .flat_map(|d| d.sends.iter().chain(&d.receives).chain([&d.error]))
    {
        if !mentions(ty.to_token_stream(), &end.to_string()) && checked.insert(key(ty)) {
            checks.push(not_unit(ty));
        }
    }

    // Each method as the contract wrote it down, with what its door takes and
    // hands back. A door with no method of its name finds no data to start from,
    // and a method with no door leaves the count short.
    let methods = doors.iter().map(|door| {
        let method = &door.name;
        let sends = door
            .sends
            .iter()
            .map(|ty| as_self(ty.to_token_stream(), &end))
            .chain(asked(&door.asks, "Sends", &end))
            .map(|ty| key(&ty));
        let receives = door
            .receives
            .iter()
            .map(|ty| as_self(ty.to_token_stream(), &end))
            .chain(asked(&door.asks, "Receives", &end))
            .map(|ty| key(&ty));
        quote! {
            ::enclavid_boundary::declaration::Method {
                door: ::core::option::Option::Some(::enclavid_boundary::declaration::Door {
                    sends: &[ #( #sends ),* ],
                    receives: &[ #( #receives ),* ],
                }),
                ..#wire::#method
            }
        }
    });
    let count = doors.len();
    let every_method =
        format!("every method of `{name}` has one door in this block, and every door one method");
    let doc = format!(
        " What an end that calls `{name}` declares: what each of its doors takes and\n \
         hands back, `Self` being that end, each error answered in full, and what a\n \
         door's `where` asks of the end."
    );

    block
        .generics
        .make_where_clause()
        .predicates
        .push(syn::parse_quote!(#end: #calls));

    Ok(quote! {
        #[doc = #doc]
        pub trait #calls: ::core::marker::Sized + ::enclavid_boundary::Boundary #( + #bounds )* {
            /// This protocol, as data, for the declaration of an end that calls it:
            /// what crosses for each method, and what its door takes and hands back.
            const PROTOCOL: ::enclavid_boundary::declaration::Protocol =
                ::enclavid_boundary::declaration::Protocol {
                    name: #wire::PROTOCOL.name,
                    methods: &[ #( #methods ),* ],
                };
        }

        const _: () = ::core::assert!(#wire::PROTOCOL.methods.len() == #count, #every_method);

        #( #checks )*

        #block
    })
}

/// What `#[calls]` refuses as it reads a door block. Each case is the well-formed
/// block with one thing wrong.
#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream;
    use quote::quote;

    fn reads(attr: TokenStream, block: TokenStream) -> bool {
        super::expand(attr, block).is_ok()
    }

    /// A door block of `doors`, at end `B`.
    fn block(doors: TokenStream) -> TokenStream {
        quote!(impl<B> Leg<B> { #doors })
    }

    #[test]
    fn a_well_formed_door_block_is_read() {
        assert!(reads(
            quote!(Contract),
            block(quote! {
                pub async fn op<C>(&self, part: Exposed<Part<B>, (), B>, back: C)
                    -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error>
                {
                    unimplemented!()
                }
                pub async fn built(&self, source: Source)
                    -> Result<(Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Len), Error>
                where
                    B: Sends<Built, Open = ()>,
                {
                    unimplemented!()
                }
                fn helper(&self) {}
            })
        ));
    }

    /// What the end declares is read off the doors into the trait — each part,
    /// each error, each `where`, the end as `Self` — and the block is bound to it.
    #[test]
    fn the_end_declares_what_its_doors_take_and_hand_back() {
        let written = super::expand(
            quote!(crate::contract::Contract),
            block(quote! {
                pub async fn op(&self, name: Exposed<Name, (), B>, part: Exposed<Part<B>, (), B>)
                    -> Result<(Vec<Untrusted<Slot, <B as Receives<Slot>>::Open, B>>, Untrusted<Version, <B as Receives<Version>>::Open, B>), Error>
                {
                    unimplemented!()
                }
                pub async fn built(&self, source: Source)
                    -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error>
                where
                    B: Sends<Built, Open = ()>,
                {
                    unimplemented!()
                }
            }),
        )
        .unwrap();
        let file: syn::File = syn::parse2(written).unwrap();
        let calls = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Trait(t) if t.ident == "ContractCalls" => Some(t),
                _ => None,
            })
            .expect("the trait");
        let supertraits: Vec<String> = calls.supertraits.iter().map(crate::key).collect();
        assert_eq!(
            supertraits,
            [
                "::core::marker::Sized",
                "::enclavid_boundary::Boundary",
                "::enclavid_boundary::Sends<Name>",
                "::enclavid_boundary::Sends<Part<Self>>",
                "::enclavid_boundary::Receives<Slot>",
                "::enclavid_boundary::Receives<Version>",
                "::enclavid_boundary::Receives<Error,Open=()>",
                "::enclavid_boundary::Receives<Rep>",
                "Sends<Built,Open=()>",
            ]
        );
        let written = quote!(#calls).to_string().replace(' ', "");
        assert!(written.contains("crate::contract::ContractWire::PROTOCOL"));
        let bound = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Impl(b) => b.generics.where_clause.as_ref(),
                _ => None,
            })
            .expect("the block, bound");
        let bound: Vec<String> = bound.predicates.iter().map(crate::key).collect();
        assert_eq!(bound, ["B:ContractCalls"]);
    }

    #[test]
    fn a_block_without_a_contract_or_a_door_is_refused() {
        let door = quote! {
            pub async fn op(&self) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> {
                unimplemented!()
            }
        };
        assert!(reads(quote!(Contract), block(door.clone())));
        assert!(!reads(quote!(), block(door)));
        let helper = block(quote! { fn helper(&self) {} });
        assert!(!reads(quote!(Contract), helper));
    }

    #[test]
    fn a_block_generic_over_more_than_its_end_is_refused() {
        let door = quote! {
            pub async fn op(&self) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> {
                unimplemented!()
            }
        };
        for block in [
            quote!(impl Leg { #door }),
            quote!(impl<B, C> Leg<B, C> { #door }),
            quote!(impl<'a, B> Leg<'a, B> { #door }),
            quote!(impl<B> Trait for Leg<B> { #door }),
        ] {
            assert!(!reads(quote!(Contract), block.clone()), "{block}");
        }
    }

    /// A door is a `pub async fn` handing back a `Result` with something open at
    /// its end in it; it takes what its end answered, a server or capability it
    /// is generic over, or a value of its own its `where` says it builds what
    /// crosses from; it names its end as the block does, and is in every build.
    #[test]
    fn a_door_that_does_not_say_what_is_answered_is_refused() {
        for door in [
            quote! { pub fn op(&self) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> { unimplemented!() } },
            quote! { pub async fn op(&self) -> Untrusted<Rep, <B as Receives<Rep>>::Open, B> { unimplemented!() } },
            quote! { pub async fn op(&self) -> Result<Rep, Error> { unimplemented!() } },
            quote! { pub async fn op(&self, raw: RecordName) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> { unimplemented!() } },
            quote! {
                pub async fn op(&self, raw: RecordName) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error>
                where B: Sends<Built>
                { unimplemented!() }
            },
            quote! { pub async fn op<E>(&self, x: Exposed<X, (), E>) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> { unimplemented!() } },
            quote! { pub async fn op(&self, x: Exposed<(), (), B>) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> { unimplemented!() } },
            quote! { pub async fn op(&self) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, ()> { unimplemented!() } },
            quote! { pub async fn op(&self, x: Exposed<Part<Self>, (), B>) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> { unimplemented!() } },
            quote! {
                #[cfg(feature = "x")]
                pub async fn op(&self) -> Result<Untrusted<Rep, <B as Receives<Rep>>::Open, B>, Error> { unimplemented!() }
            },
        ] {
            assert!(!reads(quote!(Contract), block(door.clone())), "{door}");
        }
    }
}
