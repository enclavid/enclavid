//! `#[protocol]` — what a remoc contract asks of the end that serves it, and the
//! contract as data.

use std::collections::BTreeSet;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{
    Error, FnArg, GenericArgument, Ident, ItemTrait, Meta, Pat, Path, PathArguments, Result,
    ReturnType, TraitItem, Type,
};

use crate::key;

struct Arg {
    name: Ident,
    ty: Type,
    /// For a remoc client handed over rather than a value: the door, generic
    /// over the server's end, that the server is given it in.
    capability: Option<Path>,
}

struct Method {
    name: Ident,
    args: Vec<Arg>,
    ok: Type,
    err: Type,
}

/// `()` however it is spelled: parentheses and invisible groups around it are
/// still it. An alias of it is caught by the compiler instead (`NotUnit`).
pub(crate) fn is_unit(ty: &Type) -> bool {
    match ty {
        Type::Tuple(t) => t.elems.is_empty(),
        Type::Paren(p) => is_unit(&p.elem),
        Type::Group(g) => is_unit(&g.elem),
        _ => false,
    }
}

/// An end's declaration answers for a type, not for a method, so a type that
/// crosses must be its own: `()` would be every unit reply, error or argument of
/// every protocol at once.
pub(crate) fn refuse_unit(ty: &Type, what: &str) -> Result<()> {
    if is_unit(ty) {
        return Err(Error::new_spanned(
            ty,
            format!(
                "a protocol {what} needs a type of its own: `()` is every unit {what} at \
                 once, and an end's declaration answers for a type, not for a method"
            ),
        ));
    }
    Ok(())
}

/// `ty`, held to being a type of its own by the compiler — which sees through an
/// alias of `()` that spelling cannot. `()` alone has two impls, so naming one is
/// ambiguous for it and for nothing else. The helpers' names are ones a contract
/// will not use: the block shares the contract's scope, and a helper named like a
/// contract's type would stand in for it unseen.
pub(crate) fn not_unit(ty: &Type) -> TokenStream {
    quote_spanned! {ty.span()=>
        const _: () = {
            trait __NotUnit<A> {
                fn check() {}
            }
            impl<T: ?Sized> __NotUnit<()> for T {}
            struct __Unit;
            impl __NotUnit<__Unit> for () {}
            let _ = <#ty as __NotUnit<_>>::check;
        };
    }
}

/// What a `what` — a protocol method, a door — returns, as `Result<T, E>`.
pub(crate) fn result_types(output: &ReturnType, what: &str) -> Result<(Type, Type)> {
    let shape = format!("a {what} returns `Result<T, E>`");
    let ReturnType::Type(_, ty) = output else {
        return Err(Error::new_spanned(output, shape));
    };
    if let Type::Path(p) = &**ty
        && let Some(last) = p.path.segments.last()
        && last.ident == "Result"
        && let PathArguments::AngleBracketed(a) = &last.arguments
    {
        let tys: Vec<&Type> = a
            .args
            .iter()
            .filter_map(|g| match g {
                GenericArgument::Type(t) => Some(t),
                _ => None,
            })
            .collect();
        if let [ok, err] = tys.as_slice() {
            return Ok(((*ok).clone(), (*err).clone()));
        }
    }
    Err(Error::new_spanned(ty, shape))
}

pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    if !attr.is_empty() {
        return Err(Error::new_spanned(attr, "`#[protocol]` takes no arguments"));
    }
    let mut contract: ItemTrait = syn::parse2(item)?;
    if !contract.generics.params.is_empty() || contract.generics.where_clause.is_some() {
        return Err(Error::new_spanned(
            &contract.generics,
            "a protocol with generics is not supported",
        ));
    }

    let mut methods = Vec::new();
    for item in &mut contract.items {
        let TraitItem::Fn(f) = item else {
            return Err(Error::new_spanned(item, "a protocol holds methods only"));
        };
        if f.sig.asyncness.is_none() {
            return Err(Error::new_spanned(
                &f.sig,
                "a protocol method is `async fn`",
            ));
        }
        let mut args = Vec::new();
        for input in f.sig.inputs.iter_mut() {
            let FnArg::Typed(pt) = input else { continue };
            let mut capability = None;
            for attr in pt.attrs.iter().filter(|a| a.path().is_ident("capability")) {
                let Meta::List(_) = &attr.meta else {
                    return Err(Error::new_spanned(
                        attr,
                        "a capability reaches its server through a door, `#[capability(Door)]`, \
                         so that what the server sends back through it goes through its end's \
                         declaration too",
                    ));
                };
                capability = Some(attr.parse_args::<Path>()?);
            }
            pt.attrs.retain(|a| !a.path().is_ident("capability"));
            let Pat::Ident(pat) = &*pt.pat else {
                return Err(Error::new_spanned(
                    &pt.pat,
                    "a protocol argument is a plain name",
                ));
            };
            if capability.is_none() {
                refuse_unit(&pt.ty, "argument")?;
            }
            args.push(Arg {
                name: pat.ident.clone(),
                ty: (*pt.ty).clone(),
                capability,
            });
        }
        let (ok, err) = result_types(&f.sig.output, "protocol method")?;
        refuse_unit(&ok, "reply")?;
        refuse_unit(&err, "error")?;
        methods.push(Method {
            name: f.sig.ident.clone(),
            args,
            ok,
            err,
        });
    }

    let name = &contract.ident;
    let vis = &contract.vis;
    let serves = format_ident!("{}Serves", name);
    let at = format_ident!("{}At", name);
    let adapter = format_ident!("{}Adapter", name);
    let wire = format_ident!("{}Wire", name);

    // What the serving end must declare, deduplicated by spelling.
    let mut serves_bounds = Vec::new();
    let mut seen_serves = BTreeSet::new();
    let mut push = |b: TokenStream| {
        if seen_serves.insert(b.to_string()) {
            serves_bounds.push(b);
        }
    };
    // Every type that crosses, once each, held to being a type of its own by the
    // compiler too.
    let mut crossing = Vec::new();
    let mut seen_crossing = BTreeSet::new();
    for ty in methods.iter().flat_map(|m| {
        m.args
            .iter()
            .filter(|a| a.capability.is_none())
            .map(|a| &a.ty)
            .chain([&m.ok, &m.err])
    }) {
        if seen_crossing.insert(quote!(#ty).to_string()) {
            crossing.push(not_unit(ty));
        }
    }
    for m in &methods {
        for a in m.args.iter().filter(|a| a.capability.is_none()) {
            let ty = &a.ty;
            push(quote!(::enclavid_boundary::Receives<#ty>));
        }
        let ok = &m.ok;
        let err = &m.err;
        push(quote!(::enclavid_boundary::Sends<#ok>));
        push(quote!(::enclavid_boundary::Sends<#err, Open = ()>));
    }

    let sig = |m: &Method| {
        let method = &m.name;
        let params = m.args.iter().map(|a| {
            let n = &a.name;
            let ty = &a.ty;
            match &a.capability {
                Some(door) => quote!(#n: #door<B>),
                None => {
                    quote!(#n: ::enclavid_boundary::Untrusted<#ty, <B as ::enclavid_boundary::Receives<#ty>>::Open, B>)
                }
            }
        });
        let err = &m.err;
        let ok = &m.ok;
        let ok = quote!(::enclavid_boundary::Exposed<#ok, (), B>);
        quote! {
            fn #method(&self, #( #params ),*)
                -> impl ::core::future::Future<Output = ::core::result::Result<#ok, #err>> + ::core::marker::Send
        }
    };

    let serve_methods = methods.iter().map(|m| {
        let s = sig(m);
        quote!(#s;)
    });

    let arc_methods = methods.iter().map(|m| {
        let s = sig(m);
        let method = &m.name;
        let names = m.args.iter().map(|a| &a.name);
        quote! {
            #s {
                (**self).#method(#( #names ),*)
            }
        }
    });

    let raw_methods = methods.iter().map(|m| {
        let method = &m.name;
        let params = m.args.iter().map(|a| {
            let n = &a.name;
            let ty = &a.ty;
            quote!(#n: #ty)
        });
        let wrapped = m.args.iter().map(|a| {
            let n = &a.name;
            let ty = &a.ty;
            match &a.capability {
                Some(door) => quote!(#door::<B>::from(#n)),
                None => quote!(::enclavid_boundary::inbound::<B, #ty>(#n)),
            }
        });
        let ok = &m.ok;
        let err = &m.err;
        quote! {
            async fn #method(&self, #( #params ),*) -> ::core::result::Result<#ok, #err> {
                let answer = self.0.#method(#( #wrapped ),*).await?;
                ::core::result::Result::Ok(answer.into_inner())
            }
        }
    });

    let adapter_doc = format!(
        " Serves a [`{at}`] as the raw contract, wrapping each argument as it\n \
         arrives at `B` and releasing each answer."
    );

    let wire_data = wire_data(name, &methods);

    Ok(quote! {
        #contract

        #( #crossing )*

        /// What an end that serves this protocol declares: every argument it
        /// receives, every answer and error it sends — the error answered in full.
        #vis trait #serves: ::enclavid_boundary::Boundary #( + #serves_bounds )* {
            /// This protocol, as data, for the declaration of an end that serves it.
            const PROTOCOL: ::enclavid_boundary::declaration::Protocol = #wire::PROTOCOL;
        }

        /// This protocol as its server sees it at end `B`: every argument arrives
        /// open on what `B`'s declaration left open, every answer leaves answered,
        /// an error leaves as it is — its declaration answered it in full.
        #vis trait #at<B: #serves> {
            #( #serve_methods )*
        }

        impl<T: #at<B>, B: #serves> #at<B> for ::std::sync::Arc<T> {
            #( #arc_methods )*
        }

        #[doc = #adapter_doc]
        #vis struct #adapter<T, B>(T, ::core::marker::PhantomData<fn() -> B>);

        impl<T, B> #adapter<T, B> {
            #vis fn new(service: T) -> Self {
                Self(service, ::core::marker::PhantomData)
            }
        }

        impl<T, B> #name for #adapter<T, B>
        where
            T: #at<B> + ::core::marker::Send + ::core::marker::Sync + 'static,
            B: #serves + 'static,
        {
            #( #raw_methods )*
        }

        #wire_data
    })
}

/// The contract `name` as data: each method and what crosses for it, one
/// constant a method, by its name — which the doors of a calling end are matched
/// to (`#[calls]`) — and the whole as `PROTOCOL`.
fn wire_data(name: &Ident, methods: &[Method]) -> TokenStream {
    let wire = format_ident!("{}Wire", name);
    let name = name.to_string();
    let doc = format!(" `{name}` as data: each method, and what crosses for it.");
    let consts = methods.iter().map(|m| {
        let ident = &m.name;
        let method = m.name.to_string();
        let args = m
            .args
            .iter()
            .filter(|a| a.capability.is_none())
            .map(|a| key(&a.ty));
        let reply = key(&m.ok);
        let error = key(&m.err);
        quote! {
            pub const #ident: ::enclavid_boundary::declaration::Method =
                ::enclavid_boundary::declaration::Method {
                    name: #method,
                    args: &[ #( #args ),* ],
                    reply: #reply,
                    error: #error,
                    door: ::core::option::Option::None,
                };
        }
    });
    let idents = methods.iter().map(|m| &m.name);
    quote! {
        #[doc = #doc]
        #[doc(hidden)]
        pub struct #wire;

        #[allow(non_upper_case_globals)]
        impl #wire {
            #( #consts )*

            pub const PROTOCOL: ::enclavid_boundary::declaration::Protocol =
                ::enclavid_boundary::declaration::Protocol {
                    name: #name,
                    methods: &[ #( Self::#idents ),* ],
                };
        }
    }
}

/// What `#[protocol]` refuses as it reads a contract. Each case is the
/// well-formed contract with one thing wrong; an alias of `()`, which only the
/// compiler can see through, is held by the `NotUnit` check it writes.
#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream;
    use quote::quote;

    fn reads(contract: TokenStream) -> bool {
        super::expand(quote!(), contract).is_ok()
    }

    #[test]
    fn a_well_formed_contract_is_read() {
        assert!(reads(quote! {
            pub trait Contract {
                async fn op(&self, req: Req, #[capability(Door)] back: Client) -> Result<Done, Error>;
            }
        }));
    }

    #[test]
    fn a_unit_reply_is_refused_however_it_is_spelled() {
        assert!(!reads(quote! {
            pub trait Contract { async fn op(&self, req: Req) -> Result<(), Error>; }
        }));
        assert!(!reads(quote! {
            pub trait Contract { async fn op(&self, req: Req) -> Result<(()), Error>; }
        }));
    }

    #[test]
    fn a_unit_error_is_refused() {
        assert!(!reads(quote! {
            pub trait Contract { async fn op(&self, req: Req) -> Result<Done, ()>; }
        }));
    }

    #[test]
    fn a_unit_argument_is_refused() {
        assert!(!reads(quote! {
            pub trait Contract { async fn op(&self, req: ()) -> Result<Done, Error>; }
        }));
    }

    #[test]
    fn a_capability_without_a_door_is_refused() {
        assert!(!reads(quote! {
            pub trait Contract {
                async fn op(&self, req: Req, #[capability] back: Client) -> Result<Done, Error>;
            }
        }));
    }
}
