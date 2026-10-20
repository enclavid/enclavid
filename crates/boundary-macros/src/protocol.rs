//! `#[protocol]` — what a remoc contract asks of its two ends.

use std::collections::BTreeSet;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{
    Error, FnArg, GenericArgument, Ident, ItemTrait, Meta, Pat, Path, PathArguments, Result,
    ReturnType, TraitItem, Type,
};

struct Arg {
    name: Ident,
    ty: Type,
    /// For a remoc client handed over rather than a value: the door, generic
    /// over the server's end, that the server is given it in.
    door: Option<Path>,
}

struct Method {
    name: Ident,
    args: Vec<Arg>,
    ok: Type,
    err: Type,
}

/// `()` however it is spelled: parentheses and invisible groups around it are
/// still it. An alias of it is caught by the compiler instead (`NotUnit`).
fn is_unit(ty: &Type) -> bool {
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
fn refuse_unit(ty: &Type, what: &str) -> Result<()> {
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

fn result_types(output: &ReturnType) -> Result<(Type, Type)> {
    let ReturnType::Type(_, ty) = output else {
        return Err(Error::new_spanned(
            output,
            "a protocol method returns `Result<T, E>`",
        ));
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
    Err(Error::new_spanned(
        ty,
        "a protocol method returns `Result<T, E>`",
    ))
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
            let mut door = None;
            for attr in pt.attrs.iter().filter(|a| a.path().is_ident("capability")) {
                let Meta::List(_) = &attr.meta else {
                    return Err(Error::new_spanned(
                        attr,
                        "a capability reaches its server through a door, `#[capability(Door)]`, \
                         so that what the server sends back through it goes through its end's \
                         declaration too",
                    ));
                };
                door = Some(attr.parse_args::<Path>()?);
            }
            pt.attrs.retain(|a| !a.path().is_ident("capability"));
            let Pat::Ident(pat) = &*pt.pat else {
                return Err(Error::new_spanned(
                    &pt.pat,
                    "a protocol argument is a plain name",
                ));
            };
            if door.is_none() {
                refuse_unit(&pt.ty, "argument")?;
            }
            args.push(Arg {
                name: pat.ident.clone(),
                ty: (*pt.ty).clone(),
                door,
            });
        }
        let (ok, err) = result_types(&f.sig.output)?;
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
    let calls = format_ident!("{}Calls", name);
    let serves = format_ident!("{}Serves", name);
    let at = format_ident!("{}At", name);
    let adapter = format_ident!("{}Adapter", name);

    // What each end must declare, deduplicated by spelling.
    let mut calls_bounds = Vec::new();
    let mut serves_bounds = Vec::new();
    let mut seen_calls = BTreeSet::new();
    let mut seen_serves = BTreeSet::new();
    let push = |bounds: &mut Vec<TokenStream>, seen: &mut BTreeSet<String>, b: TokenStream| {
        if seen.insert(b.to_string()) {
            bounds.push(b);
        }
    };
    // Every type that crosses, once each, held to being a type of its own by the
    // compiler too — which sees through an alias of `()` that spelling cannot.
    let mut crossing = Vec::new();
    let mut seen_crossing = BTreeSet::new();
    for ty in methods.iter().flat_map(|m| {
        m.args
            .iter()
            .filter(|a| a.door.is_none())
            .map(|a| &a.ty)
            .chain([&m.ok, &m.err])
    }) {
        if seen_crossing.insert(quote!(#ty).to_string()) {
            // `()` alone has two impls, so naming one is ambiguous for it and for
            // nothing else. The helpers' names are ones a contract will not use:
            // the block shares the contract's scope, and a helper named like a
            // contract's type would stand in for it unseen.
            crossing.push(quote_spanned! {ty.span()=>
                const _: () = {
                    trait __NotUnit<A> {
                        fn check() {}
                    }
                    impl<T: ?Sized> __NotUnit<()> for T {}
                    struct __Unit;
                    impl __NotUnit<__Unit> for () {}
                    let _ = <#ty as __NotUnit<_>>::check;
                };
            });
        }
    }
    for m in &methods {
        for a in m.args.iter().filter(|a| a.door.is_none()) {
            let ty = &a.ty;
            push(
                &mut calls_bounds,
                &mut seen_calls,
                quote!(::enclavid_boundary::Sends<#ty>),
            );
            push(
                &mut serves_bounds,
                &mut seen_serves,
                quote!(::enclavid_boundary::Receives<#ty>),
            );
        }
        let ok = &m.ok;
        let err = &m.err;
        push(
            &mut calls_bounds,
            &mut seen_calls,
            quote!(::enclavid_boundary::Receives<#ok>),
        );
        push(
            &mut serves_bounds,
            &mut seen_serves,
            quote!(::enclavid_boundary::Sends<#ok>),
        );
        push(
            &mut calls_bounds,
            &mut seen_calls,
            quote!(::enclavid_boundary::Receives<#err, Open = ()>),
        );
        push(
            &mut serves_bounds,
            &mut seen_serves,
            quote!(::enclavid_boundary::Sends<#err, Open = ()>),
        );
    }

    let sig = |m: &Method| {
        let method = &m.name;
        let params = m.args.iter().map(|a| {
            let n = &a.name;
            let ty = &a.ty;
            match &a.door {
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
            match &a.door {
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

    Ok(quote! {
        #contract

        #( #crossing )*

        /// What an end that calls this protocol declares: every argument it
        /// sends, every answer and error it receives — the error answered in full.
        #vis trait #calls: ::enclavid_boundary::Boundary #( + #calls_bounds )* {}

        /// What an end that serves this protocol declares: every argument it
        /// receives, every answer and error it sends — the error answered in full.
        #vis trait #serves: ::enclavid_boundary::Boundary #( + #serves_bounds )* {}

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
    })
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
