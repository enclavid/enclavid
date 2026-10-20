//! `boundary!` — one end of a boundary, declared.

use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::ext::IdentExt;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Expr, ExprLit, Ident, Lit, Meta, Path, PathSegment, Result, Token, Type,
    Visibility, braced, bracketed, parenthesized,
};

pub(crate) fn expand(input: TokenStream) -> Result<TokenStream> {
    let decl: Decl = syn::parse2(input)?;
    decl.generate()
}

struct Decl {
    attrs: Vec<Attribute>,
    vis: Visibility,
    name: Ident,
    calls: Vec<Path>,
    serves: Vec<Path>,
    observer: Option<Ident>,
    blocks: Vec<Block>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Dir {
    Out,
    In,
}

struct Block {
    dir: Dir,
    scope: Vec<Type>,
    entries: Vec<Entry>,
}

struct Entry {
    docs: String,
    target: Target,
    kind: Option<Path>,
}

enum Target {
    Every(Token![_]),
    One(Box<Type>),
}

/// A type or path as one comparable string.
fn key(t: &impl ToTokens) -> String {
    t.to_token_stream().to_string().replace(' ', "")
}

/// The `///` lines above an item, joined; anything else is refused, so a reason
/// is written out where it is read and never dropped on the way.
fn docs_of(attrs: &[Attribute]) -> Result<String> {
    let mut lines = Vec::new();
    for attr in attrs {
        let text = match &attr.meta {
            Meta::NameValue(nv) if attr.path().is_ident("doc") => match &nv.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        };
        let Some(text) = text else {
            return Err(Error::new_spanned(
                attr,
                "only `///` comments go here, written out: they are this line's reason",
            ));
        };
        lines.push(text.trim().to_string());
    }
    Ok(lines.join(" ").trim().to_string())
}

impl Parse for Decl {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let vis: Visibility = input.parse()?;
        let name: Ident = input.parse()?;

        let header;
        braced!(header in input);
        let mut calls = Vec::new();
        let mut serves = Vec::new();
        let mut observer = None;
        while !header.is_empty() {
            let field: Ident = header.parse()?;
            header.parse::<Token![:]>()?;
            match field.to_string().as_str() {
                "calls" | "serves" => {
                    let list;
                    bracketed!(list in header);
                    let paths = list.parse_terminated(Path::parse_mod_style, Token![,])?;
                    let target = if field == "calls" {
                        &mut calls
                    } else {
                        &mut serves
                    };
                    target.extend(paths);
                }
                "observer" => observer = Some(header.parse()?),
                _ => {
                    return Err(Error::new(
                        field.span(),
                        "expected `calls`, `serves` or `observer`",
                    ));
                }
            }
            if header.is_empty() {
                break;
            }
            header.parse::<Token![,]>()?;
        }

        let mut blocks = Vec::new();
        while !input.is_empty() {
            let word = input.call(Ident::parse_any)?;
            let dir = match word.to_string().as_str() {
                "out" => Dir::Out,
                "in" => Dir::In,
                _ => return Err(Error::new(word.span(), "expected `out` or `in`")),
            };
            let scope;
            let parens = parenthesized!(scope in input);
            let scope: Vec<Type> = scope
                .parse_terminated(Type::parse, Token![,])?
                .into_iter()
                .collect();
            if scope.is_empty() {
                return Err(Error::new(
                    parens.span.join(),
                    "a block opens at least one concern: naming what is open is the whole \
                     undertaking, and a block that opens nothing answers everything unwritten",
                ));
            }
            let mut seen = Vec::new();
            for marker in &scope {
                let k = key(marker);
                if seen.contains(&k) {
                    return Err(Error::new_spanned(
                        marker,
                        format!("`{k}` is already open in this block"),
                    ));
                }
                seen.push(k);
            }
            let body;
            braced!(body in input);
            let entries = body.parse_terminated(Entry::parse, Token![,])?;
            blocks.push(Block {
                dir,
                scope,
                entries: entries.into_iter().collect(),
            });
        }

        Ok(Decl {
            attrs,
            vis,
            name,
            calls,
            serves,
            observer,
            blocks,
        })
    }
}

impl Parse for Entry {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let docs = docs_of(&attrs)?;
        let target = if input.peek(Token![_]) {
            Target::Every(input.parse()?)
        } else {
            Target::One(Box::new(input.parse()?))
        };
        let kind = if input.peek(Token![:]) && !input.peek(Token![::]) {
            input.parse::<Token![:]>()?;
            Some(input.parse::<Path>()?)
        } else {
            None
        };
        match (&kind, docs.is_empty()) {
            (Some(kind), true) => {
                return Err(Error::new_spanned(
                    kind,
                    "an answer needs its reason: the `///` lines above it",
                ));
            }
            (None, false) => {
                return Err(Error::new_spanned(
                    &attrs[0],
                    "a `///` here is a reason, and this line answers nothing",
                ));
            }
            _ => {}
        }
        Ok(Entry { docs, target, kind })
    }
}

/// One answer: the marker it answers, the kind, its reason, and whether `_`
/// gave it for every type in its block.
#[derive(Clone)]
struct Answer {
    marker: Path,
    marker_key: String,
    kind: Path,
    docs: String,
    every_type: bool,
}

/// One type crossing this end, in one direction.
struct Crossing {
    dir: Dir,
    ty: Type,
    opens: Vec<Type>,
    answers: Vec<Answer>,
}

fn answer(kind: &Path, docs: &str, scope_keys: &[String], every_type: bool) -> Result<Answer> {
    if kind.segments.len() < 2 {
        return Err(Error::new_spanned(
            kind,
            "an answer is `Marker::Kind`, e.g. `AuthN::Identified`",
        ));
    }
    let marker = Path {
        leading_colon: kind.leading_colon,
        segments: kind
            .segments
            .iter()
            .take(kind.segments.len() - 1)
            .cloned()
            .collect(),
    };
    let marker_key = key(&marker);
    if !scope_keys.contains(&marker_key) {
        return Err(Error::new_spanned(
            kind,
            format!("this block does not open `{marker_key}`, so there is nothing to answer"),
        ));
    }
    Ok(Answer {
        marker,
        marker_key,
        kind: kind.clone(),
        docs: docs.to_string(),
        every_type,
    })
}

fn with_suffix(path: &Path, suffix: &str) -> Path {
    let mut path = path.clone();
    if let Some(last) = path.segments.last_mut() {
        let ident = format_ident!("{}{}", last.ident, suffix, span = last.ident.span());
        *last = PathSegment::from(ident);
    }
    path
}

impl Decl {
    fn generate(&self) -> Result<TokenStream> {
        let name = &self.name;
        let vis = &self.vis;

        let mut crossings: Vec<Crossing> = Vec::new();
        let mut index: BTreeMap<(Dir, String), (usize, usize)> = BTreeMap::new();
        let mut checks = Vec::new();
        let mut directions = Vec::new();

        for (b, block) in self.blocks.iter().enumerate() {
            let scope_keys: Vec<String> = block.scope.iter().map(key).collect();
            let mut every: Vec<Answer> = Vec::new();
            for entry in &block.entries {
                if let Target::Every(us) = &entry.target {
                    let kind = entry.kind.as_ref().ok_or_else(|| {
                        Error::new(
                            us.span(),
                            "`_` stands for every type in this block, so it needs an answer: `_: Marker::Kind`",
                        )
                    })?;
                    let a = answer(kind, &entry.docs, &scope_keys, true)?;
                    if every.iter().any(|x| x.marker_key == a.marker_key) {
                        return Err(Error::new_spanned(
                            kind,
                            format!(
                                "`{}` is already answered for every type in this block",
                                a.marker_key
                            ),
                        ));
                    }
                    every.push(a);
                }
            }
            checks.extend(every.iter().cloned());
            let concern = match block.dir {
                Dir::In => quote!(::enclavid_boundary::InboundConcern),
                Dir::Out => quote!(::enclavid_boundary::OutboundConcern),
            };
            directions.extend(block.scope.iter().map(|marker| {
                quote_spanned! {marker.span()=>
                    const _: () = {
                        const fn opens<M: #concern>() {}
                        opens::<#marker>()
                    };
                }
            }));

            let mut listed = false;
            for entry in &block.entries {
                let Target::One(ty) = &entry.target else {
                    continue;
                };
                listed = true;
                let k = (block.dir, key(ty));
                let at = match index.get(&k) {
                    Some(&(at, in_block)) if in_block == b => at,
                    Some(_) => {
                        return Err(Error::new_spanned(
                            ty,
                            "this type already crosses this end in this direction, in another block",
                        ));
                    }
                    None => {
                        crossings.push(Crossing {
                            dir: block.dir,
                            ty: (**ty).clone(),
                            opens: block.scope.clone(),
                            answers: every.clone(),
                        });
                        index.insert(k, (crossings.len() - 1, b));
                        crossings.len() - 1
                    }
                };
                if let Some(kind) = &entry.kind {
                    let a = answer(kind, &entry.docs, &scope_keys, false)?;
                    if crossings[at]
                        .answers
                        .iter()
                        .any(|x| x.marker_key == a.marker_key)
                    {
                        return Err(Error::new_spanned(
                            kind,
                            format!("`{}` is already answered for this type here", a.marker_key),
                        ));
                    }
                    checks.push(a.clone());
                    crossings[at].answers.push(a);
                }
            }
            if !listed {
                return Err(Error::new(
                    name.span(),
                    "a block lists at least one type that crosses",
                ));
            }
        }

        let impls = crossings.iter().map(|c| {
            let ty = &c.ty;
            let left = c
                .opens
                .iter()
                .filter(|o| !c.answers.iter().any(|a| a.marker_key == key(*o)));
            let relation = match c.dir {
                Dir::Out => quote!(::enclavid_boundary::Sends),
                Dir::In => quote!(::enclavid_boundary::Receives),
            };
            quote! {
                impl #relation<#ty> for #name {
                    type Open = ( #( #left, )* );
                }
            }
        });

        let kind_checks = checks.iter().map(|a| {
            let marker = &a.marker;
            let kind = &a.kind;
            quote_spanned! {kind.span()=>
                const _: ::enclavid_boundary::Kind<#marker, ::enclavid_boundary::Argued> = #kind;
            }
        });

        let protocols = self
            .calls
            .iter()
            .map(|p| with_suffix(p, "Calls"))
            .chain(self.serves.iter().map(|p| with_suffix(p, "Serves")))
            .map(|t| quote!(impl #t for #name {}));

        let data = self.data(&crossings)?;
        let attrs = &self.attrs;

        Ok(quote! {
            #( #attrs )*
            #vis struct #name;

            impl ::enclavid_boundary::Boundary for #name {}

            impl #name {
                /// Open `value` to leave this end, with what this declaration
                /// answers for its type already answered.
                #[allow(dead_code)]
                #vis fn expose<T>(
                    value: T,
                ) -> ::enclavid_boundary::Exposed<T, <Self as ::enclavid_boundary::Sends<T>>::Open, Self>
                where
                    Self: ::enclavid_boundary::Sends<T>,
                {
                    ::enclavid_boundary::outbound::<Self, T>(value)
                }

                /// Open the parts of a `W` to leave this end as a `W` does: the
                /// one way out is the work that builds the `W` from them.
                #[allow(dead_code)]
                #vis fn expose_as<W, T>(
                    value: T,
                ) -> ::enclavid_boundary::Parts<T, W, <Self as ::enclavid_boundary::Sends<W>>::Open, Self>
                where
                    Self: ::enclavid_boundary::Sends<W>,
                    <Self as ::enclavid_boundary::Sends<W>>::Open: ::enclavid_boundary::Open,
                {
                    ::enclavid_boundary::outbound_as::<Self, W, T>(value)
                }
            }

            #( #impls )*
            #( #directions )*
            #( #kind_checks )*
            #( #protocols )*
            #data
        })
    }

    /// The declaration as data, for the crate's own test build.
    fn data(&self, crossings: &[Crossing]) -> Result<TokenStream> {
        let name = &self.name;
        let name_str = name.to_string();
        let doc = docs_of(
            &self
                .attrs
                .iter()
                .filter(|a| a.path().is_ident("doc"))
                .cloned()
                .collect::<Vec<_>>(),
        )?;
        let observer = self
            .observer
            .as_ref()
            .map(|o| o.to_string())
            .unwrap_or_default();
        let calls = self.calls.iter().map(key);
        let serves = self.serves.iter().map(key);
        let rows = crossings.iter().map(|c| {
            let direction = match c.dir {
                Dir::Out => quote!(::enclavid_boundary::declaration::Direction::Out),
                Dir::In => quote!(::enclavid_boundary::declaration::Direction::In),
            };
            let ty = key(&c.ty);
            let opens = c.opens.iter().map(key);
            let left = c
                .opens
                .iter()
                .map(key)
                .filter(|o| !c.answers.iter().any(|a| &a.marker_key == o));
            let answers = c.answers.iter().map(|a| {
                let marker = &a.marker_key;
                let kind = a
                    .kind
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                let doc = &a.docs;
                let every_type = a.every_type;
                quote! {
                    ::enclavid_boundary::declaration::Answer {
                        marker: #marker,
                        kind: #kind,
                        doc: #doc,
                        every_type: #every_type,
                    }
                }
            });
            quote! {
                ::enclavid_boundary::declaration::Crossing {
                    direction: #direction,
                    ty: #ty,
                    opens: &[ #( #opens ),* ],
                    answers: &[ #( #answers ),* ],
                    left: &[ #( #left ),* ],
                }
            }
        });
        Ok(quote! {
            #[cfg(test)]
            impl #name {
                /// This declaration, as data.
                #[allow(dead_code)]
                pub const DECLARATION: ::enclavid_boundary::declaration::End = ::enclavid_boundary::declaration::End {
                    name: #name_str,
                    doc: #doc,
                    observer: #observer,
                    calls: &[ #( #calls ),* ],
                    serves: &[ #( #serves ),* ],
                    crossings: &[ #( #rows ),* ],
                };
            }
        })
    }
}

/// What `boundary!` refuses as it reads a declaration. Each case is the
/// well-formed declaration with one thing wrong; what the compiler refuses in
/// the code it writes — a marker of the other direction, a kind that is work or
/// a risk — is held by `enclavid-boundary`'s doctests.
#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream;
    use quote::quote;

    fn reads(input: TokenStream) -> bool {
        super::expand(input).is_ok()
    }

    #[test]
    fn a_well_formed_declaration_is_read() {
        assert!(reads(quote! {
            End { observer: Test }
            in (AuthN, Asserted) {
                #[doc = "fixture"] Req: AuthN::Indifferent,
                Other,
            }
            out (AuthZ, Covert) {
                #[doc = "fixture"] _: AuthZ::NoSecret,
                #[doc = "fixture"] Rep: Covert::Bounded,
            }
        }));
    }

    #[test]
    fn a_block_that_opens_nothing_is_refused() {
        assert!(!reads(quote! { End { observer: Test } in () { Req } }));
    }

    #[test]
    fn a_concern_opened_twice_is_refused() {
        assert!(!reads(
            quote! { End { observer: Test } in (AuthN, AuthN) { Req } }
        ));
    }

    #[test]
    fn an_answer_without_its_reason_is_refused() {
        assert!(!reads(quote! {
            End { observer: Test } in (AuthN,) { Req: AuthN::Indifferent }
        }));
    }

    #[test]
    fn a_reason_on_a_line_that_answers_nothing_is_refused() {
        assert!(!reads(quote! {
            End { observer: Test } in (AuthN,) { #[doc = "fixture"] Req }
        }));
    }

    #[test]
    fn a_reason_not_written_out_is_refused() {
        assert!(!reads(quote! {
            End { observer: Test }
            in (AuthN,) { #[doc = concat!("fix", "ture")] Req: AuthN::Indifferent }
        }));
    }

    #[test]
    fn an_answer_given_twice_for_every_type_is_refused() {
        assert!(!reads(quote! {
            End { observer: Test }
            out (AuthZ,) {
                #[doc = "fixture"] _: AuthZ::NoSecret,
                #[doc = "fixture"] _: AuthZ::Scoped,
                Rep,
            }
        }));
    }

    #[test]
    fn an_answer_given_twice_for_one_type_is_refused() {
        assert!(!reads(quote! {
            End { observer: Test }
            in (AuthN,) {
                #[doc = "fixture"] Req: AuthN::Indifferent,
                #[doc = "fixture"] Req: AuthN::Identified,
            }
        }));
    }

    #[test]
    fn an_answer_to_a_concern_the_block_does_not_open_is_refused() {
        assert!(!reads(quote! {
            End { observer: Test } in (AuthN,) { #[doc = "fixture"] Req: AuthZ::Matched }
        }));
    }

    #[test]
    fn a_type_in_two_blocks_of_one_direction_is_refused() {
        assert!(!reads(quote! {
            End { observer: Test } in (AuthN,) { Req } in (Asserted,) { Req }
        }));
    }

    #[test]
    fn a_block_that_lists_no_type_is_refused() {
        assert!(!reads(quote! {
            End { observer: Test } out (AuthZ,) { #[doc = "fixture"] _: AuthZ::NoSecret }
        }));
    }

    #[test]
    fn every_type_without_an_answer_is_refused() {
        assert!(!reads(
            quote! { End { observer: Test } in (AuthN,) { _, Req } }
        ));
    }
}
