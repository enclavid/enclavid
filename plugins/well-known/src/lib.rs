//! `enclavid:well-known` — canonical KYC field labels, standard guides and
//! pre-baked captures. Drop-in helpers so policy authors don't hand-roll
//! text-refs for standard data shapes.
//!
//! Every ref this plugin hands back (localized label, icon) is minted by
//! the host, which a component cannot do for itself: a text is a case of
//! the `key` of this plugin's slot, `enclavid-ext:well-known/i18n`, which
//! its catalog has a text for, and an icon is one of the host's own, one
//! function each in `enclavid:host-icons/icons`. A field's key is the
//! policy's, minted from its own list, which the helpers take.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:well-known/well-known@0.1.0",
    generate_all,
});

mod disclosure_fields;
mod photo;
mod sets;
mod shapes;
mod video;
mod video_guides;

struct WellKnown;

export!(WellKnown);
