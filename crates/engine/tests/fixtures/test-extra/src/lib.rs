//! Minimal `enclavid:extra` plugin — one export, `tag::get()`, which
//! resolves `extra_tag` from this plugin's own `i18n.json`. Used only by
//! the hybrid composition test: the policy imports it, it's linked at
//! runtime on top of a pre-fused (policy + well-known) core, and its
//! embedded import must route to its own catalog (strict).

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:extra/plugin@0.1.0",
    generate_all,
});

use enclavid::embedded::i18n::localized;
use exports::enclavid::extra::tag::Guest;

struct Extra;

impl Guest for Extra {
    fn get() -> String {
        localized("extra_tag")
    }
}

export!(Extra);
