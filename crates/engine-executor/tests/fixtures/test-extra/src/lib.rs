//! Minimal `enclavid:extra` plugin — one export, `tag::get()`, which is
//! `extra-tag`, one of this plugin's own texts. Used only by the hybrid
//! composition test: the policy imports it, it's linked at runtime on top
//! of a pre-fused (policy + well-known) core, and its texts come through
//! the slot its own catalog names.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:extra/plugin@0.1.0",
    generate_all,
});

use enclavid::extra::i18n::{Key, localized};
use enclavid::host::types::LocalizedRef;
use exports::enclavid::extra::tag::Guest;

struct Extra;

impl Guest for Extra {
    fn get() -> LocalizedRef {
        localized(Key::ExtraTag)
    }
}

export!(Extra);
