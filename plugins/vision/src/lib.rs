//! `enclavid:vision` — the face geometry the plugins that read a face share:
//! types alone. The pictures they read a face in are the host's `image`s,
//! which the platform decodes; this plugin holds no pixels and runs nothing.

wit_bindgen::generate!({
    path: "wit",
    world: "enclavid:vision/vision@0.1.0",
    generate_all,
});
