use std::env;

pub fn client_id() -> Option<String> {
    env::var("ENCLAVID_CLIENT_ID").ok()
}

pub fn client_secret() -> Option<String> {
    env::var("ENCLAVID_CLIENT_SECRET").ok()
}
