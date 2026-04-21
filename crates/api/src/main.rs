mod auth;
mod handlers;
mod input;
mod state;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::handlers::{get_status, post_init, post_input, post_report};
use crate::state::AppState;

#[tokio::main]
async fn main() {
    let policy_path = std::env::var("ENCLAVID_POLICY").expect("ENCLAVID_POLICY not set");
    let policy_bytes = std::fs::read(&policy_path).expect("failed to read policy");
    let app_state =
        Arc::new(AppState::init("/var/run/enclavid.sock", &policy_bytes).await);

    let app = Router::new()
        .route("/session/{id}/status", get(get_status))
        .route("/session/{id}/init", post(post_init))
        .route("/session/{id}/input", post(post_input))
        .route("/session/{id}/report", post(post_report))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind");

    println!("listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.expect("server error");
}
