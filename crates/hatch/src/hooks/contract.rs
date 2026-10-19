//! The hooks' contract, rendered from the bodies the hatch speaks them in:
//! `hooks.openapi.yaml` is this rendering, and the test below keeps it so.
//! After a change here or to the bodies, write the file again with
//!
//!   ENCLAVID_WRITE_CONTRACT=1 cargo test -p enclavid-hatch the_contract_file
//!
//! — this test alone: the others read the file it writes.

use utoipa::OpenApi;

use super::{AuthorizeAnswer, AuthorizeBody, LimitsAnswer, LimitsBody, RateLimitedAnswer};

/// Who a request to the consumer API is from.
///
/// Asked for every request to the consumer API — a creation, a read of a
/// session, a pull of its disclosures — with the request's credential and its
/// operation, and nothing else.
///
/// Any answer but these three — another status, a body that is not one below,
/// no answer within the hatch's wait — fails the request.
#[utoipa::path(
    post,
    path = "/v1/authorize",
    operation_id = "authorize",
    request_body(content = AuthorizeBody, examples(
        ("creation" = (value = json!({
            "authorization_header": "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.e30.c2ln",
            "operation": "session-create",
        }))),
    )),
    responses(
        (status = 200, description = "The credential holds for the operation, and names this principal.",
            body = AuthorizeAnswer, examples(
                ("consumer" = (value = json!({ "principal": "org-1" }))),
            )),
        (status = 401, description = "The credential is missing, malformed or refused."),
        (status = 403, description = "The credential holds, but not for this operation."),
    ),
)]
#[allow(dead_code)]
fn authorize() {}

/// What a consumer may do.
///
/// Asked at every creation of a session — and every warmup the consumer asks
/// for, which spends what a creation does — after the authorization, with the
/// principal it named, and nothing else. An applicant's preparing of a session
/// asks nothing. Each ask is a creation asked for, whether or not it goes on to
/// be made: a hook that keeps a rate counts them, and refuses one past it. The
/// hatch counts nothing. Without the authorization hook every ask names no
/// principal, so a rate the hook keeps is one shared by every caller.
///
/// The terms are the new session's, held each to the fleet's own ceiling and
/// kept for the session's life, whatever this hook answers later.
///
/// Any answer but these two, or none within the hatch's wait, fails the
/// creation.
#[utoipa::path(
    post,
    path = "/v1/limits",
    operation_id = "limits",
    request_body(content = LimitsBody, examples(
        ("consumer" = (value = json!({ "principal": "org-1" }))),
    )),
    responses(
        (status = 200, description = "The creation may go on, its session held to these terms.",
            body = LimitsAnswer, examples(
            ("limited" = (value = json!({
                "terms": {
                    "components_bytes": 104857600,
                    "cwasm_bytes": 268435456,
                    "session_ttl_secs": 86400,
                    "pull_deadline_secs": 60,
                },
            }))),
            ("unlimited" = (value = json!({}))),
        )),
        (status = 429, description = "The consumer has created sessions as often as it may for now.",
            body = RateLimitedAnswer, examples(
            ("past its rate" = (value = json!({ "retry_after_secs": 20 }))),
        )),
    ),
)]
#[allow(dead_code)]
fn limits() {}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Enclavid hatch hooks",
        version = "1",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
        description = "What the hatch asks the operator: who a request to the consumer API is \
from, and what a consumer may do.\n\n\
Each hook is switched on by a launch setting of the hatch naming the vsock port it reaches the \
hook on — `authorize-hook-port`, `limits-hook-port` — and a hook not switched on is never asked. \
Without the authorization hook every request is let through and every caller is the same one, \
with no principal; without the limits hook a consumer may create sessions as often as it asks, \
and its sessions are held to the fleet's own terms. The hatch keeps nothing of what a hook \
answers: a rate is the limits hook's to count.\n\n\
The hatch reaches a hook through a relay on the host, which takes calls from the hatch alone and \
carries them to wherever the hook listens — localhost, say. So a hook is plain HTTP and JSON, in \
any language, and knows nothing of vsock; no other guest reaches it, but whatever on the host \
reaches the address it listens at reaches it too, which is the operator's to keep. The hatch \
reads at most 16 KiB of an answer.\n\n\
What a hook answers is the operator's word, and it decides only what the operator decides \
anyway: who may use the service, and how much of it. It is never told which session a request \
names, and nothing it answers reaches an applicant or the policy.\n\n\
Rendered from the hatch's own types (crates/hatch/src/hooks.rs), whose tests keep this file \
the rendering: change those, not this.",
    ),
    servers((url = "/")),
    // No scheme: what reaches a hook is the relay, which takes calls from the
    // hatch alone.
    security(()),
    paths(authorize, limits)
)]
struct Contract;

/// The contract file is what the hatch's types render: a body changed here
/// changes the contract, and a contract edited by hand fails here.
#[test]
fn the_contract_file_is_this_rendering() {
    let rendered = Contract::openapi().to_yaml().unwrap();
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/hooks.openapi.yaml");
    if std::env::var_os("ENCLAVID_WRITE_CONTRACT").is_some() {
        std::fs::write(file, &rendered).unwrap();
    }
    assert!(
        std::fs::read_to_string(file).unwrap() == rendered,
        "hooks.openapi.yaml is not what the hatch's types render: \
         ENCLAVID_WRITE_CONTRACT=1 cargo test -p enclavid-hatch the_contract_file"
    );
}
