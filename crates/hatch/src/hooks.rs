//! The operator's hooks, as `hooks.openapi.yaml` — rendered from the bodies
//! below — describes them: who a request to the consumer API is from
//! (`/v1/authorize`), and what a consumer may do (`/v1/limits`).
//!
//! Each is reached at a port of the host the launch names, switched on by
//! naming it: a hook the launch names no port for is never asked. A hook is
//! plain HTTP and JSON; the relay in front of it on the host takes calls from
//! this guest alone, so a hook knows nothing of vsock and no other guest
//! reaches it. Whatever on the host reaches the address the hook listens at
//! reaches the hook too: that is the operator's to keep.
//!
//! What a hook answers is the operator's word. It is held to the contract's
//! shapes and bounds here — a principal of 1 to 256 characters, terms and waits
//! above zero, no field the contract does not name, an answer of
//! [`MAX_ANSWER_BYTES`] at most — and anything else is no answer at all.
//!
//! The hatch keeps nothing of what a hook says: how often a consumer has
//! created a session is the limits hook's to count, and its to refuse.

use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};

use hatch_rpc::{ClientOperation, SessionTerms};

/// The longest principal a hook may name, in characters, as the contract's
/// JSON Schema counts them. A principal is kept with every session its
/// consumer creates.
pub const MAX_PRINCIPAL_CHARS: usize = 256;

/// The most of a hook's answer that is read. Both answers fit in a few hundred
/// bytes; one past this is not one of them.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The hooks this launch switched on, and how long each answer may take.
pub struct Hooks {
    authorize: Option<String>,
    limits: Option<String>,
    deadline: Duration,
}

/// Why a hook gave no answer the hatch can act on.
#[derive(Debug)]
pub enum HookError {
    /// It could not be reached, or did not answer within the deadline.
    Unreachable,
    /// It answered with a status the contract does not give.
    Status(StatusCode),
    /// It answered with a body that is not the contract's.
    Body,
}

impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookError::Unreachable => f.write_str("the hook did not answer"),
            HookError::Status(s) => write!(f, "the hook answered {s}"),
            HookError::Body => f.write_str("the hook's answer is not the contract's"),
        }
    }
}

/// What the authorization hook said of a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Authorization {
    /// It is from this principal.
    Principal(String),
    /// Its credential is missing, malformed or refused.
    Unauthenticated,
    /// Its credential holds, but not for its operation.
    Denied,
}

/// What the limits hook said of a creation.
#[derive(Debug, PartialEq, Eq)]
pub enum Limits {
    /// It may go on, its session held to these terms.
    Terms(SessionTerms),
    /// Its consumer has created sessions as often as it may for now: not
    /// another for this many seconds.
    RateLimited { retry_after_secs: u32 },
}

// The contract's bodies, as JSON. hooks.openapi.yaml is rendered from these
// (`contract`): what each says of itself here is what the hooks' implementers
// read there.

#[cfg(test)]
mod contract;

/// `session-create` is a creation, and a warmup of a session, which spends
/// what a creation does; `session-read` a read of a session; `data-read` a
/// pull of its disclosures.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
enum Operation {
    SessionCreate,
    SessionRead,
    DataRead,
}

impl From<ClientOperation> for Operation {
    fn from(op: ClientOperation) -> Self {
        match op {
            ClientOperation::SessionCreate => Operation::SessionCreate,
            ClientOperation::SessionRead => Operation::SessionRead,
            ClientOperation::DataRead => Operation::DataRead,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(utoipa::ToSchema), schema(as = AuthorizeRequest))]
#[serde(deny_unknown_fields)]
struct AuthorizeBody {
    /// The request's `Authorization` header, verbatim — empty where it has none.
    authorization_header: String,
    operation: Operation,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(utoipa::ToSchema), schema(as = AuthorizeResponse))]
#[serde(deny_unknown_fields)]
struct AuthorizeAnswer {
    /// Who the request is from: the consumer, as the operator names it. Every
    /// session keeps the principal that created it, and only that principal
    /// reads it.
    #[cfg_attr(test, schema(min_length = 1, max_length = 256))]
    principal: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(utoipa::ToSchema), schema(as = LimitsRequest))]
#[serde(deny_unknown_fields)]
struct LimitsBody {
    /// The principal the authorization named — `null` where the authorization
    /// hook is off.
    #[cfg_attr(test, schema(required, max_length = 256))]
    principal: Option<String>,
}

/// The creation may go on. Anything left out is not limited by the hook: the
/// fleet's own term.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(utoipa::ToSchema), schema(as = Limits))]
#[serde(deny_unknown_fields)]
struct LimitsAnswer {
    /// The terms its new session is held to.
    #[serde(default)]
    terms: TermsBody,
}

/// The consumer has created sessions as often as the hook lets it for now.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(utoipa::ToSchema), schema(as = RateLimited))]
#[serde(deny_unknown_fields)]
struct RateLimitedAnswer {
    /// How long until it may create one again, in seconds; the consumer is
    /// told the same, as `Retry-After`.
    // A 32-bit wait, which the contract's signed formats hold only as int64.
    #[cfg_attr(test, schema(value_type = u64, minimum = 1, maximum = 4294967295_u64))]
    retry_after_secs: NonZeroU32,
}

/// Each held to the fleet's own ceiling; one left out is the fleet's own.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(utoipa::ToSchema), schema(as = SessionTerms))]
#[serde(deny_unknown_fields)]
struct TermsBody {
    /// The policy and its plugins together, in bytes.
    #[serde(default)]
    #[cfg_attr(test, schema(value_type = u64, required = false, minimum = 1))]
    components_bytes: Option<NonZeroU64>,
    /// The composition compiled, in bytes.
    #[serde(default)]
    #[cfg_attr(test, schema(value_type = u64, required = false, minimum = 1))]
    cwasm_bytes: Option<NonZeroU64>,
    /// How long the session lives, in seconds.
    #[serde(default)]
    #[cfg_attr(test, schema(value_type = u64, required = false, minimum = 1))]
    session_ttl_secs: Option<NonZeroU64>,
    /// How long one pull from a registry may take, in seconds.
    #[serde(default)]
    #[cfg_attr(test, schema(value_type = u64, required = false, minimum = 1))]
    pull_deadline_secs: Option<NonZeroU64>,
}

impl From<TermsBody> for SessionTerms {
    fn from(terms: TermsBody) -> Self {
        let get = |n: Option<NonZeroU64>| n.map(NonZeroU64::get);
        SessionTerms {
            components_bytes: get(terms.components_bytes),
            cwasm_bytes: get(terms.cwasm_bytes),
            session_ttl_secs: get(terms.session_ttl_secs),
            pull_deadline_secs: get(terms.pull_deadline_secs),
        }
    }
}

/// A hook's answer, read as the contract's body `T` or as none at all.
fn read<T: serde::de::DeserializeOwned>(answer: &[u8]) -> Result<T, HookError> {
    serde_json::from_slice(answer).map_err(|_| HookError::Body)
}

/// A principal as the contract bounds it.
fn principal(answer: AuthorizeAnswer) -> Result<String, HookError> {
    let shaped =
        !answer.principal.is_empty() && answer.principal.chars().count() <= MAX_PRINCIPAL_CHARS;
    shaped.then_some(answer.principal).ok_or(HookError::Body)
}

impl Hooks {
    /// The hooks at these addresses, `None` for one switched off, each given
    /// `deadline` to answer.
    pub fn new(authorize: Option<String>, limits: Option<String>, deadline: Duration) -> Self {
        Self {
            authorize,
            limits,
            deadline,
        }
    }

    /// Whether the authorization hook is switched on.
    pub fn authorizes(&self) -> bool {
        self.authorize.is_some()
    }

    /// Who a request is from, by the authorization hook — `None` where it is
    /// switched off, and every caller is the same one.
    pub async fn authorize(
        &self,
        authorization_header: &str,
        operation: ClientOperation,
    ) -> Result<Option<Authorization>, HookError> {
        let Some(addr) = &self.authorize else {
            return Ok(None);
        };
        let body = AuthorizeBody {
            authorization_header: authorization_header.to_owned(),
            operation: operation.into(),
        };
        let (status, answer) = post(addr, "/v1/authorize", &body, self.deadline).await?;
        Ok(Some(match status {
            StatusCode::OK => Authorization::Principal(principal(read(&answer)?)?),
            StatusCode::UNAUTHORIZED => Authorization::Unauthenticated,
            StatusCode::FORBIDDEN => Authorization::Denied,
            other => return Err(HookError::Status(other)),
        }))
    }

    /// What a creation by `principal` may do, by the limits hook — nothing
    /// limited where it is switched off. Every ask is a creation the hook may
    /// count.
    pub async fn limits(&self, principal: Option<&str>) -> Result<Limits, HookError> {
        let Some(addr) = &self.limits else {
            return Ok(Limits::Terms(SessionTerms::default()));
        };
        let body = LimitsBody {
            principal: principal.map(str::to_owned),
        };
        match post(addr, "/v1/limits", &body, self.deadline).await? {
            (StatusCode::OK, answer) => {
                let answer: LimitsAnswer = read(&answer)?;
                Ok(Limits::Terms(answer.terms.into()))
            }
            (StatusCode::TOO_MANY_REQUESTS, answer) => {
                let answer: RateLimitedAnswer = read(&answer)?;
                Ok(Limits::RateLimited {
                    retry_after_secs: answer.retry_after_secs.get(),
                })
            }
            (other, _) => Err(HookError::Status(other)),
        }
    }
}

/// POST `body` as JSON to `path` of the hook at `addr`, on a connection of its
/// own, and read its status and at most [`MAX_ANSWER_BYTES`] of its answer —
/// all of it within `deadline`.
async fn post<B: Serialize>(
    addr: &str,
    path: &str,
    body: &B,
    deadline: Duration,
) -> Result<(StatusCode, Bytes), HookError> {
    let json = serde_json::to_vec(body).map_err(|_| HookError::Body)?;
    let exchange = async {
        let stream = fleet_transport::dial(addr)
            .await
            .map_err(|_| HookError::Unreachable)?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| HookError::Unreachable)?;
        tokio::spawn(conn);
        let request = Request::post(path)
            .header(hyper::header::HOST, "hook")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(|_| HookError::Body)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| HookError::Unreachable)?;
        let status = response.status();
        let answer = Limited::new(response.into_body(), MAX_ANSWER_BYTES)
            .collect()
            .await
            .map_err(|_| HookError::Body)?
            .to_bytes();
        Ok((status, answer))
    };
    tokio::time::timeout(deadline, exchange)
        .await
        .map_err(|_| HookError::Unreachable)?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract, as the hooks' implementers read it. Its examples are
    /// written by hand (`contract`), so they are held to the types here.
    fn contract() -> serde_yaml::Value {
        serde_yaml::from_str(include_str!("../hooks.openapi.yaml")).unwrap()
    }

    /// The contract's example `name` of `path`'s request or a response.
    fn example(path: &str, at: &[&str], name: &str) -> serde_json::Value {
        let mut node = &contract()["paths"][path]["post"];
        for key in at {
            node = &node[*key];
        }
        let value = &node["content"]["application/json"]["examples"][name]["value"];
        assert!(!value.is_null(), "{path} {at:?} has no example {name}");
        serde_json::to_value(value).unwrap()
    }

    /// What the contract shows a hook asked and answering is what this side
    /// writes and reads — every example, field for field.
    #[test]
    fn the_contracts_examples_are_what_the_hatch_speaks() {
        let asked: AuthorizeBody =
            serde_json::from_value(example("/v1/authorize", &["requestBody"], "creation")).unwrap();
        assert_eq!(asked.operation, Operation::SessionCreate);
        assert_eq!(
            serde_json::to_value(&asked).unwrap(),
            example("/v1/authorize", &["requestBody"], "creation")
        );

        let answered: AuthorizeAnswer =
            serde_json::from_value(example("/v1/authorize", &["responses", "200"], "consumer"))
                .unwrap();
        assert_eq!(principal(answered).unwrap(), "org-1");

        let asked: LimitsBody =
            serde_json::from_value(example("/v1/limits", &["requestBody"], "consumer")).unwrap();
        assert_eq!(asked.principal.as_deref(), Some("org-1"));

        let terms: SessionTerms = serde_json::from_value::<LimitsAnswer>(example(
            "/v1/limits",
            &["responses", "200"],
            "limited",
        ))
        .unwrap()
        .terms
        .into();
        assert_eq!(terms.components_bytes, Some(104_857_600));
        assert_eq!(terms.session_ttl_secs, Some(86_400));

        let unlimited: SessionTerms = serde_json::from_value::<LimitsAnswer>(example(
            "/v1/limits",
            &["responses", "200"],
            "unlimited",
        ))
        .unwrap()
        .terms
        .into();
        assert_eq!(unlimited, SessionTerms::default());

        let past: RateLimitedAnswer = serde_json::from_value(example(
            "/v1/limits",
            &["responses", "429"],
            "past its rate",
        ))
        .unwrap();
        assert_eq!(past.retry_after_secs.get(), 20);
    }

    /// An answer outside the contract is no answer.
    #[test]
    fn an_answer_outside_the_contract_is_refused() {
        for body in [
            r#"{"principal": ""}"#,
            r#"{"principal": 7}"#,
            r#"{"principal": "a", "role": "admin"}"#,
        ] {
            let parsed = serde_json::from_str::<AuthorizeAnswer>(body)
                .map_err(|_| HookError::Body)
                .and_then(principal);
            assert!(parsed.is_err(), "{body}");
        }
        let named = |p: String| {
            principal(serde_json::from_value(serde_json::json!({ "principal": p })).unwrap())
        };
        assert!(named("a".repeat(MAX_PRINCIPAL_CHARS + 1)).is_err());
        // Characters, as the contract's JSON Schema counts them: as many in a
        // script of more bytes each stand.
        assert!(named("ж".repeat(MAX_PRINCIPAL_CHARS)).is_ok());
        assert!(named("ж".repeat(MAX_PRINCIPAL_CHARS + 1)).is_err());

        for body in [
            r#"{"sessions": {"count": 1, "period_secs": 60}}"#,
            r#"{"terms": {"cwasm_bytes": 0}}"#,
            r#"{"terms": {"round_fuel": 1}}"#,
            r#"{"rate": 1}"#,
        ] {
            assert!(
                serde_json::from_str::<LimitsAnswer>(body).is_err(),
                "{body}"
            );
        }
        for body in [
            r#"{"retry_after_secs": 0}"#,
            r#"{}"#,
            r#"{"retry_after_secs": 5, "why": "busy"}"#,
        ] {
            assert!(
                serde_json::from_str::<RateLimitedAnswer>(body).is_err(),
                "{body}"
            );
        }
    }

    /// A hook served on a loopback port: authorizes `Bearer good`, refuses
    /// `Bearer forbidden`, and answers every other with 401; gives `org-1`'s
    /// sessions a day to live, and refuses `org-2` a creation for 20 s.
    async fn hook() -> String {
        use axum::http::StatusCode as S;
        use axum::routing::post;
        use axum::{Json, Router};
        let app = Router::new()
            .route(
                "/v1/authorize",
                post(|Json(body): Json<AuthorizeBody>| async move {
                    match body.authorization_header.as_str() {
                        "Bearer good" => Ok(Json(serde_json::json!({ "principal": "org-1" }))),
                        "Bearer forbidden" => Err(S::FORBIDDEN),
                        _ => Err(S::UNAUTHORIZED),
                    }
                }),
            )
            .route(
                "/v1/limits",
                post(|Json(body): Json<LimitsBody>| async move {
                    match body.principal.as_deref() {
                        Some("org-2") => (
                            S::TOO_MANY_REQUESTS,
                            Json(serde_json::json!({ "retry_after_secs": 20 })),
                        ),
                        _ => (
                            S::OK,
                            Json(serde_json::json!({ "terms": { "session_ttl_secs": 86400 } })),
                        ),
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    #[tokio::test]
    async fn a_hook_is_asked_and_its_answer_read() {
        let addr = hook().await;
        let hooks = Hooks::new(Some(addr.clone()), Some(addr), Duration::from_secs(5));
        let ask = |h: &'static str| hooks.authorize(h, ClientOperation::SessionCreate);
        assert_eq!(
            ask("Bearer good").await.unwrap(),
            Some(Authorization::Principal("org-1".into()))
        );
        assert_eq!(
            ask("Bearer forbidden").await.unwrap(),
            Some(Authorization::Denied)
        );
        assert_eq!(ask("").await.unwrap(), Some(Authorization::Unauthenticated));
        assert_eq!(
            hooks.limits(Some("org-1")).await.unwrap(),
            Limits::Terms(SessionTerms {
                session_ttl_secs: Some(86400),
                ..SessionTerms::default()
            })
        );
        assert_eq!(
            hooks.limits(Some("org-2")).await.unwrap(),
            Limits::RateLimited {
                retry_after_secs: 20
            }
        );
    }

    /// A hook switched off is never asked: every caller is let through as one,
    /// and nothing is limited.
    #[tokio::test]
    async fn a_hook_switched_off_is_not_asked() {
        let hooks = Hooks::new(None, None, Duration::from_secs(5));
        assert!(!hooks.authorizes());
        assert_eq!(
            hooks
                .authorize("Bearer anything", ClientOperation::SessionCreate)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            hooks.limits(None).await.unwrap(),
            Limits::Terms(SessionTerms::default())
        );
    }

    /// A hook that is not there is no answer, within the deadline.
    #[tokio::test]
    async fn a_hook_not_there_is_no_answer() {
        let gone = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().to_string()
        };
        let hooks = Hooks::new(Some(gone), None, Duration::from_secs(5));
        assert!(matches!(
            hooks.authorize("", ClientOperation::SessionRead).await,
            Err(HookError::Unreachable)
        ));
    }
}
