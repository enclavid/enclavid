//! The tuning every test pushes, as JSON and as the values it spells.
//!
//! Small numbers, so a test that waits for a timeout waits milliseconds. One set
//! for the whole crate, so a fixture in one module and a constant in another
//! cannot drift apart — `crate::config::table`'s tests pin the two to each
//! other.

use std::time::Duration;

use super::table::{ListenerTuning, Tuning, UpstreamTuning};

pub const CONNECTIONS: usize = 256;
pub const PER_SOURCE: usize = 2;
pub const STREAMS: u32 = 8;
pub const HANDSHAKE: Duration = Duration::from_millis(200);
pub const HEADERS: Duration = Duration::from_secs(30);
pub const PING: Duration = Duration::from_secs(20);
pub const FIRST_REQUEST: Duration = Duration::from_millis(100);
pub const IDLE: Duration = Duration::from_secs(1);
pub const LIFETIME: Duration = Duration::from_secs(3);
pub const DRAIN: Duration = Duration::from_secs(150);
pub const BODY_PAUSE: Duration = Duration::from_secs(1);
pub const BODY: Duration = Duration::from_secs(5);

pub const REQUESTS_PER_MEMBER: usize = 16;
pub const MEMBER_WAIT: Duration = Duration::from_millis(200);
pub const ANSWER: Duration = Duration::from_millis(300);
pub const TRIES: usize = 3;
pub const COOLDOWN: Duration = Duration::from_millis(200);
pub const OPEN: Duration = Duration::from_millis(200);
pub const LEG_IDLE: Duration = Duration::from_millis(300);
pub const PARKED: usize = 256;

/// The `tuning` member of a push, for a fixture to place beside the rest.
pub const TUNING: &str = r#""tuning": {
  "listener": {
    "connections": 256, "connections_per_source": 2, "streams_per_connection": 8,
    "handshake_timeout_ms": 200, "header_timeout_ms": 30000, "ping_interval_ms": 20000,
    "first_request_timeout_ms": 100, "idle_timeout_ms": 1000, "lifetime_ms": 3000,
    "drain_timeout_ms": 150000, "request_body_pause_ms": 1000, "request_body_timeout_ms": 5000
  },
  "upstream": {
    "requests_per_member": 16, "member_wait_ms": 200, "answer_timeout_ms": 300,
    "tries": 3, "cooldown_ms": 200, "open_timeout_ms": 200, "leg_idle_ms": 300,
    "parked_legs": 256
  }
}"#;

/// What [`TUNING`] says, for a test that builds a set or a member directly.
pub fn tuning() -> Tuning {
    Tuning {
        listener: ListenerTuning {
            connections: CONNECTIONS,
            connections_per_source: PER_SOURCE,
            streams_per_connection: STREAMS,
            handshake_timeout: HANDSHAKE,
            header_timeout: HEADERS,
            ping_interval: PING,
            first_request_timeout: FIRST_REQUEST,
            idle_timeout: IDLE,
            lifetime: LIFETIME,
            drain_timeout: DRAIN,
            request_body_pause: BODY_PAUSE,
            request_body_timeout: BODY,
        },
        upstream: UpstreamTuning {
            requests_per_member: REQUESTS_PER_MEMBER,
            member_wait: MEMBER_WAIT,
            answer_timeout: ANSWER,
            tries: TRIES,
            cooldown: COOLDOWN,
            open_timeout: OPEN,
            leg_idle: LEG_IDLE,
            parked_legs: PARKED,
        },
    }
}
