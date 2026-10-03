//! Per-principal rate limits on the client API.
//!
//! One keyed limiter per operation, keyed by the principal `/authorize`
//! resolved, with a per-minute quota from `HATCH_<OPERATION>_PER_MINUTE` —
//! unset: 60 session creates, 600 session reads, 120 disclosure reads; `-1`:
//! no limit. A quota allows the whole minute's worth as a burst and refills
//! evenly.
//!
//! With `HATCH_AUTH=oidc` the key is a verified organization, so a bad
//! credential never reaches a limiter and a tenant can exhaust only its own
//! quota. With `HATCH_AUTH=none` every request has the same principal, so a
//! quota is shared by the whole host and anyone can exhaust it — `-1` keeps an
//! operation out of that.
//!
//! State is in memory, per hatch process. Keys are never evicted: there is one
//! per principal that has made a request, so they are bounded by the tenants.

use std::num::NonZeroU32;
use std::time::Duration;

use anyhow::Context;
use governor::clock::Clock;
use governor::{DefaultKeyedRateLimiter, Quota};

use hatch_protocol::ClientOperation;

type Limiter = DefaultKeyedRateLimiter<String>;

/// `None` is an operation without a limit.
pub struct RateLimits {
    session_create: Option<Limiter>,
    session_read: Option<Limiter>,
    data_read: Option<Limiter>,
}

impl RateLimits {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            session_create: limiter("HATCH_SESSION_CREATE_PER_MINUTE", 60)?,
            session_read: limiter("HATCH_SESSION_READ_PER_MINUTE", 600)?,
            data_read: limiter("HATCH_DATA_READ_PER_MINUTE", 120)?,
        })
    }

    /// Counts the request against `principal`'s quota for `op`. Over the
    /// quota, says how long until the principal may retry.
    pub fn check(&self, principal: &str, op: ClientOperation) -> Result<(), Duration> {
        let limiter = match op {
            ClientOperation::SessionCreate => &self.session_create,
            ClientOperation::SessionRead => &self.session_read,
            ClientOperation::DataRead => &self.data_read,
        };
        let Some(limiter) = limiter else {
            return Ok(());
        };
        limiter
            .check_key(&principal.to_owned())
            .map_err(|not_until| not_until.wait_time_from(limiter.clock().now()))
    }
}

fn limiter(name: &str, default: u32) -> anyhow::Result<Option<Limiter>> {
    let setting = std::env::var(name).ok();
    let quota = quota(setting.as_deref(), default)
        .with_context(|| format!("{name}: a count above zero, or -1 for no limit"))?;
    Ok(quota.map(Limiter::keyed))
}

/// The quota a setting names: `None` for `-1`, `default` when unset.
fn quota(setting: Option<&str>, default: u32) -> anyhow::Result<Option<Quota>> {
    let per_minute = match setting {
        None => default,
        Some("-1") => return Ok(None),
        Some(n) => n.parse()?,
    };
    let per_minute = NonZeroU32::new(per_minute).context("zero")?;
    Ok(Some(Quota::per_minute(per_minute)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn per_minute(n: u32) -> Option<Limiter> {
        Some(Limiter::keyed(Quota::per_minute(
            NonZeroU32::new(n).unwrap(),
        )))
    }

    /// A quota is one principal's, for one operation: exhausting it leaves
    /// another principal's, and another operation's, as they were.
    #[test]
    fn a_quota_is_per_principal_and_per_operation() {
        let limits = RateLimits {
            session_create: per_minute(2),
            session_read: per_minute(2),
            data_read: per_minute(2),
        };
        for _ in 0..2 {
            limits.check("a", ClientOperation::SessionCreate).unwrap();
        }
        let wait = limits
            .check("a", ClientOperation::SessionCreate)
            .expect_err("a third within the minute is over a quota of two");
        assert!(
            wait <= Duration::from_secs(30),
            "one refills in 30 s, said {wait:?}"
        );

        limits.check("b", ClientOperation::SessionCreate).unwrap();
        limits.check("a", ClientOperation::SessionRead).unwrap();
        limits.check("a", ClientOperation::DataRead).unwrap();
    }

    #[test]
    fn an_operation_without_a_limit_is_never_refused() {
        let limits = RateLimits {
            session_create: per_minute(1),
            session_read: None,
            data_read: None,
        };
        for _ in 0..1000 {
            limits.check("a", ClientOperation::SessionRead).unwrap();
        }
        limits.check("a", ClientOperation::SessionCreate).unwrap();
        limits
            .check("a", ClientOperation::SessionCreate)
            .expect_err("the limited operation still is");
    }

    #[test]
    fn a_setting_is_a_count_or_minus_one_and_unset_is_the_default() {
        let minute = |n| Some(Quota::per_minute(NonZeroU32::new(n).unwrap()));
        assert_eq!(quota(None, 60).unwrap(), minute(60));
        assert_eq!(quota(Some("5"), 60).unwrap(), minute(5));
        assert_eq!(quota(Some("-1"), 60).unwrap(), None);
        for refused in ["0", "-2", "", "unlimited", " 5", "4294967296"] {
            assert!(quota(Some(refused), 60).is_err(), "{refused:?}");
        }
    }
}
