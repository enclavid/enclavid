//! The one remoc connection config every fleet leg is brought up with.
//!
//! Both contracts that bring a leg up — the engine's and the storage tier's —
//! build from [`connection_cfg`], so the two ends of every leg agree on the parts
//! that are facts of this code, and each role sets the parts that are its
//! deployment's from its own launch settings ([`LegSettings`]). The two ends need
//! not agree on those: chmux announces each end's own in its hello and the other
//! end fits to it (see the fields).

use std::time::Duration;

/// What a role decides about its own end of each fleet leg, unless the host says
/// otherwise (its `leg-timeout-secs`, `leg-max-ports`, `leg-chunk-bytes` and
/// `leg-receive-bytes` settings).
///
/// None of it reaches what a session discloses or how it is padded: the framing
/// that holds the host's view of a round to a constant size is the contract's,
/// above this, and a chunk only splits a frame already that size. What these
/// change is how soon a dead peer is noticed, how many rounds one leg carries at
/// once, and how fast a bundle crosses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegSettings {
    /// How long this end lets a leg go silent before it treats it as gone.
    ///
    /// chmux has no separate ping interval: each end pings at HALF the
    /// patience its PEER announced whenever it has nothing else to send, and
    /// gives up when nothing has arrived within its own (`chmux/mux.rs`, where
    /// `send_task` takes `remote_cfg.connection_timeout / 2` and `recv_task`
    /// takes `local_cfg.connection_timeout`). So the two ends may differ, and
    /// each is pinged fast enough for its own patience.
    ///
    /// 20 s by default rather than chmux's 60: it is what bounds the window in
    /// which api is alive, listening, and failing every request that touches a
    /// dead peer. Not lower, because the margin is exactly one ping: a ping that
    /// arrives late by more than its own interval times the link out. Bytes are
    /// not lost on this hop — vsock through a splicing relay is a reliable
    /// stream — so "late" means the sender's runtime did not schedule its send
    /// task for 10 s, which roles that hand their work to child processes should
    /// never do.
    pub timeout: Duration,
    /// How many ports this end lets its peer hold open at once.
    ///
    /// Below chmux's 16384 because the far end of a worker's leg is untrusted
    /// once its wasm or Cranelift is escaped, and a peer that opens ports without
    /// end costs this end memory for each. What one round holds on each end while
    /// it is in flight: its reply and its callback client, a port each, and on a
    /// cache miss the bundle's two streams besides — four. A callback in progress
    /// holds one more. So 256 is some sixty cold rounds in flight on one leg, or
    /// about twice that warm. A round past that waits for a port, up to chmux's
    /// 60 s, rather than failing at once, and a round's ports free as it ends.
    pub max_ports: u32,
    /// The size of the pieces a long message travels to this end in.
    ///
    /// The RECEIVER's to choose: each end announces its own and its peer splits
    /// to fit. 64 KiB by default rather than chmux's 16 KiB because a bundle
    /// streams across a leg whole, and a quarter of the frames measured about
    /// twice the throughput.
    pub chunk_bytes: u32,
    /// How much a port's sender may have on its way to this end before it waits
    /// for this end to take some: the window a stream crosses the leg in.
    ///
    /// The RECEIVER's to choose, like the chunk. A stream runs no faster than
    /// this window over the time a chunk takes to cross and its credit to come
    /// back. 8 MiB by default rather than chmux's 512 KiB: a bundle crossing a
    /// leg between two guests, through the host's relay, ran about half again
    /// as fast with it, and nothing past it. The price is what a peer that
    /// sends without this end reading can make it hold: this much on every
    /// port it holds open, so up to `max_ports` times this.
    pub receive_bytes: u32,
}

impl Default for LegSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            max_ports: 256,
            chunk_bytes: 64 * 1024,
            receive_bytes: 8 * 1024 * 1024,
        }
    }
}

impl LegSettings {
    /// Which of these chmux cannot run a leg with, if any — named for the boot
    /// line that refuses it. chmux itself would panic at the first connect, which
    /// is a worse place to learn it.
    pub fn refusal(&self) -> Option<&'static str> {
        if self.timeout.is_zero() {
            return Some("a leg timeout of zero");
        }
        if self.max_ports == 0 || self.max_ports > 1 << 31 {
            return Some("a leg port limit outside 1 to 2^31");
        }
        if self.chunk_bytes < 4 || self.chunk_bytes > u32::MAX - 16 {
            return Some("a leg chunk outside 4 bytes to 2^32 - 16");
        }
        if self.receive_bytes < 4 {
            return Some("a leg receive window under 4 bytes");
        }
        None
    }
}

/// The remoc connection config for one end of a fleet leg.
///
/// Beside `leg`, three parts that are facts of this code rather than of a
/// deployment:
///
///   * `max_data_size` is the largest message chmux receives in one piece; past
///     it a remote channel streams the message through a deserialization thread
///     instead. It is not a size limit. What caps one request or one reply is
///     remoc's per-item limit (`remoc::rch::DEFAULT_MAX_ITEM_SIZE`, 16 MiB), and
///     an item past that fails the channel it was sent on. 64 MiB rather than
///     chmux's 512 KiB so a compile reply, which carries its bundle as one item,
///     arrives whole.
///   * `flush_delay` is zero. chmux's 20 ms waits to coalesce sends, which on a
///     request/response RPC adds about 20 ms per direction to every call
///     (measured); these messages are whole RPC frames, so there is nothing to
///     coalesce.
///   * `max_received_ports` is 64: how many ports one message may carry. Ours
///     carry a handful, so this bounds only a peer's malformed ones.
///
/// `remoc::Cfg` is `#[non_exhaustive]`, so it cannot be built as a struct
/// literal from here — mutate-after-default is the only option.
#[allow(clippy::field_reassign_with_default)]
pub fn connection_cfg(leg: &LegSettings) -> remoc::Cfg {
    let mut cfg = remoc::Cfg::default();
    cfg.connection_timeout = Some(leg.timeout);
    cfg.max_ports = leg.max_ports;
    cfg.chunk_size = leg.chunk_bytes;
    cfg.receive_buffer = leg.receive_bytes;
    cfg.max_data_size = 64 * 1024 * 1024;
    cfg.flush_delay = Duration::ZERO;
    cfg.max_received_ports = 64;
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_run_a_leg() {
        assert_eq!(LegSettings::default().refusal(), None);
    }

    #[test]
    fn what_chmux_cannot_run_is_refused() {
        let leg = LegSettings::default();
        for bad in [
            LegSettings {
                timeout: Duration::ZERO,
                ..leg
            },
            LegSettings {
                max_ports: 0,
                ..leg
            },
            LegSettings {
                max_ports: (1 << 31) + 1,
                ..leg
            },
            LegSettings {
                chunk_bytes: 3,
                ..leg
            },
            LegSettings {
                receive_bytes: 3,
                ..leg
            },
        ] {
            assert!(bad.refusal().is_some(), "{bad:?}");
        }
    }
}
