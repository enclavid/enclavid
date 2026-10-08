//! The channel between a supervisor and its child: one socketpair, framed by
//! remoc the same way at both ends.

/// The remoc connection config of the channel supervisor↔child, used by both
/// halves. `max_data_size` is the largest message chmux receives in one piece;
/// past it a remote channel streams the message through a deserialization thread
/// instead. It is not a size limit: a compile returns its `cwasm` over this
/// connection, and what caps that reply is remoc's per-item limit
/// (`remoc::rch::DEFAULT_MAX_ITEM_SIZE`, 16 MiB). Raised from chmux's 512 KiB so
/// that reply arrives whole. The engine RPC contract raises the same limit on
/// the api hop; this crate is a leaf and cannot name that constant.
// `remoc::Cfg` is `#[non_exhaustive]`, so a struct literal (`Cfg { .., ..default }`)
// can't be built from here — the mutate-after-default is the only option.
#[allow(clippy::field_reassign_with_default)]
pub(crate) fn channel_config() -> remoc::Cfg {
    let mut cfg = remoc::Cfg::default();
    cfg.max_data_size = 64 * 1024 * 1024;
    // Flush immediately: chmux's default 20 ms `flush_delay` (a throughput
    // coalescing timer) adds ~20 ms per SEND direction to our latency-bound
    // request/response RPC — measured ~40 ms/round-trip. Each side flushes its own
    // sends, so BOTH this (child-serve) side and the engine-rpc (api/supervisor)
    // side must set it. Nothing to coalesce: our writes are whole RPC frames.
    cfg.flush_delay = std::time::Duration::ZERO;
    // Pin the peer-driven port limits well below chmux's defaults (16384 ports /
    // 128 received). The child is UNTRUSTED once its wasm/Cranelift is escaped, and
    // it drives its own end of this socketpair — the default would let a compromised
    // child open thousands of ports to exhaust supervisor memory. Our RPC uses only
    // a handful of concurrent channels (base + prime/run + a few callbacks), so 256
    // is generous headroom while bounding the exhaustion surface.
    cfg.max_ports = 256;
    cfg.max_received_ports = 64;
    cfg
}
