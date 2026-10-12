//! The algorithm's side: one `System` that holds what every server last said
//! and steers the clock from it. The sources ask it for what only it can do —
//! make a source, take a measurement, drop a source — over one channel, so
//! what one source asks is handled in the order it asked.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ntp_proto::{
    AlgorithmConfig, KalmanClockController, KeyExchangeResult, NtpDuration, NtpSource,
    NtpSourceActionIterator, NtpSourceUpdate, SourceConfig, StepThreshold, SynchronizationConfig,
    System, SystemAction, SystemSourceUpdate, TimeSyncController,
};
use timesync::MAX_ERROR;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;

use crate::clock::SystemClock;
use crate::servers::AGREEING;

/// Which source a measurement came from. A new one for every key exchange, so
/// a measurement can never be credited to a source made after it.
pub type SourceId = u64;

type Controller = KalmanClockController<SystemClock, SourceId>;
type SourceMessage = <Controller as TimeSyncController>::SourceMessage;
type ControllerMessage = <Controller as TimeSyncController>::ControllerMessage;

pub type Source = NtpSource<<Controller as TimeSyncController>::NtpSourceController>;
pub type SourceActions = NtpSourceActionIterator<SourceMessage>;
pub type SourceUpdate = NtpSourceUpdate<SourceMessage>;
pub type SystemUpdate = SystemSourceUpdate<ControllerMessage>;

/// How many messages from the system every source may fall behind by. Each is a
/// correction the source applies to its own estimate, so one that falls further
/// has missed one, and ends (source.rs); its next key exchange starts it level.
const UPDATE_BUFFER: usize = 32;

/// What `ntp-proto` keeps as a source's address. It derives a reference ID from
/// it and checks it against this machine's own addresses for loops; there are
/// none here, and the server is named by its key exchange instead.
const NO_ADDRESS: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

pub enum Request {
    /// A key exchange finished: make the source it agreed keys for.
    Create {
        ke: KeyExchangeResult,
        reply: oneshot::Sender<Created>,
    },
    /// A source took a measurement. Boxed: it is most of a kilobyte, and the
    /// other two are a few words.
    Update(SourceId, Box<SourceUpdate>),
    /// A source stopped. Sent by the same source after its last update, so the
    /// system never hears from a source it has dropped.
    Remove(SourceId),
}

pub struct Created {
    pub id: SourceId,
    pub source: Source,
    pub actions: SourceActions,
    pub updates: broadcast::Receiver<SystemUpdate>,
}

/// How the clock is taken.
///
/// [`AGREEING`] servers have to agree before anything changes. The step limits
/// at startup are lifted: the clock starts at what the host's emulated RTC
/// said, so how far off it is says nothing about the servers, and an agreement
/// is the only authority there is.
///
/// After that, a single step of more than [`MAX_ERROR`] either way ends this
/// process, and with it the guest. Every role's guard took the clock to be
/// within that much of the time until the step, so a larger one says it was
/// not; on a TSC the host cannot move, it says the servers moved. Steps are not
/// limited added up: agreeing servers can move the clock by slewing it, which
/// takes no step at all, so such a limit would stop only the ones that step.
fn synchronization() -> SynchronizationConfig {
    let step = Some(NtpDuration::from_system_duration(MAX_ERROR));
    SynchronizationConfig {
        minimum_agreeing_sources: AGREEING,
        single_step_panic_threshold: StepThreshold {
            forward: step,
            backward: step,
        },
        startup_step_panic_threshold: StepThreshold {
            forward: None,
            backward: None,
        },
        ..SynchronizationConfig::default()
    }
}

/// Serve the sources' requests and steer the clock, for as long as the process
/// lives.
pub async fn run(mut requests: mpsc::Receiver<Request>) {
    let mut system = System::<SourceId, Controller>::new(
        SystemClock,
        synchronization(),
        AlgorithmConfig::default(),
        Arc::new([]),
    )
    .expect("making the system reads no clock");
    system
        .check_clock_access()
        .expect("the keeper runs with the right to set the clock");

    let (updates, _) = broadcast::channel(UPDATE_BUFFER);
    let mut next_id: SourceId = 0;
    // The algorithm asks to be woken when it has something to finish, such as
    // the end of a slew; until it asks, there is nothing to wake it for.
    let timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(timer);
    let mut armed = false;

    loop {
        let actions = tokio::select! {
            request = requests.recv() => {
                match request.expect("every source holds a sender for as long as it runs") {
                    Request::Create { ke, reply } => {
                        next_id += 1;
                        // ntp-proto's own pace: every 16 s, widening as the
                        // estimate settles. Every guest on a host reaches the
                        // servers from the host's one address, and some of
                        // them silently drop what comes faster from one.
                        let (source, actions) = system
                            .create_ntp_source(
                                next_id,
                                SourceConfig::default(),
                                NO_ADDRESS,
                                ke.protocol_version,
                                Some(ke.nts),
                            )
                            .expect("the system took the clock before any source");
                        let _ = reply.send(Created {
                            id: next_id,
                            source,
                            actions,
                            updates: updates.subscribe(),
                        });
                        continue;
                    }
                    Request::Update(id, update) => system
                        .handle_source_update(id, *update)
                        .expect("the clock is steered by a process that may steer it"),
                    Request::Remove(id) => {
                        system
                            .handle_source_remove(id)
                            .expect("removing a source touches no clock");
                        continue;
                    }
                }
            }
            () = &mut timer, if armed => {
                armed = false;
                system.handle_timer()
            }
        };
        for action in actions {
            match action {
                SystemAction::UpdateSources(update) => {
                    // No source listening is a moment between sources, not a fault.
                    let _ = updates.send(update);
                }
                SystemAction::SetTimer(after) => {
                    timer.as_mut().reset(Instant::now() + after);
                    armed = true;
                }
            }
        }
    }
}
