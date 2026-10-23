//! Where the stores find the storage-CVM: the leg api keeps connected to it, as
//! it keeps one to each of its peers, held at api's end of it.

use std::sync::Arc;

use storage_rpc::StorageLeg;

use crate::boundary::Storage;
use crate::error::StoreError;

/// The storage leg as its holder keeps it — `None` while the leg is down, and
/// then a call fails rather than waits: how long to wait for the leg is the
/// host's call, and api's health port is already telling it.
pub trait Link: Send + Sync + 'static {
    fn leg(&self) -> Option<Arc<StorageLeg<Storage>>>;
}

/// The storage leg, or the leg being down as a transport failure.
pub(crate) fn storage(link: &dyn Link) -> Result<Arc<StorageLeg<Storage>>, StoreError> {
    link.leg()
        .ok_or_else(|| StoreError::Transport("the storage leg is down".into()))
}
