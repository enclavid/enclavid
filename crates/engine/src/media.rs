//! The host-owned `enclavid:host/types.clip` resource.
//!
//! A capture's frames are held here, host-side, for exactly one reducer
//! round. The runtime mints a handle from the applicant's `/input` bytes
//! when it builds `event::media` (see [`runner::convert::event_to_wit`]);
//! the policy receives the handle and routes it to a verification plugin
//! (fused into the same store), which pulls the frames it needs via the
//! `frame` / `frame-count` methods. The pixel bytes therefore enter a
//! component's linear memory only at the point of use — never the
//! policy's, which is a pure router — and can't be smuggled into the
//! sealed `state` (the handle is meaningless across rounds; the backing
//! bytes are dropped with the Store).

use wasmtime::component::Resource;

use crate::state::HostState;

/// Backing rep for a `clip` handle: the raw JPEG frames of one capture.
/// Owned by the run's [`ResourceTable`](wasmtime::component::ResourceTable);
/// a component only ever holds an unforgeable handle to it.
pub struct ClipRep {
    pub frames: Vec<Vec<u8>>,
}

impl crate::enclavid::host::types::HostClip for HostState {
    async fn frame_count(&mut self, self_: Resource<ClipRep>) -> wasmtime::Result<u32> {
        Ok(self.table.get(&self_)?.frames.len() as u32)
    }

    async fn frame(
        &mut self,
        self_: Resource<ClipRep>,
        index: u32,
    ) -> wasmtime::Result<Option<Vec<u8>>> {
        Ok(self.table.get(&self_)?.frames.get(index as usize).cloned())
    }

    async fn frames(&mut self, self_: Resource<ClipRep>) -> wasmtime::Result<Vec<Vec<u8>>> {
        Ok(self.table.get(&self_)?.frames.clone())
    }

    async fn drop(&mut self, rep: Resource<ClipRep>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
