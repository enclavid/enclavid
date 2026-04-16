mod error;
mod grpc;
mod stores;

mod proto {
    pub mod blob {
        tonic::include_proto!("enclavid.blob_store");
    }
    pub mod list {
        tonic::include_proto!("enclavid.list_store");
    }
    pub mod state {
        tonic::include_proto!("enclavid.state");
    }
}

pub use error::StoreError;
pub use grpc::{connect_uds, GrpcBlobStore, GrpcChannel, GrpcListStore};
pub use proto::state::{SessionMetadata, SessionState, TwoSidedDocument};
pub use stores::{DisclosureStore, MetadataStore, StateStore};
