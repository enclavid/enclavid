use tonic::transport::Channel;

use crate::error::StoreError;
use crate::proto::blob::blob_store_client::BlobStoreClient;
use crate::proto::blob::{
    DeleteRequest, ExistsRequest, GetRequest as BlobGetRequest, PutRequest,
};
use crate::proto::list::list_store_client::ListStoreClient;
use crate::proto::list::{AppendRequest, GetRequest as ListGetRequest};

pub use tonic::transport::Channel as GrpcChannel;

/// Connects to the store gRPC server over a Unix domain socket.
pub async fn connect_uds(socket_path: &str) -> Result<GrpcChannel, StoreError> {
    let channel = Channel::from_shared(format!("unix://{socket_path}"))
        .map_err(|e| StoreError::Transport(e.to_string()))?
        .connect()
        .await?;
    Ok(channel)
}

/// Builds a Channel without actually dialing — RPCs will fail if made, but
/// the channel is a valid value for constructing store clients. Intended
/// for tests that inject stores without exercising them.
pub fn lazy_channel() -> GrpcChannel {
    Channel::from_static("http://localhost").connect_lazy()
}

/// BlobStore client — read/write/delete single blobs by key.
#[derive(Clone)]
pub struct GrpcBlobStore {
    client: BlobStoreClient<Channel>,
    namespace: String,
}

// fn test <T: Into<dyn ::prost::Message + Sized>>(s: T) {
//     println!("blabla");
// }

impl GrpcBlobStore {
    pub fn new(channel: GrpcChannel, namespace: &str) -> Self {
        Self {
            client: BlobStoreClient::new(channel),
            namespace: namespace.to_string(),
        }
    }

    fn key(&self, session_id: &str) -> String {
        format!("{}:{}", self.namespace, session_id)
    }

    pub async fn put(&self, session_id: &str, data: Vec<u8>) -> Result<(), StoreError> {
        self.client
            .clone()
            .put(PutRequest {
                key: self.key(session_id),
                data,
            })
            .await?;
        Ok(())
    }

    pub async fn get(&self, session_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let response = self
            .client
            .clone()
            .get(BlobGetRequest {
                key: self.key(session_id),
            })
            .await?;
        Ok(response.into_inner().data)
    }

    pub async fn exists(&self, session_id: &str) -> Result<bool, StoreError> {
        let response = self
            .client
            .clone()
            .exists(ExistsRequest {
                key: self.key(session_id),
            })
            .await?;
        Ok(response.into_inner().exists)
    }

    pub async fn delete(&self, session_id: &str) -> Result<(), StoreError> {
        self.client
            .clone()
            .delete(DeleteRequest {
                key: self.key(session_id),
            })
            .await?;
        Ok(())
    }
}

/// ListStore client — append-only list by key.
#[derive(Clone)]
pub struct GrpcListStore {
    client: ListStoreClient<Channel>,
    namespace: String,
}

impl GrpcListStore {
    pub fn new(channel: GrpcChannel, namespace: &str) -> Self {
        Self {
            client: ListStoreClient::new(channel),
            namespace: namespace.to_string(),
        }
    }

    fn key(&self, session_id: &str) -> String {
        format!("{}:{}", self.namespace, session_id)
    }

    pub async fn append(&self, session_id: &str, data: Vec<u8>) -> Result<(), StoreError> {
        self.client
            .clone()
            .append(AppendRequest {
                key: self.key(session_id),
                data,
            })
            .await?;
        Ok(())
    }

    pub async fn get(&self, session_id: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        let response = self
            .client
            .clone()
            .get(ListGetRequest {
                key: self.key(session_id),
            })
            .await?;
        Ok(response.into_inner().items)
    }
}
