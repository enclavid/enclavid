use tonic::transport::Channel;

use crate::error::StoreError;
use crate::proto::blob::blob_store_client::BlobStoreClient;
use crate::proto::blob::{
    DeleteRequest, ExistsRequest, GetRequest as BlobGetRequest, PutRequest,
};
use crate::proto::list::list_store_client::ListStoreClient;
use crate::proto::list::{AppendRequest, GetRequest as ListGetRequest};

pub use crate::transport::{connect_store, GrpcChannel};

/// BlobStore client — read/write/delete single blobs by key.
#[derive(Clone)]
pub struct GrpcBlobStore {
    client: BlobStoreClient<Channel>,
    namespace: String,
}

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
