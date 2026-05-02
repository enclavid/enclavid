use enclavid_untrusted::Untrusted;
use tonic::transport::Channel;

use crate::error::BridgeError;
use crate::proto::blob::blob_store_client::BlobStoreClient;
use crate::proto::blob::{
    DeleteRequest, ExistsRequest, GetRequest as BlobGetRequest, PutRequest,
};
use crate::proto::list::list_store_client::ListStoreClient;
use crate::proto::list::{AppendRequest, GetRequest as ListGetRequest};

pub use crate::transport::{connect_store, GrpcChannel};

/// BlobStore client — read/write/delete single blobs by key.
///
/// Every successful return crosses the host trust boundary. Read values
/// are wrapped in `Untrusted<T>` so callers must explicitly verify or
/// `.trust_unchecked()` with a comment. Write/delete responses are
/// wrapped in `Untrusted<()>` even though the unit carries no data —
/// this forces every caller to acknowledge that "Ok" means "host claims
/// it succeeded", not "TEE verified the on-disk state matches". Without
/// this marker, callers naturally drift into building security on top
/// of an advisory signal.
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

    /// Returns `Untrusted<()>` — store-write carries no payload back, so
    /// "Ok" is just the host's acknowledgement that it claims to have
    /// stored the bytes. The unit is a placeholder for the trust-marker
    /// wrapper; `delete`/`append` carry an actual count instead.
    pub async fn put(
        &self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<Untrusted<()>, BridgeError> {
        self.client
            .clone()
            .put(PutRequest {
                key: self.key(session_id),
                data,
            })
            .await?;
        Ok(Untrusted::new(()))
    }

    /// Returns `Untrusted<Option<Vec<u8>>>` — both the existence
    /// discriminator and the bytes are host-controlled. A lying host
    /// could hide an existing blob behind a fake `None`. Caller must
    /// decide via `.trust(...)` or `.trust_unchecked()` whether to
    /// accept the host's existence claim.
    pub async fn get(
        &self,
        session_id: &str,
    ) -> Result<Untrusted<Option<Vec<u8>>>, BridgeError> {
        let response = self
            .client
            .clone()
            .get(BlobGetRequest {
                key: self.key(session_id),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().data))
    }

    pub async fn exists(
        &self,
        session_id: &str,
    ) -> Result<Untrusted<bool>, BridgeError> {
        let response = self
            .client
            .clone()
            .exists(ExistsRequest {
                key: self.key(session_id),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().exists))
    }

    /// Returns `Untrusted<u64>` — number of keys actually removed
    /// according to the host. 0 means "key did not exist" (idempotent
    /// no-op); >0 means "host claims it wiped real bytes". Trust as
    /// observability hint, not as security signal — a lying host can
    /// fake either direction.
    pub async fn delete(
        &self,
        session_id: &str,
    ) -> Result<Untrusted<u64>, BridgeError> {
        let response = self
            .client
            .clone()
            .delete(DeleteRequest {
                key: self.key(session_id),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().deleted))
    }
}

/// ListStore client — append-only list by key. Same trust model as
/// `GrpcBlobStore`: every successful return is `Untrusted<T>` to make
/// the host-bridge boundary visible at every call site.
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

    /// Returns `Untrusted<u64>` — list length after the append.
    /// Useful for observability and comparing with expected sequence
    /// numbers; not a security signal.
    pub async fn append(
        &self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<Untrusted<u64>, BridgeError> {
        let response = self
            .client
            .clone()
            .append(AppendRequest {
                key: self.key(session_id),
                data,
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().length))
    }

    pub async fn get(
        &self,
        session_id: &str,
    ) -> Result<Untrusted<Vec<Vec<u8>>>, BridgeError> {
        let response = self
            .client
            .clone()
            .get(ListGetRequest {
                key: self.key(session_id),
            })
            .await?;
        Ok(Untrusted::new(response.into_inner().items))
    }
}
