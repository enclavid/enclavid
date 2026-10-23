//! A storage-CVM in memory, for tests: both contracts served over a pipe as the
//! storage-CVM serves them, and the leg brought up at [`Storage`] as api brings
//! it up. What it keeps is in maps a test reaches into — the volume as the host
//! has it, to read, change, or put an older copy back.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use enclavid_boundary::{AuthN, Exposed, Untrusted};
use enclavid_boundary_macros::boundary;
use fleet_stream::{Incoming, StreamLen, bin};
use futures::StreamExt;
use storage_rpc::{
    BlobField, BlobName, CACHE_STREAM_DEADLINE, CACHE_STREAM_IDLE, CacheBlob, CacheError, Dropped,
    FieldSelector, Kept, LegSettings, ListField, ListSlot, MediaName, Op, ReadRequest,
    ReadResponse, RecordName, RemoteCacheAt, RemoteSessionStoreAt, ScalarSlot, SessionError, Slot,
    StorageLeg, WriteRequest, WriteResponse,
};

use crate::boundary::Storage;
use crate::link::Link;

boundary! {
    /// The store end of a test's leg: what it is handed it keeps as it is, for
    /// the test to read as the host would.
    Volume {
        serves: [storage_rpc::RemoteSessionStore, storage_rpc::RemoteCache],
        observer: Test,
    }

    in (AuthN,) {
        /// Kept as it is, for the test that sent it.
        _: AuthN::Indifferent,
        RecordName,
        BlobName,
        ReadRequest,
        WriteRequest,
        CacheBlob,
    }

    out (AuthN,) {
        /// Read back by the test's own client.
        _: AuthN::Indifferent,
        ReadResponse,
        WriteResponse,
        Option<CacheBlob>,
        Kept,
        Dropped,
        SessionError,
        CacheError,
    }
}

/// One session's record, as the store keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub version: u64,
    pub metadata: Option<Vec<u8>>,
    pub state: Option<Vec<u8>>,
    pub media: HashMap<MediaName, Vec<u8>>,
    pub disclosures: Vec<Vec<u8>>,
    pub deadline_unix_secs: Option<u64>,
}

/// Everything a store in memory keeps: each record under its name, each cache
/// blob under its name.
#[derive(Default)]
pub struct Disk {
    pub records: Mutex<HashMap<RecordName, Record>>,
    pub blobs: Mutex<HashMap<BlobName, Vec<u8>>>,
    /// Answer every read with one slot fewer than it asked for: a store that
    /// does not keep to the contract.
    pub short_reads: AtomicBool,
}

impl Disk {
    /// This disk served over a pipe as the storage-CVM serves its own, and the
    /// leg to it brought up at api's end.
    pub async fn connect(self: &Arc<Self>) -> Arc<dyn Link> {
        let (store, api) = tokio::io::duplex(1024 * 1024);
        let (store_r, store_w) = tokio::io::split(store);
        let (api_r, api_w) = tokio::io::split(api);
        let served = Served(self.clone());
        tokio::spawn(async move {
            let _ = storage_rpc::serve_storage::<Volume, _, _, _>(
                store_r,
                store_w,
                served,
                4,
                4,
                &LegSettings::default(),
            )
            .await;
        });
        let (leg, _ended) =
            storage_rpc::connect_storage::<Storage, _, _>(api_r, api_w, &LegSettings::default())
                .await
                .expect("a leg over a pipe comes up");
        Arc::new(Connected(Arc::new(leg)))
    }
}

struct Connected(Arc<StorageLeg<Storage>>);

impl Link for Connected {
    fn leg(&self) -> Option<Arc<StorageLeg<Storage>>> {
        Some(self.0.clone())
    }
}

/// A [`Disk`], served.
struct Served(Arc<Disk>);

impl RemoteSessionStoreAt<Volume> for Served {
    async fn read(
        &self,
        record: Untrusted<RecordName, (), Volume>,
        req: Untrusted<ReadRequest, (), Volume>,
    ) -> Result<Exposed<ReadResponse, (), Volume>, SessionError> {
        let records = self.0.records.lock().unwrap();
        let record = records.get(&record.into_inner());
        let scalar = |value: Option<&Vec<u8>>| {
            Slot::Scalar(ScalarSlot {
                value: value.cloned(),
            })
        };
        let mut slots: Vec<Slot> = req
            .into_inner()
            .fields
            .into_iter()
            .map(|field| match field {
                FieldSelector::Blob(BlobField::Metadata) => {
                    scalar(record.and_then(|r| r.metadata.as_ref()))
                }
                FieldSelector::Blob(BlobField::State) => {
                    scalar(record.and_then(|r| r.state.as_ref()))
                }
                FieldSelector::Media(name) => scalar(record.and_then(|r| r.media.get(&name))),
                FieldSelector::List(ListField::Disclosure) => Slot::List(ListSlot {
                    items: record.map(|r| r.disclosures.clone()).unwrap_or_default(),
                }),
            })
            .collect();
        if self.0.short_reads.load(Ordering::Relaxed) {
            slots.pop();
        }
        Ok(Volume::expose(ReadResponse {
            slots,
            version: record.map_or(0, |r| r.version),
        }))
    }

    async fn write(
        &self,
        record: Untrusted<RecordName, (), Volume>,
        req: Untrusted<WriteRequest, (), Volume>,
    ) -> Result<Exposed<WriteResponse, (), Volume>, SessionError> {
        let req = req.into_inner();
        if req.ops.is_empty() {
            return Err(SessionError::Internal("write with no ops".into()));
        }
        let mut records = self.0.records.lock().unwrap();
        let name = record.into_inner();
        // `None` is a create, and finds no record; `Some` finds the one at it.
        if req.expected_version != records.get(&name).map(|r| r.version) {
            return Err(SessionError::VersionMismatch);
        }
        let record = records.entry(name).or_insert_with(|| Record {
            deadline_unix_secs: req.deadline_unix_secs,
            ..Record::default()
        });
        for op in req.ops {
            match op {
                Op::Blob(b) => match b.field {
                    BlobField::Metadata => record.metadata = Some(b.value),
                    BlobField::State => record.state = Some(b.value),
                },
                Op::ListAppend(a) => match a.field {
                    ListField::Disclosure => record.disclosures.push(a.value),
                },
                Op::MediaWrite(m) => {
                    record.media.insert(m.name, m.value);
                }
                Op::Reset => {
                    record.state = None;
                    record.media.clear();
                    record.disclosures.clear();
                }
            }
        }
        record.version += 1;
        Ok(Volume::expose(WriteResponse {
            new_version: record.version,
        }))
    }
}

impl RemoteCacheAt<Volume> for Served {
    async fn store(
        &self,
        blob: Untrusted<BlobName, (), Volume>,
        body: Untrusted<CacheBlob, (), Volume>,
    ) -> Result<Exposed<Kept, (), Volume>, CacheError> {
        let body = body.into_inner();
        let failed = |e: fleet_stream::StreamError| CacheError(e.to_string());
        let mut pieces = Incoming::open(body.body, body.length.get(), CACHE_STREAM_IDLE)
            .await
            .map_err(failed)?
            .into_pieces(CACHE_STREAM_DEADLINE, None);
        let mut held = Vec::new();
        while let Some(piece) = pieces.next().await {
            held.extend_from_slice(&piece.map_err(failed)?);
        }
        self.0.blobs.lock().unwrap().insert(blob.into_inner(), held);
        Ok(Volume::expose(Kept))
    }

    async fn load(
        &self,
        blob: Untrusted<BlobName, (), Volume>,
    ) -> Result<Exposed<Option<CacheBlob>, (), Volume>, CacheError> {
        let Some(held) = self
            .0
            .blobs
            .lock()
            .unwrap()
            .get(&blob.into_inner())
            .cloned()
        else {
            return Ok(Volume::expose(None));
        };
        let length = StreamLen::new(held.len() as u64)
            .ok_or_else(|| CacheError("a blob past what the leg carries".into()))?;
        let (tx, body) = bin::channel();
        // In pieces of 1000 bytes, which line up with nothing a store wrote.
        let pieces: Vec<Result<Bytes, std::convert::Infallible>> = held
            .chunks(1000)
            .map(|p| Ok(Bytes::copy_from_slice(p)))
            .collect();
        tokio::spawn(async move {
            let _ = fleet_stream::send_from(tx, futures::stream::iter(pieces)).await;
        });
        Ok(Volume::expose(Some(CacheBlob { length, body })))
    }

    async fn remove(
        &self,
        blob: Untrusted<BlobName, (), Volume>,
    ) -> Result<Exposed<Dropped, (), Volume>, CacheError> {
        self.0.blobs.lock().unwrap().remove(&blob.into_inner());
        Ok(Volume::expose(Dropped))
    }
}
