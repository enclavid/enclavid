//! What a read, a write and a stored blob are made of, as a caller hands them to
//! the leg: the fields a read asks for; an op of each kind, every one answered at
//! the caller's end before it is added, and the record they are for; what the
//! record must be for the write to land; a blob as the stream it is sent as. The
//! doors turn them into the `ReadRequest`, the `WriteRequest` and the `CacheBlob`
//! that cross, so what crosses is built only of answered parts — and these, not
//! what crosses, are what a calling end declares (`RemoteSessionStoreCalls`,
//! `RemoteCacheCalls`).
//!
//! Only an answered part goes in. The control first:
//!
//! ```
//! use enclavid_boundary::{Boundary, Sends, outbound};
//! use storage_rpc::{MetadataOp, Ops, RecordName};
//! struct A;
//! impl Boundary for A {}
//! impl Sends<RecordName> for A { type Open = (); }
//! impl Sends<MetadataOp> for A { type Open = (); }
//! let mut ops = Ops::<A>::for_record(outbound::<A, _>(RecordName([0; 32])));
//! ops.metadata(outbound::<A, _>(MetadataOp(vec![])));
//! ```
//!
//! An op with a concern still open does not:
//!
//! ```compile_fail
//! use enclavid_boundary::{AuthN, Boundary, Sends, outbound};
//! use storage_rpc::{MetadataOp, Ops, RecordName};
//! struct A;
//! impl Boundary for A {}
//! impl Sends<RecordName> for A { type Open = (); }
//! impl Sends<MetadataOp> for A { type Open = (AuthN,); }
//! let mut ops = Ops::<A>::for_record(outbound::<A, _>(RecordName([0; 32])));
//! ops.metadata(outbound::<A, _>(MetadataOp(vec![])));
//! ```
//!
//! Nor does a media name nobody answered, in a write or in a read:
//!
//! ```compile_fail
//! use enclavid_boundary::{AuthN, Boundary, Sends, outbound};
//! use storage_rpc::{Fields, MediaName};
//! struct A;
//! impl Boundary for A {}
//! impl Sends<MediaName> for A { type Open = (AuthN,); }
//! let mut fields = Fields::<A>::new();
//! fields.media(outbound::<A, _>(MediaName([0; 32])));
//! ```

use std::marker::PhantomData;

use bytes::Bytes;
use enclavid_boundary::Exposed;
use fleet_stream::StreamLen;
use futures_util::stream::BoxStream;

use crate::session::{BlobField, BlobWrite, FieldSelector, ListAppend, ListField, MediaWrite, Op};
use crate::{MAX_CACHE_BLOB_BYTES, MediaName, RecordName};

/// A record's metadata, sealed.
pub struct MetadataOp(pub Vec<u8>);

/// A record's state, sealed.
pub struct StateOp(pub Vec<u8>);

/// One media blob, sealed. The name its record keeps it under is a part of its
/// own ([`Ops::media`]).
pub struct MediaOp(pub Vec<u8>);

/// One disclosure, sealed to its consumer.
#[derive(Clone)]
pub struct DisclosureOp(pub Vec<u8>);

/// Dropping a record's state, media and disclosures, keeping its metadata and
/// version.
pub struct ResetOp;

/// The ops of one write to one record, in the order they were added, each
/// answered at end `B` before it was. The record is named when the set is
/// started, so the ops can only land in the record they were made for.
pub struct Ops<B> {
    record: RecordName,
    ops: Vec<Op>,
    _end: PhantomData<fn() -> B>,
}

impl<B> Ops<B> {
    /// The ops of a write to the record `record` names.
    pub fn for_record(record: Exposed<RecordName, (), B>) -> Self {
        Self {
            record: record.into_inner(),
            ops: Vec::new(),
            _end: PhantomData,
        }
    }

    pub fn metadata(&mut self, op: Exposed<MetadataOp, (), B>) {
        self.ops.push(Op::Blob(BlobWrite {
            field: BlobField::Metadata,
            value: op.into_inner().0,
        }));
    }

    pub fn state(&mut self, op: Exposed<StateOp, (), B>) {
        self.ops.push(Op::Blob(BlobWrite {
            field: BlobField::State,
            value: op.into_inner().0,
        }));
    }

    /// One media blob, under the name `name`.
    pub fn media(&mut self, name: Exposed<MediaName, (), B>, op: Exposed<MediaOp, (), B>) {
        self.ops.push(Op::MediaWrite(MediaWrite {
            name: name.into_inner(),
            value: op.into_inner().0,
        }));
    }

    pub fn disclosure(&mut self, op: Exposed<DisclosureOp, (), B>) {
        self.ops.push(Op::ListAppend(ListAppend {
            field: ListField::Disclosure,
            value: op.into_inner().0,
        }));
    }

    pub fn reset(&mut self, op: Exposed<ResetOp, (), B>) {
        let ResetOp = op.into_inner();
        self.ops.push(Op::Reset);
    }

    /// How many ops the write makes.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub(crate) fn into_parts(self) -> (RecordName, Vec<Op>) {
        (self.record, self.ops)
    }
}

/// The fields one read asks for, in the order they were added: each slot of the
/// reply answers the field at its place.
pub struct Fields<B> {
    fields: Vec<FieldSelector>,
    _end: PhantomData<fn() -> B>,
}

impl<B> Default for Fields<B> {
    fn default() -> Self {
        Self {
            fields: Vec::new(),
            _end: PhantomData,
        }
    }
}

impl<B> Fields<B> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn metadata(&mut self) {
        self.fields.push(FieldSelector::Blob(BlobField::Metadata));
    }

    pub fn state(&mut self) {
        self.fields.push(FieldSelector::Blob(BlobField::State));
    }

    pub fn disclosures(&mut self) {
        self.fields.push(FieldSelector::List(ListField::Disclosure));
    }

    /// One media blob, by the name `name`.
    pub fn media(&mut self, name: Exposed<MediaName, (), B>) {
        self.fields.push(FieldSelector::Media(name.into_inner()));
    }

    /// How many fields the read asks for: one slot each.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub(crate) fn into_selectors(self) -> Vec<FieldSelector> {
        self.fields
    }
}

/// What a record must be for a write to land.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expected {
    /// Absent: the write creates it, with this deadline in unix seconds, or none.
    Absent { deadline_unix_secs: Option<u64> },
    /// At this version, as a read or a write returned it.
    Version(u64),
}

/// A cache blob as it is sent: its exact length, and its pieces in order. A piece
/// that fails abandons the blob; what failed is the sender's to know, and does
/// not cross.
pub struct BlobStream {
    pub length: StreamLen<MAX_CACHE_BLOB_BYTES>,
    pub pieces: BoxStream<'static, Result<Bytes, ()>>,
}
