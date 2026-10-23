//! This role's end of the api leg, declared.
//!
//! The listener accepts any attested guest — it cannot pin api, whose
//! measurement is a function of this one's — so a completed handshake proves a
//! genuine SNP guest of this host, and not which. And this role keeps every
//! caller's records in one store. That is why `AuthN` and `AuthZ` are open on
//! what arrives: a caller may be one the host launched, asking for records that
//! are not its own.
//!
//! What answers both is the partition (`scope`): every record and blob is filed
//! under a digest of the caller's own measurement and the name it sent, so
//! whatever a caller sends lands in its own partition and reaches nothing of
//! another's. It is kept as it arrived, unread — sealed bytes under names api
//! derived — which this role neither opens nor needs to. Not `Replay` on the way
//! in: no request outlives its own call.
//!
//! On the way out there is no `AuthN`: the channel names no peer, and the
//! recipient is not this role's to choose — it answers only the call that asked.
//! What a reply carries comes from the caller's own partition, so `AuthZ` is
//! answered type by type; and it comes off the volume the host provisions and
//! reads, or is one of a few fixed values, so `Covert` is answered type by type
//! with which.

use enclavid_boundary::{AuthN, AuthZ, Covert};
use enclavid_boundary_macros::boundary;
use storage_rpc::{
    BlobName, CacheBlob, CacheError, Dropped, Kept, ReadRequest, ReadResponse, RecordName,
    SessionError, WriteRequest, WriteResponse,
};

boundary! {
    /// Whoever called: a genuine SNP guest of this host, not identifiably api.
    pub AnyCaller {
        serves: [storage_rpc::RemoteSessionStore, storage_rpc::RemoteCache],
        observer: HostSplices,
    }

    in (AuthN, AuthZ) {
        /// Filed under a digest of it and the caller's own measurement: whatever a
        /// caller names, it names a record of its own.
        RecordName: AuthN::Indifferent,
        /// The digest is drawn from the measurement the caller attested, so no
        /// name reaches another caller's record.
        RecordName: AuthZ::Scoped,
        /// Filed as a record's name is, in the cache's half of the partition.
        BlobName: AuthN::Indifferent,
        /// Drawn from the caller's own measurement, as a record's name is.
        BlobName: AuthZ::Scoped,
        /// Field tags and names to read, of the record its call names: what it
        /// selects is the caller's own.
        ReadRequest: AuthN::Indifferent,
        /// It reads only the record its call names, in the caller's own partition.
        ReadRequest: AuthZ::Scoped,
        /// Kept as it arrived, unread, in the record its call names: whatever a
        /// caller writes is its own.
        WriteRequest: AuthN::Indifferent,
        /// It writes only the record its call names, in the caller's own partition.
        WriteRequest: AuthZ::Scoped,
        /// Kept as it arrived, unread, under the name its call gives.
        CacheBlob: AuthN::Indifferent,
        /// It is kept only under the name its call gives, in the caller's own
        /// partition.
        CacheBlob: AuthZ::Scoped,
    }

    out (AuthZ, Covert) {
        /// Read from the record its call named, in the caller's own partition.
        ReadResponse: AuthZ::Scoped,
        /// Bytes and a version read off the volume the host provisions and reads.
        ReadResponse: Covert::AlreadyHeld,
        /// The version of the record its call wrote, in the caller's own partition.
        WriteResponse: AuthZ::Scoped,
        /// A version the volume holds, bumped by a write the host watched land.
        WriteResponse: Covert::AlreadyHeld,
        /// The blob kept under the name its call gave, in the caller's own
        /// partition.
        Option<CacheBlob>: AuthZ::Scoped,
        /// Bytes read off the volume the host provisions and reads.
        Option<CacheBlob>: Covert::AlreadyHeld,
        /// That the blob this call sent is kept, and nothing else.
        Kept: AuthZ::NoSecret,
        /// One fixed value.
        Kept: Covert::Bounded,
        /// That no blob is kept under the name this call gave, and nothing else.
        Dropped: AuthZ::NoSecret,
        /// One fixed value.
        Dropped: Covert::Bounded,
        /// A failure of this call: its write lost the version race, or the store
        /// failed it.
        SessionError: AuthZ::NoSecret,
        /// A fixed value, never one the store fills in; what it failed on goes to
        /// the debug log.
        SessionError: Covert::Bounded,
        /// A failure of this call, which the store failed.
        CacheError: AuthZ::NoSecret,
        /// One fixed value; what the store failed on goes to the debug log.
        CacheError: Covert::Bounded,
    }
}

#[cfg(test)]
mod tests {
    use enclavid_boundary::declaration::Direction;

    use super::AnyCaller;

    /// What leaves is answered for `AuthZ` and `Covert` type by type, never for the
    /// whole block, and nothing leaves on the channel's word: this end names no
    /// peer.
    #[test]
    fn every_release_says_what_it_is_computed_from() {
        for crossing in AnyCaller::DECLARATION.crossings {
            assert!(
                crossing.answers.iter().all(|a| !a.every_type),
                "{}",
                crossing.ty
            );
            if crossing.direction == Direction::Out {
                assert!(!crossing.opens.contains(&"AuthN"), "{}", crossing.ty);
                for marker in ["AuthZ", "Covert"] {
                    assert!(
                        crossing.answers.iter().any(|a| a.marker == marker),
                        "{} leaves with no {marker} answer",
                        crossing.ty
                    );
                }
            }
        }
    }
}
