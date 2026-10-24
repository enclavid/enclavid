//! api's end of the storage leg, declared.
//!
//! Reviewer grep guide:
//!
//!   * `Storage::expose_builder` / `Storage::expose` — every value built or
//!     opened to leave for the volume.
//!   * `trust(` / `trust_with(` / `trust_accept_risk(` and `vouch(` /
//!     `vouch_with(` / `vouch_accept_risk(` — how each concern left open here
//!     gets answered.

use enclavid_boundary::{AuthN, AuthZ, Covert, Replay};
use enclavid_boundary_macros::boundary;
use storage_rpc::{
    BlobName, BlobStream, CacheBlob, CacheError, DisclosureOp, Dropped, Expected, Fields, Kept,
    MediaName, MediaOp, MetadataOp, Ops, RecordName, ResetOp, SessionError, Slot, StateOp, Version,
};

boundary! {
    /// The storage-CVM, over one RA-TLS leg api pins and the host splices — and
    /// taken for the volume it keeps everything on.
    ///
    /// The CVM is our own build and keeps what it is handed unread. But it keeps
    /// it on a volume the host provisions and reads, and can change or put an
    /// older copy back on. So api judges this leg as the host's disk: what leaves
    /// is written where the host reads it, and what arrives was read back from
    /// where the host could have changed it. The pin answers for nothing here.
    ///
    /// A name is derived where it is minted, under a key only api holds, so the
    /// volume holds no session id, no capture's hash and no composition. A read
    /// leaves as the fields it asks for, a write as its parts — its ops, each of
    /// its own kind, and what the record must be — and a blob as its stream. The
    /// doors build the requests and the blob that cross from these, and take a
    /// read's and a write's responses apart, so what is declared and judged here
    /// is each part, each slot and the version.
    pub Storage {
        calls: [storage_rpc::RemoteSessionStore, storage_rpc::RemoteCache],
        observer: HostKeeps,
    }

    out (AuthN, AuthZ, Covert) {
        /// Derived from the session id, so a call can name only the record of the
        /// session it serves.
        RecordName: AuthZ::Scoped,
        /// Derived from a session id the TEE minted at random: no party with
        /// something to leak picked it.
        RecordName: Covert::NotChosen,
        /// The cache is api's own, shared by every session's compiles: there is no
        /// party to authorize.
        BlobName: AuthZ::NoPrincipal,
        /// A keyed digest, so all its reader can tell of one is whether it has seen
        /// it before; and a new one comes only with a compile.
        BlobName: Covert::Bounded,
        /// Derived from the session and the capture, so a read or a write can name
        /// only a blob of the session it serves.
        MediaName: AuthZ::Scoped,
        /// Derived from a frame the applicant uploaded to this session: no party
        /// with something to leak picked it.
        MediaName: Covert::NotChosen,
        /// Field tags, and media names each answered where it was derived.
        Fields<Storage>: AuthN::Indifferent,
        /// Which fields of the record its call names: nothing the store does not
        /// keep.
        Fields<Storage>: AuthZ::NoSecret,
        /// Field tags each route fixes, or the name of one of the session's own
        /// captures, which a policy picks among the few its applicant made.
        Fields<Storage>: Covert::Bounded,
        /// Sealed under a key only api holds: the store keeps what opens nowhere
        /// else.
        MetadataOp: AuthZ::NoSecret,
        /// Sealed under the session's own applicant token, inside a key only api
        /// holds: the store keeps what opens only for that session.
        StateOp: AuthZ::NoSecret,
        /// Sealed as a state is, under the session's own applicant token inside a
        /// key only api holds.
        MediaOp: AuthZ::NoSecret,
        DisclosureOp,
        /// Carries no bytes, only that a record's applicant data goes.
        ResetOp: AuthN::Indifferent,
        /// Drops the data of the one record its write names.
        ResetOp: AuthZ::Scoped,
        /// One fixed op, with nothing filled in.
        ResetOp: Covert::Bounded,
        /// No bytes of its own: each op in it was answered for itself before it was
        /// added.
        Ops<Storage>: AuthN::Indifferent,
        /// Started for the one record it lands in, the record of the session every
        /// op in it was sealed for.
        Ops<Storage>: AuthZ::Scoped,
        /// The version the store returned, or a create's deadline: the store's own
        /// counter, or the time the host watched the create happen at plus the
        /// lifetime its terms gave.
        Expected: AuthN::Indifferent,
        /// Nothing the store does not hold, or watch happen.
        Expected: AuthZ::NoSecret,
        /// The host counts every write it watches land, and watched the create:
        /// both are what it holds already.
        Expected: Covert::AlreadyHeld,
        /// The cache is api's own, shared by every session's compiles: there is no
        /// party to authorize.
        BlobStream: AuthZ::NoPrincipal,
        /// Its length is a function of what it is a compile of — the composition
        /// the consumer pinned, which the host watched pulled — and carries
        /// nothing of an applicant's.
        BlobStream: Covert::AlreadyHeld,
    }

    in (AuthN, AuthZ, Replay) {
        Slot,
        /// Fed back only as the version a write expects: any value makes that write
        /// land or refuse, and nothing else is decided on it.
        Version: AuthN::Indifferent,
        /// A return value on this side's own call, which grants nothing.
        Version: AuthZ::NoPrincipal,
        /// A return value on this side's own call, from api's own cache of
        /// compiles: there is no party to authorize.
        Option<CacheBlob>: AuthZ::NoPrincipal,
        /// Named by what it is a compile of, and sealed to that name: an older blob
        /// is a compile of the same composition for the same runtime, and acts as
        /// the latest one does.
        Option<CacheBlob>: Replay::Idempotent,
    }

    in (AuthN, AuthZ) {
        /// One fixed value, on which nothing is decided: a later load is judged on
        /// its own.
        Kept: AuthN::Indifferent,
        /// A return value on this side's own call.
        Kept: AuthZ::NoPrincipal,
        /// One fixed value, on which nothing is decided: a blob that stays loads as
        /// what it is, or is found bad again.
        Dropped: AuthN::Indifferent,
        /// A return value on this side's own call.
        Dropped: AuthZ::NoPrincipal,
        /// Each case ends the call as it says — the version race lost, which the
        /// caller refuses or reads again on; the store failing, whose text reaches
        /// only the debug log; or a write the door refused as too large, which no
        /// store sent.
        SessionError: AuthN::Indifferent,
        /// A return value on this side's own call.
        SessionError: AuthZ::NoPrincipal,
        /// One case, the cache failing, which ends the call as a miss or an unkept
        /// blob does; its text reaches only the debug log.
        CacheError: AuthN::Indifferent,
        /// A return value on this side's own call.
        CacheError: AuthZ::NoPrincipal,
    }
}

#[cfg(test)]
mod tests {
    use enclavid_boundary::declaration::Direction;

    use super::Storage;

    /// The pin answers nothing on a leg taken for the host's disk: no answer is
    /// given for every type, and every value read back has `AuthN` open on it
    /// until it is opened, or answered for its type.
    #[test]
    fn the_pin_answers_nothing_on_the_host_s_disk() {
        for crossing in Storage::DECLARATION.crossings {
            assert!(
                crossing.answers.iter().all(|a| !a.every_type),
                "{}",
                crossing.ty
            );
            assert!(
                crossing.answers.iter().all(|a| a.kind != "Identified"),
                "{}",
                crossing.ty
            );
            if crossing.direction == Direction::In {
                assert!(crossing.opens.contains(&"AuthN"), "{}", crossing.ty);
            }
        }
    }

    /// What is left on a type for the site that holds a value of it.
    fn left(ty: &str) -> &'static [&'static str] {
        Storage::DECLARATION
            .crossings
            .iter()
            .find(|c| c.ty == ty)
            .unwrap_or_else(|| panic!("{ty} is declared"))
            .left
    }

    /// A name leaves with its confidentiality left to the mint, which derives it
    /// under a key only api holds — never answered here for the type.
    #[test]
    fn a_name_is_answered_where_it_is_derived() {
        for name in ["RecordName", "MediaName", "BlobName"] {
            assert_eq!(left(name), ["AuthN"], "{name}");
        }
    }

    /// Whatever leaves with bytes of its own is sealed where it is built: no
    /// declaration line answers who may read it.
    #[test]
    fn what_carries_bytes_is_sealed_where_it_is_built() {
        for ty in [
            "MetadataOp",
            "StateOp",
            "MediaOp",
            "DisclosureOp",
            "BlobStream",
        ] {
            assert!(left(ty).contains(&"AuthN"), "{ty}");
        }
    }

    /// How many ops a write makes, and of which kinds, is its caller's to
    /// answer: the set leaves only that open.
    #[test]
    fn a_write_leaves_its_count_to_its_caller() {
        assert_eq!(left("Ops<Storage>"), ["Covert"]);
        assert!(left("Expected").is_empty());
        assert!(left("ResetOp").is_empty());
    }

    /// The doors build both requests and the blob, and take both responses
    /// apart: this end declares what they take and hand back. That it declares
    /// nothing it never holds is held by the test `boundary!` writes for it.
    #[test]
    fn this_end_declares_what_its_doors_take() {
        let d = Storage::DECLARATION;
        let calls: Vec<_> = d.calls.iter().map(|p| p.name).collect();
        assert_eq!(calls, ["RemoteSessionStore", "RemoteCache"]);
        let methods: Vec<_> = d.calls.iter().flat_map(|p| p.methods).collect();
        assert!(methods.iter().all(|m| m.door.is_some()));
        let write = methods.iter().find(|m| m.name == "write").expect("a write");
        assert_eq!(write.args, ["RecordName", "WriteRequest"]);
        let door = write.door.as_ref().expect("its door");
        assert_eq!(door.sends, ["Expected", "Ops<Self>"]);
        assert_eq!(door.receives, ["Version"]);
    }
}
