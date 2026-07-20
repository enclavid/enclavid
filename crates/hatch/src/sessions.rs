//! Redis-backed session store handlers.
//!
//! Per-session typed fields. Scalar fields (status, metadata, state,
//! version) land in a single Redis hash `session:{id}`. List fields
//! (disclosure) live at `session:{id}:disclosure`.
//!
//! The TEE never sees these key shapes — it sends `BlobField` /
//! `ListField` wire enums; this module maps them to hash fields and
//! list keys. `write` is a single Lua script doing optimistic-
//! concurrency CAS + version increment + blob HSETs + list RPUSHes
//! atomically. A version mismatch surfaces as HTTP 412; the TEE's
//! read-then-write callers branch on it.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use redis::AsyncCommands;

use hatch_protocol::{
    BlobField, DeleteResponse, FieldSelector, ListField, ListSlot, Op, ReadRequest, ReadResponse,
    ScalarSlot, Slot, WriteRequest, WriteResponse,
};

use crate::AppState;
use crate::error::{HatchError, decode_body, encode_body};

fn hash_key(id: &str) -> String {
    format!("session:{id}")
}

fn list_key(id: &str, field: ListField) -> String {
    match field {
        ListField::Disclosure => format!("session:{id}:disclosure"),
    }
}

/// Per-session media hash: `session:{id}:media`, keyed by each blob's
/// content hash. Kept SEPARATE from the scalar hash so a whole-session media
/// purge is a single `DEL` (see [`delete_state`]) and the (large) sealed
/// captures don't bloat the field hash the hatch HMGETs on every read.
fn media_key(id: &str) -> String {
    format!("session:{id}:media")
}

fn blob_field_name(field: BlobField) -> &'static str {
    match field {
        BlobField::Status => "status",
        BlobField::Metadata => "metadata",
        BlobField::State => "state",
        // Plaintext principal for revocation/rate-limit/audit indexing.
        // TEE writes it at /sessions create via `SetPrincipal`; hatch
        // can query without TEE involvement.
        BlobField::Principal => "principal",
    }
}

fn internal(e: redis::RedisError) -> HatchError {
    HatchError::Internal(format!("store: {e}"))
}

fn parse_version(bytes: Option<&[u8]>) -> u64 {
    bytes
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Atomic CAS-write script. All three op kinds commit under ONE version CAS.
///
/// KEYS[1]        = session (scalar) hash key.
/// KEYS[2..1+L]   = the L list keys (one per RPUSH op, in op order).
/// KEYS[2+L]      = media hash key (present only when M > 0).
/// ARGV[1]        = expected_version: "" means "session must not exist",
///                  otherwise the stringified u64 the current version must equal.
/// ARGV[2]        = B = number of blob (field, value) HSET pairs.
/// ARGV[3 .. 2+2B]   = the B blob pairs interleaved (field, value, ...).
/// ARGV[3+2B]        = L = number of list appends.
/// ARGV[4+2B .. 3+2B+L] = the L list values, one per KEYS[2..1+L], same order.
/// ARGV[4+2B+L]      = M = number of media (blob-key, value) pairs.
/// ARGV[5+2B+L ..]   = the M media pairs interleaved (blob-key, value, ...),
///                     HSET into KEYS[2+L].
///
/// On success: bumps `version = old + 1`, HSETs the blob fields, RPUSHes each
/// list value, HSETs each media blob, and returns the new version. On
/// precondition failure: returns Lua error "version_mismatch" (HTTP 412).
const WRITE_SCRIPT: &str = r#"
local hash_key = KEYS[1]
local expected = ARGV[1]
local current = redis.call('HGET', hash_key, 'version')

if expected == '' then
  if current then
    return redis.error_reply('version_mismatch')
  end
elseif current ~= expected then
  return redis.error_reply('version_mismatch')
end

local new_version = (tonumber(current) or 0) + 1

-- Blobs: HSET into the session hash alongside the version bump.
local num_blobs = tonumber(ARGV[2])
local hset_args = {hash_key, 'version', tostring(new_version)}
for i = 0, num_blobs - 1 do
  table.insert(hset_args, ARGV[3 + i * 2])
  table.insert(hset_args, ARGV[3 + i * 2 + 1])
end
redis.call('HSET', unpack(hset_args))

-- Lists: RPUSH one value per list key (KEYS[2 .. 1+num_lists]).
local off = 3 + num_blobs * 2
local num_lists = tonumber(ARGV[off])
for i = 1, num_lists do
  redis.call('RPUSH', KEYS[1 + i], ARGV[off + i])
end

-- Media: keyed HSETs into the media hash (KEYS[2 + num_lists]).
off = off + num_lists + 1
local num_media = tonumber(ARGV[off])
if num_media > 0 then
  local margs = {KEYS[2 + num_lists]}
  for i = 0, num_media - 1 do
    table.insert(margs, ARGV[off + 1 + i * 2])
    table.insert(margs, ARGV[off + 1 + i * 2 + 1])
  end
  redis.call('HSET', unpack(margs))
end

return new_version
"#;

/// POST /sessions/{id}/read
pub async fn read(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, HatchError> {
    let req: ReadRequest = decode_body(&body)?;
    let mut conn = state.redis.clone();

    enum Resolved {
        Blob(&'static str),
        List(String),
        /// Blob-hash field within `session:{id}:media`.
        Media(Vec<u8>),
    }
    let resolved: Vec<Resolved> = req
        .fields
        .iter()
        .map(|sel| match sel {
            FieldSelector::Blob(b) => Resolved::Blob(blob_field_name(*b)),
            FieldSelector::List(l) => Resolved::List(list_key(&id, *l)),
            FieldSelector::Media(h) => Resolved::Media(h.clone()),
        })
        .collect();

    // Fast path: nothing requested → return version only (probe).
    if resolved.is_empty() {
        let hk = hash_key(&id);
        let version_str: Option<Vec<u8>> = conn.hget(&hk, "version").await.map_err(internal)?;
        let version = parse_version(version_str.as_deref());
        return encode_body(&ReadResponse {
            slots: Vec::new(),
            version,
        });
    }

    let blob_names: Vec<&str> = resolved
        .iter()
        .filter_map(|r| match r {
            Resolved::Blob(name) => Some(*name),
            _ => None,
        })
        .collect();

    // Fetch `version` alongside any requested blobs in one HMGET. No
    // MULTI/EXEC: Read promises only "hatch's current value per field",
    // matching the engine's per-op atomicity.
    let hk = hash_key(&id);
    let mut hget_fields: Vec<&str> = Vec::with_capacity(blob_names.len() + 1);
    hget_fields.push("version");
    hget_fields.extend(blob_names.iter().copied());

    let raw: Vec<Option<Vec<u8>>> = conn.hget(&hk, &hget_fields).await.map_err(internal)?;
    let version = parse_version(raw.first().and_then(|v| v.as_deref()));
    let mut blob_iter = raw.into_iter().skip(1);

    let mut slots = Vec::with_capacity(resolved.len());
    for sel in resolved {
        match sel {
            Resolved::Blob(_) => {
                let value = blob_iter.next().expect("blob_iter aligned with selectors");
                slots.push(Slot::Scalar(ScalarSlot { value }));
            }
            Resolved::List(key) => {
                let items: Vec<Vec<u8>> = conn.lrange(&key, 0, -1).await.map_err(internal)?;
                slots.push(Slot::List(ListSlot { items }));
            }
            Resolved::Media(field) => {
                let mk = media_key(&id);
                let value: Option<Vec<u8>> =
                    conn.hget(&mk, field.as_slice()).await.map_err(internal)?;
                slots.push(Slot::Scalar(ScalarSlot { value }));
            }
        }
    }

    encode_body(&ReadResponse { slots, version })
}

/// POST /sessions/{id}/write
pub async fn write(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, HatchError> {
    let req: WriteRequest = decode_body(&body)?;
    let mut conn = state.redis.clone();

    let mut blob_pairs: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let mut list_appends: Vec<(String, Vec<u8>)> = Vec::new();
    let mut media_pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for op in req.ops {
        match op {
            Op::Blob(b) => blob_pairs.push((blob_field_name(b.field), b.value)),
            Op::ListAppend(la) => list_appends.push((list_key(&id, la.field), la.value)),
            Op::MediaWrite(m) => media_pairs.push((m.blob_key, m.value)),
        }
    }

    let hk = hash_key(&id);
    let mk = media_key(&id);
    let expected_str = req
        .expected_version
        .map(|v| v.to_string())
        .unwrap_or_default();
    let num_blobs_str = blob_pairs.len().to_string();
    let num_lists_str = list_appends.len().to_string();
    let num_media_str = media_pairs.len().to_string();

    let script = redis::Script::new(WRITE_SCRIPT);
    let mut invocation = script.prepare_invoke();
    // KEYS: session hash, then list keys, then the media hash (only when
    // there are media writes — the Lua reads it as KEYS[2 + num_lists]).
    invocation.key(hk.as_str());
    for (key, _) in &list_appends {
        invocation.key(key.as_str());
    }
    if !media_pairs.is_empty() {
        invocation.key(mk.as_str());
    }
    invocation.arg(expected_str.as_str());
    invocation.arg(num_blobs_str.as_str());
    for (field, value) in &blob_pairs {
        invocation.arg(*field);
        invocation.arg(value.as_slice());
    }
    invocation.arg(num_lists_str.as_str());
    for (_, value) in &list_appends {
        invocation.arg(value.as_slice());
    }
    invocation.arg(num_media_str.as_str());
    for (key, value) in &media_pairs {
        invocation.arg(key.as_slice());
        invocation.arg(value.as_slice());
    }

    let result: Result<u64, redis::RedisError> = invocation.invoke_async(&mut conn).await;
    match result {
        Ok(new_version) => encode_body(&WriteResponse { new_version }),
        Err(e) => {
            if e.to_string().contains("version_mismatch") {
                Err(HatchError::VersionMismatch)
            } else {
                Err(HatchError::Internal(format!("store: {e}")))
            }
        }
    }
}

/// DELETE /sessions/{id}/state — the /reset path (non-CAS HDEL of the
/// State field). Also purges the whole session media hash: the captures were
/// sealed under the now-discarded applicant token, so they're already
/// unreadable, and a single `DEL` reclaims them. `deleted` reflects the State
/// field only (the caller's "was state present" signal).
pub async fn delete_state(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, HatchError> {
    let mut conn = state.redis.clone();
    let hk = hash_key(&id);
    let deleted: i64 = conn.hdel(&hk, "state").await.map_err(internal)?;
    let _: i64 = conn.del(media_key(&id)).await.map_err(internal)?;
    encode_body(&DeleteResponse {
        deleted: deleted.max(0) as u64,
    })
}

/// HEAD /sessions/{id} — existence check.
pub async fn exists(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, HatchError> {
    let mut conn = state.redis.clone();
    let hk = hash_key(&id);
    let exists: bool = conn.exists(&hk).await.map_err(internal)?;
    Ok(if exists {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    })
}
