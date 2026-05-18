use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use oci_client::client::{Client, ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use oci_client::Reference;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{policy_manifest, registry_auth};

const POLICY_LAYER_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.wasm.v1.encrypted";
const POLICY_MANIFEST_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.manifest.v1.json";
const POLICY_CONFIG_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.config.v1+json";

/// Manifest annotation key consumed by `POST /api/v1/sessions` for a
/// cheap (`<1 KB`) client_policy_key check against the artifact this
/// manifest describes. Value is base64-standard of the artifact's age
/// stream prefix — header (version line + recipient stanzas + MAC) +
/// 16-byte nonce — enough for `age::Decryptor::new()` to fully parse,
/// after which `.decrypt(identity)` performs the recipient-stanza
/// unwrap that proves the key matches.
///
/// Must match the constant on the api side
/// (`crates/api/src/policy_pull.rs::AGE_HEADER_ANNOTATION`).
const AGE_HEADER_ANNOTATION: &str = "com.enclavid.policy.age-header";

pub async fn run(
    artifact: PathBuf,
    reference: String,
    auth_override: Option<String>,
    manifest_path: PathBuf,
) -> Result<()> {
    // Parse the user-supplied OCI ref. If the user didn't include a
    // tag, default to a timestamp; that gets back into the reference
    // below so we can also push a `:latest` alias afterward.
    let parsed_ref = Reference::from_str(&reference)
        .with_context(|| format!("invalid OCI reference: {reference}"))?;
    let registry = parsed_ref.registry().to_string();
    let repository = parsed_ref.repository().to_string();
    let tag = parsed_ref
        .tag()
        .map(str::to_string)
        .unwrap_or_else(default_tag);
    let reference = Reference::with_tag(registry.clone(), repository.clone(), tag.clone());

    // Resolve registry credentials via the standard chain:
    //   --auth flag → ENCLAVID_REGISTRY_AUTH → ~/.docker/config.json
    // No Enclavid-specific carve-out — pushing to our Angos uses the
    // same path as pushing to ghcr / ECR / Docker Hub. `enclavid login`
    // wires the credHelper hook that keeps tokens fresh.
    let auth_creds = registry_auth::resolve(&registry, auth_override.as_deref()).await?;

    let bytes = std::fs::read(&artifact)
        .with_context(|| format!("reading {}", artifact.display()))?;

    // Snapshot the age stream prefix (header + 16-byte nonce) into a
    // manifest annotation. `POST /api/v1/sessions` reads it and runs
    // `age::Decryptor::new(prefix)?.decrypt(client_policy_key)` —
    // recipient-stanza unwrap succeeds iff the supplied key matches
    // the one the policy was encrypted to. No `--key` needed at push
    // time: the recipient is already crypto-baked into the file by
    // `enclavid policy encrypt`, we just lift the front of the stream.
    let age_header_b64 = extract_age_header(&bytes)
        .with_context(|| format!("extracting age header from {}", artifact.display()))?;
    let mut annotations = BTreeMap::new();
    annotations.insert(AGE_HEADER_ANNOTATION.to_string(), age_header_b64);

    // Optional policy manifest layer. Read + validate the
    // `policy.json` file; skip if absent (policy with no UI strings
    // — decision-only stubs). Validation errors abort the push so
    // the policy author sees the same problem here that the TEE
    // would trap on at first /connect.
    //
    // Ship the on-disk bytes verbatim: serde re-serialization could
    // reorder map keys, changing the layer digest. Content-addressing
    // means same source = same digest across pushes.
    let manifest_layer: Option<ImageLayer> = if manifest_path.is_file() {
        let parsed = policy_manifest::read(&manifest_path)?;
        let report = policy_manifest::validate(&parsed);
        for w in &report.warnings {
            println!("warning: {w}");
        }
        if !report.ok() {
            for e in &report.errors {
                println!("error: {e}");
            }
            anyhow::bail!(
                "manifest validation failed ({} error(s)) — run `enclavid policy validate {}` for full report",
                report.errors.len(),
                manifest_path.display(),
            );
        }
        let bytes = policy_manifest::read_bytes(&manifest_path)?;
        println!(
            "Manifest layer: {} byte(s), {} disclosure field(s), {} localized ref(s)",
            bytes.len(),
            parsed.disclosure_fields.len(),
            parsed.localized.len(),
        );
        Some(ImageLayer::new(
            bytes,
            POLICY_MANIFEST_MEDIA_TYPE.to_string(),
            None,
        ))
    } else {
        None
    };

    let wasm_layer = ImageLayer::new(bytes, POLICY_LAYER_MEDIA_TYPE.to_string(), None);
    let layers: Vec<ImageLayer> = std::iter::once(wasm_layer.clone())
        .chain(manifest_layer.clone())
        .collect();

    // Empty config blob — manifest digest depends only on layer content, not on
    // mutable metadata like name/tag. Discrimination of artifact kind is done
    // via the config descriptor's media type. Future metadata (signatures,
    // SBOMs, attestations) attaches via OCI Referrers, not this blob.
    let config_blob = Config::new(b"{}".to_vec(), POLICY_CONFIG_MEDIA_TYPE.to_string(), None);

    let client_config = ClientConfig {
        protocol: detect_protocol(&registry),
        ..Default::default()
    };
    let client = Client::new(client_config);

    let manifest = OciImageManifest::build(&layers, &config_blob, Some(annotations.clone()));

    client
        .push(
            &reference,
            &layers,
            config_blob.clone(),
            &auth_creds,
            Some(manifest.clone()),
        )
        .await
        .context("pushing OCI artifact")?;

    // Manifest digest = the value the consumer pins in
    // `POST /api/v1/sessions` (TEE only accepts `<repo>@sha256:<hex>`,
    // never tag form). Fetched from the registry via a separate HEAD
    // (`Docker-Content-Digest` header) rather than parsed out of the
    // push response's `Location` URL — some registries (Angos among
    // them) put the tag form there, not the digest form. Doing the
    // HEAD makes the output consistent across registries and avoids
    // local-recompute fallbacks (which could disagree with whatever
    // the registry actually stored).
    let digest = client
        .fetch_manifest_digest(&reference, &auth_creds)
        .await
        .context("fetching manifest digest from registry")?;

    println!("Pushed: {} → {}/{}:{}", artifact.display(), registry, repository, tag);
    println!("Digest:     {digest}");
    println!("Pinned ref: {registry}/{repository}@{digest}");
    println!();
    println!("Use the pinned ref above as `policy` in POST /api/v1/sessions.");

    // Always also point :latest at this manifest so consumers can request the
    // freshest revision without knowing the explicit tag. Skipped if the user
    // already used :latest as the explicit tag (no work to do).
    if tag != LATEST_TAG {
        let latest_ref = Reference::with_tag(registry.clone(), repository.clone(), LATEST_TAG.to_string());
        client
            .push(&latest_ref, &layers, config_blob, &auth_creds, Some(manifest))
            .await
            .context("retagging as :latest")?;
        println!("Also tagged: {}/{}:{}", registry, repository, LATEST_TAG);
    }

    Ok(())
}

/// Read just enough of the age stream (header + 16-byte nonce) for
/// `age::Decryptor::new()` to fully parse it on the TEE side. Returns
/// the prefix base64-encoded, ready to drop into a manifest annotation.
///
/// Implementation note: `Decryptor::new` consumes its reader through
/// the end of the nonce. We feed it a `Cursor` over the file bytes;
/// `cursor.position()` after the call is exactly the prefix length we
/// want — no manual scanning for `\n--- ` markers, no fixed-size
/// heuristic. Errors here surface real corruption (truncated header,
/// invalid stanza) before push uploads anything.
///
/// Rejects passphrase-encrypted streams: enclavid policy workflow is
/// always recipient-based (`enclavid policy keygen` produces an X25519
/// identity). A passphrase-encrypted file slipping through would
/// silently mean "anyone with the passphrase can mint sessions",
/// which is not the threat model.
fn extract_age_header(age_bytes: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(age_bytes);
    let decryptor = age::Decryptor::new(&mut cursor)
        .context("not a valid age stream — was the artifact produced by `enclavid policy encrypt`?")?;
    if decryptor.is_scrypt() {
        anyhow::bail!(
            "passphrase-encrypted artifact not supported — use `enclavid policy keygen` + `enclavid policy encrypt --key`"
        );
    }
    let prefix_len = cursor.position() as usize;
    Ok(BASE64.encode(&age_bytes[..prefix_len]))
}

const LATEST_TAG: &str = "latest";

fn default_tag() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("ts-{secs}")
}

fn detect_protocol(registry: &str) -> ClientProtocol {
    if registry.starts_with("localhost") || registry.starts_with("127.0.0.1") {
        ClientProtocol::Http
    } else {
        ClientProtocol::Https
    }
}
