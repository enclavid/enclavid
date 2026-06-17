//! `enclavid oci push` — uploads an Enclavid artifact (a policy OR a
//! plugin wasm component) to an OCI registry as a single
//! `application/wasm` layer.
//!
//! Role-agnostic: a policy and a plugin are the same kind of thing on
//! the wire. The artifact is self-contained (the `policy` / `plugin`
//! `embed` step welded the embedded declarations into the wasm
//! component as custom sections); push just ships the bytes. Integrity
//! is enforced TEE-side by re-verifying the layer digest on pull.

use anyhow::{Context, Result};
use oci_client::client::{Client, ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use oci_client::Reference;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::registry_auth;

/// Wasm layer media type — unified for policies and plugins. Matches
/// the TEE-side constant in `crates/api/src/policy_pull.rs::WASM_LAYER`
/// and `wkg`'s pull whitelist (see `[[project-wkg-wac-poc-findings]]`).
const WASM_LAYER_MEDIA_TYPE: &str = "application/wasm";
const POLICY_CONFIG_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.config.v1+json";

pub async fn run(
    artifact: PathBuf,
    reference: String,
    auth_override: Option<String>,
) -> Result<()> {
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
    let auth_creds = registry_auth::resolve(&registry, auth_override.as_deref()).await?;

    let bytes = std::fs::read(&artifact)
        .with_context(|| format!("reading {}", artifact.display()))?;

    let wasm_layer = ImageLayer::new(bytes, WASM_LAYER_MEDIA_TYPE.to_string(), None);
    let layers: Vec<ImageLayer> = vec![wasm_layer];

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

    let manifest = OciImageManifest::build(&layers, &config_blob, None);

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

    let digest = client
        .fetch_manifest_digest(&reference, &auth_creds)
        .await
        .context("fetching manifest digest from registry")?;

    println!("Pushed: {} → {}/{}:{}", artifact.display(), registry, repository, tag);
    println!("Digest:     {digest}");
    println!("Pinned ref: {registry}/{repository}@{digest}");
    println!();
    println!("Use the pinned ref above as `policy` in POST /api/v1/sessions.");

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
