//! `enclavid oci push` — uploads an Enclavid artifact (a policy OR a
//! plugin wasm component) to an OCI registry as an `application/wasm`
//! layer, and beside it the files of its models, each a layer of its own.
//!
//! Role-agnostic: a policy and a plugin are the same kind of thing on
//! the wire. The artifact is self-contained (the `policy` / `plugin`
//! `embed` step welded the embedded declarations into the wasm
//! component as custom sections); push just ships the bytes. Integrity
//! is enforced TEE-side by re-verifying the layer digest on pull.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use engine_types::limits::MAX_MODEL_FILE_BYTES;
use oci_client::Reference;
use oci_client::annotations::ORG_OPENCONTAINERS_IMAGE_TITLE;
use oci_client::client::{Client, ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use enclavid_crypto::ocicrypt;

use crate::EncryptMode;
use crate::registry_auth;

#[cfg(test)]
mod tests;

/// Wasm layer media type — unified for policies and plugins. Matches
/// the TEE-side constant in `crates/api/src/policy_pull.rs::WASM_LAYER`
/// and `wkg`'s pull whitelist (see `[[project-wkg-wac-poc-findings]]`).
const WASM_LAYER_MEDIA_TYPE: &str = "application/wasm";
/// A model file's layer media type: a weight layer neither archived nor
/// compressed, as the CNCF ModelPack specification names one, a graph and
/// its data file alike. Matches `crates/api/src/policy_pull.rs::MODEL_LAYER`.
const MODEL_LAYER_MEDIA_TYPE: &str = "application/vnd.cncf.model.weight.v1.raw";
const POLICY_CONFIG_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.config.v1+json";
/// Keyprovider name for the KBS resource-URI annotation
/// (`org.opencontainers.image.enc.keys.provider.enclavid-kbs`).
const KBS_PROVIDER: &str = "provider.enclavid-kbs";

pub async fn run(
    artifact: PathBuf,
    reference: String,
    auth_override: Option<String>,
    encrypt: Option<EncryptMode>,
    kbs_resource: Option<String>,
    models: Option<PathBuf>,
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

    // The models' files go in the clear, so an encrypted artifact carries
    // none rather than one whose weights are readable beside it.
    if encrypt.is_some() && models.is_some() {
        bail!("model files cannot be encrypted: push them without --encrypt");
    }
    let model_layers = match &models {
        Some(dir) => model_layers(dir)?,
        None => Vec::new(),
    };

    let bytes =
        std::fs::read(&artifact).with_context(|| format!("reading {}", artifact.display()))?;

    // Plaintext (default) or ocicrypt-encrypted layer per `--encrypt`.
    let (layer_bytes, layer_media_type, layer_annotations) =
        build_layer(bytes, encrypt, kbs_resource.as_deref())?;
    let wasm_layer = ImageLayer::new(layer_bytes, layer_media_type, layer_annotations);
    let mut layers: Vec<ImageLayer> = vec![wasm_layer];
    layers.extend(model_layers);

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

    println!(
        "Pushed: {} → {}/{}:{}",
        artifact.display(),
        registry,
        repository,
        tag
    );
    for layer in &layers[1..] {
        let name = layer
            .annotations
            .as_ref()
            .and_then(|a| a.get(ORG_OPENCONTAINERS_IMAGE_TITLE))
            .map_or("", String::as_str);
        println!("  with {name} ({} bytes)", layer.data.len());
    }
    println!("Digest:     {digest}");
    println!("Pinned ref: {registry}/{repository}@{digest}");
    println!();
    println!("Use the pinned ref above as `policy` in POST /api/v1/sessions.");

    if tag != LATEST_TAG {
        let latest_ref =
            Reference::with_tag(registry.clone(), repository.clone(), LATEST_TAG.to_string());
        client
            .push(
                &latest_ref,
                &layers,
                config_blob,
                &auth_creds,
                Some(manifest),
            )
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

/// The model files in `dir` — every `<function>.onnx` and
/// `<function>.onnx.data` — each a layer of its own named for its file, in
/// the order of their names. None there is an error: `--models` names files
/// to push.
fn model_layers(dir: &Path) -> Result<Vec<ImageLayer>> {
    let files = crate::models::files(dir)?;
    if files.is_empty() {
        bail!(
            "no model files (`<function>.onnx`, `<function>.onnx.data`) in {}",
            dir.display()
        );
    }
    files
        .into_iter()
        .map(|(name, path)| {
            let len = std::fs::metadata(&path)
                .with_context(|| format!("reading {}", path.display()))?
                .len();
            if len > MAX_MODEL_FILE_BYTES {
                bail!(
                    "{}: past the {MAX_MODEL_FILE_BYTES} bytes a model file may hold",
                    path.display()
                );
            }
            let bytes =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let title = BTreeMap::from([(ORG_OPENCONTAINERS_IMAGE_TITLE.to_string(), name)]);
            Ok(ImageLayer::new(
                bytes,
                MODEL_LAYER_MEDIA_TYPE.to_string(),
                Some(title),
            ))
        })
        .collect()
}

fn detect_protocol(registry: &str) -> ClientProtocol {
    if registry.starts_with("localhost") || registry.starts_with("127.0.0.1") {
        ClientProtocol::Http
    } else {
        ClientProtocol::Https
    }
}

/// Build the wasm layer per the chosen encryption mode. Returns the layer
/// bytes, its media type, and the descriptor annotations.
///
/// Both modes produce the SAME standard-ocicrypt ciphertext + `enc.pubopts`
/// annotation; they differ only in how the layer key (the private-opts
/// JSON) reaches the TEE:
/// - `None` → plaintext `application/wasm`, no annotations (today's path).
/// - `inline` → prints the layer key (base64 private-opts JSON) for the
///   client to pass directly as `"key": "<base64>"` (owner == creator).
/// - `kbs` → writes the `--kbs-resource` URI into the `enc.keys.*`
///   annotation (digest-pinned, the TEE reads it to locate the key) and
///   prints the layer key to register as that KBS resource.
fn build_layer(
    bytes: Vec<u8>,
    encrypt: Option<EncryptMode>,
    kbs_resource: Option<&str>,
) -> Result<(Vec<u8>, String, Option<BTreeMap<String, String>>)> {
    let Some(mode) = encrypt else {
        return Ok((bytes, WASM_LAYER_MEDIA_TYPE.to_string(), None));
    };

    let (ciphertext, public, private) = ocicrypt::encrypt(&bytes);
    let mut annotations = BTreeMap::new();
    annotations.insert(
        ocicrypt::ANNOTATION_PUBOPTS.to_string(),
        ocicrypt::pubopts_to_annotation(&public).map_err(|e| anyhow!("pubopts: {e}"))?,
    );
    let priv_json = ocicrypt::privopts_to_json(&private).map_err(|e| anyhow!("privopts: {e}"))?;

    match mode {
        EncryptMode::Inline => {
            if kbs_resource.is_some() {
                bail!("--kbs-resource is only valid with --encrypt kbs");
            }
            println!(
                "Encrypted (ocicrypt {})",
                ocicrypt::CIPHER_AES256CTR_HMAC_SHA256
            );
            println!("Layer key (base64): {}", BASE64.encode(&priv_json));
            println!("  Pass it as  \"key\": \"<above>\"");
            println!("  in POST /api/v1/sessions (per policy / plugin). Keep it secret.");
        }
        EncryptMode::Kbs => {
            let resource = kbs_resource.ok_or_else(|| {
                anyhow!("--encrypt kbs requires --kbs-resource kbs:///<repo>/<type>/<tag>")
            })?;
            let rel = resource
                .strip_prefix("kbs:///")
                .ok_or_else(|| anyhow!("--kbs-resource must be kbs:///<repo>/<type>/<tag>"))?;
            if rel.split('/').filter(|p| !p.is_empty()).count() != 3 {
                bail!("--kbs-resource must be kbs:///<repo>/<type>/<tag>");
            }
            // The resource URI (not the key) goes in the artifact; it's
            // covered by the manifest digest the TEE pins, so it can't be
            // redirected. The key itself is registered out-of-band as that
            // KBS resource — the TEE fetches it under attestation.
            annotations.insert(
                format!("{}{}", ocicrypt::ANNOTATION_KEYS_PREFIX, KBS_PROVIDER),
                resource.to_string(),
            );
            let priv_json_str = String::from_utf8_lossy(&priv_json);
            println!(
                "Encrypted (ocicrypt {})",
                ocicrypt::CIPHER_AES256CTR_HMAC_SHA256
            );
            println!("Resource URI (in enc.keys annotation): {resource}");
            println!();
            println!("Register the layer key as that KBS resource (raw private-opts JSON):");
            println!("  {priv_json_str}");
            println!(
                "  e.g.  curl -X POST <kbs>/kbs/v0/resource/{rel} \\\n         \
                 -H \"Authorization: Bearer <admin-token>\" --data-binary '{priv_json_str}'"
            );
            println!();
            println!(
                "Then the client passes  \"key\": {{ \"kbs\": {{ \"endpoint\": \"<kbs>\" }} }}"
            );
            println!("  in POST /api/v1/sessions (per policy / plugin).");
        }
    }

    let media_type = format!(
        "{WASM_LAYER_MEDIA_TYPE}{}",
        ocicrypt::ENCRYPTED_MEDIA_SUFFIX
    );
    Ok((ciphertext, media_type, Some(annotations)))
}
