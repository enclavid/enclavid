//! `enclavid oci push` — uploads an Enclavid artifact (a policy OR a
//! plugin wasm component) to an OCI registry as a single
//! `application/wasm` layer.
//!
//! Role-agnostic: a policy and a plugin are the same kind of thing on
//! the wire. The artifact is self-contained (the `policy` / `plugin`
//! `embed` step welded the embedded declarations into the wasm
//! component as custom sections); push just ships the bytes. Integrity
//! is enforced TEE-side by re-verifying the layer digest on pull.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use oci_client::client::{Client, ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use oci_client::Reference;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use broker_protocol::SealedBlob;
use enclavid_crypto::kbswrap;
use enclavid_crypto::ocicrypt;

use crate::EncryptMode;
use crate::registry_auth;

/// Wasm layer media type — unified for policies and plugins. Matches
/// the TEE-side constant in `crates/api/src/policy_pull.rs::WASM_LAYER`
/// and `wkg`'s pull whitelist (see `[[project-wkg-wac-poc-findings]]`).
const WASM_LAYER_MEDIA_TYPE: &str = "application/wasm";
const POLICY_CONFIG_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.config.v1+json";
/// Keyprovider name for the KBS-wrapped layer key annotation
/// (`org.opencontainers.image.enc.keys.provider.enclavid-kbs`).
const KBS_PROVIDER: &str = "provider.enclavid-kbs";

pub async fn run(
    artifact: PathBuf,
    reference: String,
    auth_override: Option<String>,
    encrypt: Option<EncryptMode>,
    kbs_pubkey: Option<String>,
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

    // Plaintext (default) or ocicrypt-encrypted layer per `--encrypt`.
    let (layer_bytes, layer_media_type, layer_annotations) =
        build_layer(bytes, encrypt, kbs_pubkey.as_deref())?;
    let wasm_layer = ImageLayer::new(layer_bytes, layer_media_type, layer_annotations);
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

/// Build the wasm layer per the chosen encryption mode. Returns the layer
/// bytes, its media type, and the descriptor annotations.
///
/// - `None` → plaintext `application/wasm`, no annotations (today's path).
/// - `inbound` → ocicrypt-encrypted; prints the layer key (base64
///   private-opts JSON) for the client to pass as `key_source.inbound`.
/// - `kbs` → ocicrypt-encrypted; seals the layer key to `--kbs-pubkey`
///   and stores it in the `enc.keys.provider.enclavid-kbs` annotation.
fn build_layer(
    bytes: Vec<u8>,
    encrypt: Option<EncryptMode>,
    kbs_pubkey: Option<&str>,
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
            if kbs_pubkey.is_some() {
                bail!("--kbs-pubkey is only valid with --encrypt kbs");
            }
            println!("Encrypted (ocicrypt {})", ocicrypt::CIPHER_AES256CTR_HMAC_SHA256);
            println!("Layer key (base64): {}", BASE64.encode(&priv_json));
            println!("  Pass it as  \"key\": \"<above>\"");
            println!("  in POST /api/v1/sessions (per policy / plugin). Keep it secret.");
        }
        EncryptMode::Kbs => {
            let pk = kbs_pubkey
                .ok_or_else(|| anyhow!("--encrypt kbs requires --kbs-pubkey <base64 X25519>"))?;
            let pk_bytes: [u8; 32] = BASE64
                .decode(pk)
                .context("--kbs-pubkey base64")?
                .try_into()
                .map_err(|_| anyhow!("--kbs-pubkey must be 32 bytes"))?;
            let sealed =
                kbswrap::seal(&pk_bytes, &priv_json).map_err(|e| anyhow!("kbs seal: {e}"))?;
            let blob = SealedBlob {
                sender_pub: sealed.sender_pub.to_vec(),
                nonce: sealed.nonce.to_vec(),
                ciphertext: sealed.ciphertext,
            };
            let blob_bytes = broker_protocol::encode(&blob).map_err(|e| anyhow!("encode: {e}"))?;
            annotations.insert(
                format!("{}{}", ocicrypt::ANNOTATION_KEYS_PREFIX, KBS_PROVIDER),
                BASE64.encode(&blob_bytes),
            );
            println!("Encrypted (ocicrypt {})", ocicrypt::CIPHER_AES256CTR_HMAC_SHA256);
            println!("Layer key sealed to the KBS public key.");
            println!("  Pass  \"key\": {{ \"kbs\": {{ \"endpoint\", \"pubkey\", \"token\" }} }}");
            println!("  in POST /api/v1/sessions (per policy / plugin).");
        }
    }

    let media_type = format!("{WASM_LAYER_MEDIA_TYPE}{}", ocicrypt::ENCRYPTED_MEDIA_SUFFIX);
    Ok((ciphertext, media_type, Some(annotations)))
}
