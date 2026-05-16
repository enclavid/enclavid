use age::Encryptor;
use age::x25519::Identity;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use oci_client::client::{Client, ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::manifest::OciImageManifest;
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{auth, policy_manifest};

const POLICY_LAYER_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.wasm.v1.encrypted";
const POLICY_MANIFEST_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.manifest.v1.json";
const POLICY_CONFIG_MEDIA_TYPE: &str = "application/vnd.enclavid.policy.config.v1+json";

/// Manifest annotation key consumed by `POST /api/v1/sessions` to
/// validate the supplied K_client matches the artifact this manifest
/// describes. Must match the constant on the api side
/// (`crates/api/src/policy_pull.rs::VALIDATOR_ANNOTATION`).
const VALIDATOR_ANNOTATION: &str = "com.enclavid.policy.validator";
/// Plaintext that the validator decrypts to. Single byte; the actual
/// age envelope is hundreds of bytes regardless because of header
/// framing. Must match the constant on the api side
/// (`crates/api/src/policy_pull.rs::VALIDATOR_PLAINTEXT`).
const VALIDATOR_PLAINTEXT: &[u8] = &[1u8];

pub async fn run(
    artifact: PathBuf,
    reference: String,
    key: PathBuf,
    manifest_path: PathBuf,
) -> Result<()> {
    let access_token = auth::get_access_token().await?;

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

    let bytes = std::fs::read(&artifact)
        .with_context(|| format!("reading {}", artifact.display()))?;

    // Mint the validator annotation: a fresh age envelope around a
    // single byte, encrypted to the K_client's recipient. The session
    // create handler decrypts this with the K_client the platform
    // consumer hands it to confirm the right key without pulling the
    // whole artifact. Same `K_client` path the user passed to `encrypt`.
    let identity = read_identity(&key)
        .with_context(|| format!("reading key from {}", key.display()))?;
    let validator_b64 = mint_validator(&identity).context("minting validator annotation")?;
    let mut annotations = BTreeMap::new();
    annotations.insert(VALIDATOR_ANNOTATION.to_string(), validator_b64);

    // Optional policy manifest layer. Read + validate the
    // `policy.json` file; skip if absent (polici with no UI strings
    // — decision-only stubs). Validation errors abort the push so
    // the polici author sees the same problem here that the TEE
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
                "manifest validation failed ({} error(s)) — run `enclavid validate {}` for full report",
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

    let auth_creds = RegistryAuth::Bearer(access_token);

    let client_config = ClientConfig {
        protocol: detect_protocol(&registry),
        ..Default::default()
    };
    let client = Client::new(client_config);

    let manifest = OciImageManifest::build(&layers, &config_blob, Some(annotations.clone()));

    let response = client
        .push(
            &reference,
            &layers,
            config_blob.clone(),
            &auth_creds,
            Some(manifest.clone()),
        )
        .await
        .context("pushing OCI artifact")?;

    println!("Pushed: {} → {}/{}:{}", artifact.display(), registry, repository, tag);
    println!("Manifest: {}", response.manifest_url);

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

/// Read an age `Identity` (K_client) from the keygen output file.
/// Skips comment lines, takes the first AGE-SECRET-KEY-1 line.
fn read_identity(path: &PathBuf) -> Result<Identity> {
    let mut content = String::new();
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .read_to_string(&mut content)?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return Identity::from_str(trimmed)
            .map_err(|e| anyhow::anyhow!("invalid age identity in {}: {e}", path.display()));
    }
    anyhow::bail!("no AGE-SECRET-KEY-1 line found in {}", path.display())
}

/// Encrypt the validator plaintext to the K_client recipient and
/// return the base64-encoded age envelope (the manifest annotation
/// value).
fn mint_validator(identity: &Identity) -> Result<String> {
    let recipient = identity.to_public();
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .context("building age encryptor")?;
    let mut buf = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut buf)
        .context("initializing age writer")?;
    writer
        .write_all(VALIDATOR_PLAINTEXT)
        .context("writing validator plaintext")?;
    writer.finish().context("finalizing age envelope")?;
    Ok(BASE64.encode(&buf))
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
