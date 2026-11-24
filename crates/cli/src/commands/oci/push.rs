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
use oci_client::errors::OciDistributionError;
use oci_client::manifest::{OCI_IMAGE_MEDIA_TYPE, OciImageManifest};
use oci_client::secrets::RegistryAuth;
use reqwest::header::HeaderValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use enclavid_crypto::ocicrypt;

use crate::EncryptMode;
use crate::plain_http;
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

/// What `oci push` was asked.
pub struct Asked {
    pub artifact: PathBuf,
    /// `<registry>/<repository>[:tag]`.
    pub reference: String,
    pub auth: Option<String>,
    pub encrypt: Option<EncryptMode>,
    /// Where the layer key of `encrypt` goes: a new file, or `-` for stdout.
    pub key_out: Option<PathBuf>,
    pub kbs_resource: Option<String>,
    pub models: Option<PathBuf>,
    /// Print the pinned reference alone, for another command to read.
    pub quiet: bool,
}

/// Where what a push says goes: stdout, or stderr while stdout carries the
/// layer key.
#[derive(Clone, Copy)]
enum Say {
    Out,
    Err,
}

impl Say {
    fn line(self, text: impl std::fmt::Display) {
        match self {
            Say::Out => println!("{text}"),
            Say::Err => eprintln!("{text}"),
        }
    }
}

/// Push what `asked` names.
pub async fn run(asked: Asked) -> Result<()> {
    let Asked {
        artifact,
        reference,
        auth: auth_override,
        encrypt,
        key_out,
        kbs_resource,
        models,
        quiet,
    } = asked;
    let key_to_stdout = key_out.as_deref() == Some(Path::new("-"));
    if quiet && key_to_stdout {
        bail!("--quiet and --key-out - would both write to stdout: write the key to a file");
    }
    let say = if key_to_stdout { Say::Err } else { Say::Out };
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
    //   --auth flag → ENCLAVID_REGISTRY_AUTH → ~/.docker/config.json → none
    let auth_creds = registry_auth::resolve(&registry, auth_override.as_deref()).await?;
    let anonymous = matches!(auth_creds, RegistryAuth::Anonymous);
    // A refusal of a push made with no credentials says how to give some.
    let failed = |e: OciDistributionError, what: &'static str| {
        let wants_credentials = anonymous && registry_auth::needs_credentials(&e);
        let failed = anyhow::Error::from(e);
        if wants_credentials {
            failed.context(registry_auth::no_credentials_message(&registry))
        } else {
            failed.context(what)
        }
    };

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
    let layer = build_layer(bytes, encrypt, kbs_resource.as_deref())?;
    // The key is written before anything is pushed: a layer pushed under a
    // key that was then lost could never be read.
    let key_file = match (&layer.key, &key_out) {
        (Some(key), Some(out)) => write_key(out, key)?,
        (None, None) => None,
        _ => bail!("--key-out names where the key of --encrypt goes: give both or neither"),
    };
    let wasm_layer = ImageLayer::new(layer.bytes, layer.media_type, layer.annotations);
    let mut layers: Vec<ImageLayer> = vec![wasm_layer];
    layers.extend(model_layers);

    // Empty config blob — manifest digest depends only on layer content, not on
    // mutable metadata like name/tag. Discrimination of artifact kind is done
    // via the config descriptor's media type. Future metadata (signatures,
    // SBOMs, attestations) attaches via OCI Referrers, not this blob.
    let config_blob = Config::new(b"{}".to_vec(), POLICY_CONFIG_MEDIA_TYPE.to_string(), None);

    let client = Client::new(registry_client_config(&registry));

    // The manifest as the bytes pushed: what is pinned is their digest, never
    // what the tag names when read back, which another push to it may have
    // moved by then.
    let manifest = serde_json::to_vec(&OciImageManifest::build(&layers, &config_blob, None))
        .context("writing the manifest")?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest)));
    let pinned = format!("{registry}/{repository}@{digest}");

    let pushed = push_artifact(
        &client,
        &reference,
        &auth_creds,
        &layers,
        &config_blob,
        &manifest,
    )
    .await;
    if let Err(e) = pushed {
        // The push failed, so its key goes too: a retry may write the same
        // path.
        if let Some(file) = &key_file {
            let _ = std::fs::remove_file(file);
        }
        return Err(failed(e, "pushing OCI artifact"));
    }

    if !quiet {
        say.line(format_args!(
            "Pushed: {} → {}/{}:{}",
            artifact.display(),
            registry,
            repository,
            tag
        ));
        for layer in &layers[1..] {
            let name = layer
                .annotations
                .as_ref()
                .and_then(|a| a.get(ORG_OPENCONTAINERS_IMAGE_TITLE))
                .map_or("", String::as_str);
            say.line(format_args!("  with {name} ({} bytes)", layer.data.len()));
        }
        say.line(format_args!("Digest:     {digest}"));
        say.line(format_args!("Pinned ref: {pinned}"));
        say.line("");
        say.line("Use the pinned ref above as `--policy` of `enclavid session create`.");
        if let Some(mode) = encrypt {
            say.line("");
            say_key(say, mode, key_file.as_deref(), kbs_resource.as_deref());
        }
    }

    if tag != LATEST_TAG {
        let latest_ref =
            Reference::with_tag(registry.clone(), repository.clone(), LATEST_TAG.to_string());
        push_artifact(
            &client,
            &latest_ref,
            &auth_creds,
            &layers,
            &config_blob,
            &manifest,
        )
        .await
        .map_err(|e| failed(e, "retagging as :latest"))?;
        if !quiet {
            say.line(format_args!(
                "Also tagged: {}/{}:{}",
                registry, repository, LATEST_TAG
            ));
        }
    }

    if quiet {
        println!("{pinned}");
    }
    Ok(())
}

/// `layers` and `config`, then `manifest`, the bytes that name them, pushed
/// to `reference` with `auth`. The blobs go with each tag's push: a
/// registry may take a manifest only with the blobs pushed for it.
async fn push_artifact(
    client: &Client,
    reference: &Reference,
    auth: &RegistryAuth,
    layers: &[ImageLayer],
    config: &Config,
    manifest: &[u8],
) -> std::result::Result<(), OciDistributionError> {
    client
        .store_auth_if_needed(reference.resolve_registry(), auth)
        .await;
    for layer in layers {
        client
            .push_blob(reference, layer.data.clone(), &layer.sha256_digest())
            .await?;
    }
    client
        .push_blob(reference, config.data.clone(), &config.sha256_digest())
        .await?;
    client
        .push_manifest_raw(
            reference,
            manifest.to_vec(),
            HeaderValue::from_static(OCI_IMAGE_MEDIA_TYPE),
        )
        .await?;
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

/// The proxy a push to this machine names: nothing listens there, so a
/// request it is not exempt from fails instead of leaving in the clear.
const NO_PROXY_ADDRESS: &str = "http://127.0.0.1:0";

/// Every destination on this machine, as a proxy's exemption list.
const THIS_MACHINE: &str = "localhost,127.0.0.0/8,::1";

/// How `registry` is reached. One on this machine takes plain http and no
/// proxy, since a proxy from the environment would see its credentials and
/// the artifact in the clear. oci-client has no setting for no proxy at all,
/// but a client that names a proxy stops using the environment's, so it names
/// [`NO_PROXY_ADDRESS`] with this machine exempt.
fn registry_client_config(registry: &str) -> ClientConfig {
    let here = url::Url::parse(&format!("http://{registry}"))
        .ok()
        .and_then(|url| url.host().map(|host| plain_http::is_this_machine(&host)))
        .unwrap_or(false);
    if here {
        ClientConfig {
            protocol: ClientProtocol::Http,
            http_proxy: Some(NO_PROXY_ADDRESS.to_string()),
            no_proxy: Some(THIS_MACHINE.to_string()),
            ..Default::default()
        }
    } else {
        ClientConfig {
            protocol: ClientProtocol::Https,
            ..Default::default()
        }
    }
}

/// The wasm layer as pushed, and, when it is encrypted, its key.
struct Layer {
    bytes: Vec<u8>,
    media_type: String,
    annotations: Option<BTreeMap<String, String>>,
    /// The layer key in the form its mode takes it: for `inline`, base64, as
    /// the `"key"` of a session; for `kbs`, the private-opts JSON, as the
    /// resource's body.
    key: Option<Vec<u8>>,
}

/// Build the wasm layer per the chosen encryption mode.
///
/// Both modes produce the SAME standard-ocicrypt ciphertext + `enc.pubopts`
/// annotation; they differ only in how the layer key (the private-opts
/// JSON) reaches the TEE:
/// - `None` → plaintext `application/wasm`, no annotations (today's path).
/// - `inline` → the consumer passes the key, base64, as `"key": "<base64>"`
///   (owner == creator).
/// - `kbs` → writes the `--kbs-resource` URI into the `enc.keys.*`
///   annotation (digest-pinned, the TEE reads it to locate the key); the key
///   is registered as that KBS resource.
fn build_layer(
    bytes: Vec<u8>,
    encrypt: Option<EncryptMode>,
    kbs_resource: Option<&str>,
) -> Result<Layer> {
    // A resource given without `--encrypt kbs` would otherwise push the
    // layer in the clear, or under a key no KBS holds.
    if kbs_resource.is_some() && !matches!(encrypt, Some(EncryptMode::Kbs)) {
        bail!("--kbs-resource is only valid with --encrypt kbs");
    }
    let Some(mode) = encrypt else {
        return Ok(Layer {
            bytes,
            media_type: WASM_LAYER_MEDIA_TYPE.to_string(),
            annotations: None,
            key: None,
        });
    };

    let (ciphertext, public, private) = ocicrypt::encrypt(&bytes);
    let mut annotations = BTreeMap::new();
    annotations.insert(
        ocicrypt::ANNOTATION_PUBOPTS.to_string(),
        ocicrypt::pubopts_to_annotation(&public).map_err(|e| anyhow!("pubopts: {e}"))?,
    );
    let key = ocicrypt::privopts_to_json(&private).map_err(|e| anyhow!("privopts: {e}"))?;

    let key = match mode {
        EncryptMode::Inline => BASE64.encode(&key).into_bytes(),
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
            key
        }
    };

    Ok(Layer {
        bytes: ciphertext,
        media_type: format!(
            "{WASM_LAYER_MEDIA_TYPE}{}",
            ocicrypt::ENCRYPTED_MEDIA_SUFFIX
        ),
        annotations: Some(annotations),
        key: Some(key),
    })
}

/// Write the layer key to `out`: a new file, which only its owner may read,
/// or stdout for `-`. The file it wrote, when it wrote one.
fn write_key(out: &Path, key: &[u8]) -> Result<Option<PathBuf>> {
    if out == Path::new("-") {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(key)
            .and_then(|()| stdout.write_all(b"\n"))
            .context("writing the layer key to stdout")?;
        return Ok(None);
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(out).with_context(|| {
        format!(
            "creating {} for the layer key — it must not exist yet",
            out.display()
        )
    })?;
    file.write_all(key)
        .with_context(|| format!("writing the layer key to {}", out.display()))?;
    Ok(Some(out.to_path_buf()))
}

/// What the layer key of `mode`, in `key_file` or on stdout, is for — never
/// the key itself.
fn say_key(say: Say, mode: EncryptMode, key_file: Option<&Path>, kbs_resource: Option<&str>) {
    let place = match key_file {
        Some(file) => format!("is in {}", file.display()),
        None => "went to stdout".to_string(),
    };
    say.line(format_args!(
        "Encrypted (ocicrypt {}). The layer key {place}: keep it secret.",
        ocicrypt::CIPHER_AES256CTR_HMAC_SHA256
    ));
    match mode {
        EncryptMode::Inline => {
            say.line("Pass it, base64 already, as  \"key\": \"<the key>\"");
            say.line("  in POST /api/v1/sessions (per policy / plugin).");
        }
        EncryptMode::Kbs => {
            let Some(resource) = kbs_resource else {
                return;
            };
            let rel = resource.trim_start_matches("kbs:///");
            let data =
                key_file.map_or_else(|| "@-".to_string(), |file| format!("@{}", file.display()));
            say.line(format_args!("Register it as the KBS resource {resource}:"));
            say.line(format_args!(
                "  curl -X POST <kbs>/kbs/v0/resource/{rel} \\\n       \
                 -H \"Authorization: Bearer <admin-token>\" --data-binary {data}"
            ));
            say.line("Then the consumer passes  \"key\": { \"kbs\": { \"endpoint\": \"<kbs>\" } }");
            say.line("  in POST /api/v1/sessions (per policy / plugin).");
        }
    }
}
