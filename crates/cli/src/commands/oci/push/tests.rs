use super::*;

/// Every model file in the directory is a layer of its own, of the model
/// media type, named for its file, in the order of their names; nothing else
/// there is pushed.
#[test]
fn each_model_file_is_a_layer_named_for_it() {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("split.onnx", &b"graph"[..]),
        ("age.onnx.data", b"weights"),
        ("age.onnx", b"age graph"),
        ("README.md", b"not a model"),
    ] {
        std::fs::write(dir.path().join(name), bytes).unwrap();
    }
    let layers = model_layers(dir.path()).unwrap();
    let named: Vec<(&str, &[u8])> = layers
        .iter()
        .map(|layer| {
            assert_eq!(layer.media_type, MODEL_LAYER_MEDIA_TYPE);
            let title = &layer.annotations.as_ref().unwrap()[ORG_OPENCONTAINERS_IMAGE_TITLE];
            (title.as_str(), &layer.data[..])
        })
        .collect();
    assert_eq!(
        named,
        [
            ("age.onnx", &b"age graph"[..]),
            ("age.onnx.data", b"weights"),
            ("split.onnx", b"graph"),
        ]
    );
}

/// A model file that is a link is refused, not followed: what is pushed is
/// never a file elsewhere a link points at.
#[test]
fn a_link_among_the_model_files_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("secret");
    std::fs::write(&elsewhere, b"not the vendor's").unwrap();
    std::fs::write(dir.path().join("age.onnx"), b"age graph").unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.path().join("age.onnx.data")).unwrap();
    assert!(model_layers(dir.path()).is_err());
}

/// A directory with no model files, or none at all, is an error: `--models`
/// names files to push.
#[test]
fn a_directory_of_no_model_files_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.md"), b"not a model").unwrap();
    assert!(model_layers(dir.path()).is_err());
    assert!(model_layers(&dir.path().join("absent")).is_err());
}

/// The key each mode gives opens the layer: base64 for `inline`, the JSON
/// itself for `kbs`, whose layer also names its resource.
#[test]
fn each_mode_gives_the_key_that_opens_its_layer() {
    let resource = "kbs:///acme/key/1";
    for (mode, kbs_resource) in [
        (EncryptMode::Inline, None),
        (EncryptMode::Kbs, Some(resource)),
    ] {
        let layer = build_layer(b"component".to_vec(), Some(mode), kbs_resource).unwrap();
        let key = layer.key.unwrap();
        let json = match mode {
            EncryptMode::Inline => BASE64.decode(&key).unwrap(),
            EncryptMode::Kbs => key,
        };
        let annotations = layer.annotations.unwrap();
        let public =
            ocicrypt::pubopts_from_annotation(&annotations[ocicrypt::ANNOTATION_PUBOPTS]).unwrap();
        let private = ocicrypt::privopts_from_json(&json).unwrap();
        assert_eq!(
            ocicrypt::decrypt(&layer.bytes, &public, &private).unwrap(),
            b"component"
        );
        let named = annotations.get(&format!(
            "{}{KBS_PROVIDER}",
            ocicrypt::ANNOTATION_KEYS_PREFIX
        ));
        assert_eq!(named.map(String::as_str), kbs_resource);
    }
}

/// A KBS resource goes with `--encrypt kbs` alone, and that one needs one of
/// the right shape: else a layer meant for a KBS would go in the clear, or
/// under a key no KBS holds.
#[test]
fn a_kbs_resource_goes_with_encrypt_kbs_alone() {
    let resource = Some("kbs:///acme/key/1");
    assert!(build_layer(b"c".to_vec(), None, resource).is_err());
    assert!(build_layer(b"c".to_vec(), Some(EncryptMode::Inline), resource).is_err());
    assert!(build_layer(b"c".to_vec(), Some(EncryptMode::Kbs), None).is_err());
    assert!(
        build_layer(
            b"c".to_vec(),
            Some(EncryptMode::Kbs),
            Some("kbs:///acme/key")
        )
        .is_err()
    );
    let plain = build_layer(b"c".to_vec(), None, None).unwrap();
    assert_eq!(plain.media_type, WASM_LAYER_MEDIA_TYPE);
    assert!(plain.key.is_none());
}

/// The key file is a new one only its owner may read; one already there is
/// never written over.
#[test]
fn a_key_file_is_new_and_its_owners_alone() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("key");
    assert_eq!(write_key(&out, b"secret").unwrap(), Some(out.clone()));
    let mode = std::fs::metadata(&out).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(write_key(&out, b"another").is_err());
    assert_eq!(std::fs::read(&out).unwrap(), b"secret");
}

/// A registry on this machine takes plain http and no proxy; any other takes
/// https, a name that merely begins like this machine's included.
#[test]
fn plain_http_goes_to_a_registry_on_this_machine_alone() {
    for registry in [
        "localhost:5000",
        "localhost",
        "127.0.0.1:5000",
        "[::1]:5000",
    ] {
        let config = registry_client_config(registry);
        assert_eq!(config.protocol, ClientProtocol::Http, "{registry}");
        assert_eq!(
            config.http_proxy.as_deref(),
            Some(NO_PROXY_ADDRESS),
            "{registry}"
        );
        assert_eq!(config.no_proxy.as_deref(), Some(THIS_MACHINE), "{registry}");
    }
    for registry in [
        "localhost.example.com:5000",
        "127.0.0.1.example.com",
        "ghcr.io",
        "10.0.0.1:5000",
    ] {
        let config = registry_client_config(registry);
        assert_eq!(config.protocol, ClientProtocol::Https, "{registry}");
        assert!(config.http_proxy.is_none(), "{registry}");
    }
}
