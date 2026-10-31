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

/// A directory with no model files, or none at all, is an error: `--models`
/// names files to push.
#[test]
fn a_directory_of_no_model_files_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.md"), b"not a model").unwrap();
    assert!(model_layers(dir.path()).is_err());
    assert!(model_layers(&dir.path().join("absent")).is_err());
}
