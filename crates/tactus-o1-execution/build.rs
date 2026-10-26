use std::{env, fs, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let rules = root.join("rules-v1.txt");
    let lock = root.join("../../Cargo.lock");
    for input in [&rules, &lock] {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    let mut descriptor = fs::read(rules).expect("execution rules");
    descriptor.extend_from_slice(&fs::read(lock).expect("root dependency lock"));
    let hash = tactus_o1_protocol::batch::hash(b"tactus/o1/execution-rules/v1", &descriptor);
    let mut generated = format!("const EXECUTION_RULES_HASH: [u8; 32] = {hash:?};\n");
    if env::var_os("CARGO_FEATURE_V02").is_some() {
        let v02_rules = root.join("rules-v02.txt");
        let artifact = root.join("../../contracts/bridge/NativeCKB.json");
        for input in [&v02_rules, &artifact] {
            println!("cargo:rerun-if-changed={}", input.display());
        }
        let mut v02_descriptor = fs::read(v02_rules).expect("0.02 execution rules");
        v02_descriptor.extend_from_slice(&descriptor);
        v02_descriptor.extend_from_slice(&fs::read(artifact).expect("native bridge artifact"));
        let v02_hash =
            tactus_o1_protocol::batch::hash(b"tactus/0.02/execution-rules", &v02_descriptor);
        generated.push_str(&format!(
            "#[cfg(feature = \"v02\")]\nconst V02_EXECUTION_RULES_HASH: [u8; 32] = {v02_hash:?};\n"
        ));
    }
    if env::var_os("CARGO_FEATURE_NATIVE_BRIDGE").is_some() {
        let native_rules = root.join("rules-native-v2.txt");
        let artifact = root.join("../../contracts/bridge/NativeCKB.json");
        for input in [&native_rules, &artifact] {
            println!("cargo:rerun-if-changed={}", input.display());
        }
        let artifact_bytes = fs::read(artifact).expect("pinned native bridge artifact");
        let mut native_descriptor = fs::read(native_rules).expect("native execution rules");
        native_descriptor.extend_from_slice(&descriptor);
        native_descriptor.extend_from_slice(&artifact_bytes);
        let native_hash = tactus_o1_protocol::batch::hash(
            b"tactus/o1/native-execution-rules/v2",
            &native_descriptor,
        );
        let artifact: serde_json::Value =
            serde_json::from_slice(&artifact_bytes).expect("native bridge JSON");
        let deployed = &artifact["contract"]["evm"]["deployedBytecode"];
        let hex = deployed["object"].as_str().expect("native runtime hex");
        assert!(hex.len().is_multiple_of(2));
        let code: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("native runtime byte")
            })
            .collect();
        let references = deployed["immutableReferences"]
            .as_object()
            .expect("immutable references");
        assert_eq!(references.len(), 1, "one native DOMAIN immutable");
        let mut offsets = Vec::new();
        for patch in references.values().next().unwrap().as_array().unwrap() {
            assert_eq!(patch["length"], 32);
            let start = usize::try_from(patch["start"].as_u64().unwrap()).unwrap();
            assert_eq!(
                code.get(start..start.checked_add(32).unwrap()),
                Some([0u8; 32].as_slice())
            );
            assert!(offsets.iter().all(|&old: &usize| start.abs_diff(old) >= 32));
            offsets.push(start);
        }
        generated.push_str(&format!(
            "#[cfg(feature = \"native-bridge\")]\nconst NATIVE_EXECUTION_RULES_HASH: [u8; 32] = {native_hash:?};\n\
             #[cfg(feature = \"native-bridge\")]\nconst NATIVE_RUNTIME: &[u8] = &{code:?};\n\
             #[cfg(feature = \"native-bridge\")]\nconst NATIVE_DOMAIN_OFFSETS: &[usize] = &{offsets:?};\n"
        ));
    }
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("execution_rules.rs"),
        generated,
    )
    .expect("generated execution rules digest");
}
