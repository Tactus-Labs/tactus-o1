use std::{env, fs, path::PathBuf};
fn digest(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    let mut h = blake2b_ref::Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    h.update(domain);
    h.update(data);
    h.finalize(&mut out);
    out
}
fn main() {
    let files = [
        "../../crates/tactus-o1-execution/rules-native-v2.txt",
        "../../crates/tactus-o1-execution/rules-v1.txt",
        "../../Cargo.lock",
        "../../contracts/bridge/NativeCKB.json",
    ];
    let mut descriptor = vec![];
    for path in files {
        println!("cargo:rerun-if-changed={path}");
        descriptor.extend_from_slice(&fs::read(path).unwrap());
    }
    let rules = digest(b"tactus/o1/native-execution-rules/v2", &descriptor);
    let path = "../../artifacts/tactus_o1_native_vault_script.elf";
    println!("cargo:rerun-if-changed={path}");
    let vault = digest(
        b"",
        &fs::read(path).expect("build pinned native vault first"),
    );
    let want = "3b0c9f82f019407ad1784fcf0d62fe695eba3cf235c2e8ce474af5aebbe39237";
    assert_eq!(
        vault.iter().map(|v| format!("{v:02x}")).collect::<String>(),
        want,
        "unexpected native vault executable"
    );
    let artifact: serde_json::Value = serde_json::from_slice(&fs::read(files[3]).unwrap()).unwrap();
    let d = &artifact["contract"]["evm"]["deployedBytecode"];
    let bytes: Vec<u8> = d["object"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let refs = d["immutableReferences"].as_object().unwrap();
    assert_eq!(refs.len(), 1);
    let offsets: Vec<usize> = refs
        .values()
        .next()
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            assert_eq!(v["length"], 32);
            let start = v["start"].as_u64().unwrap() as usize;
            assert_eq!(&bytes[start..start + 32], &[0; 32]);
            start
        })
        .collect();
    fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join("pinned.rs"),format!("pub const RULES:[u8;32]={rules:?};\npub const VAULT_CODE:[u8;32]={vault:?};\nconst RUNTIME:&[u8]=&{bytes:?};\nconst PATCHES:&[usize]=&{offsets:?};\n")).unwrap();
}
