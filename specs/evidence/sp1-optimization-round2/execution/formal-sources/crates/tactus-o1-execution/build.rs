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
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("execution_rules.rs"),
        format!("const EXECUTION_RULES_HASH: [u8; 32] = {hash:?};\n"),
    )
    .expect("generated execution rules digest");
}
