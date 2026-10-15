//! Offline: rebuild the committed ground-truth tx and test whether MY message
//! construction verifies ITS signature. Pure local computation.
fn main() {
    use secp256k1::{ecdsa, Message, Secp256k1};
    use tactus_o1_devnet_driver::molecule;
    use tactus_o1_devnet_driver::rpc;
    use tactus_o1_ordering_script::{ckb_blake2b, ckb_blakeb160};

    let tx = rpc::call(
        "get_transaction",
        serde_json::json!(["0x336a247f0481f9dc88bda15e246fa22d0ddd7598e24873456129af60931ad1d5"]),
    )
    .unwrap()
    .get("transaction")
    .cloned()
    .unwrap();

    // Rebuild raw from the JSON.
    let hx = |s: &str| rpc::hex_to_bytes(s);
    let deps: Vec<Vec<u8>> = tx["cell_deps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let op = &d["out_point"];
            molecule::cell_dep(
                &molecule::out_point(
                    &hx(op["tx_hash"].as_str().unwrap()).try_into().unwrap(),
                    u32::from_str_radix(op["index"].as_str().unwrap().trim_start_matches("0x"), 16)
                        .unwrap(),
                ),
                if d["dep_type"] == "dep_group" { 1 } else { 0 },
            )
        })
        .collect();
    let inputs: Vec<Vec<u8>> = tx["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let op = &i["previous_output"];
            molecule::cell_input(
                0,
                &molecule::out_point(
                    &hx(op["tx_hash"].as_str().unwrap()).try_into().unwrap(),
                    u32::from_str_radix(op["index"].as_str().unwrap().trim_start_matches("0x"), 16)
                        .unwrap(),
                ),
            )
        })
        .collect();
    let outputs: Vec<Vec<u8>> = tx["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            let l = &o["lock"];
            let lock = molecule::script(
                &hx(l["code_hash"].as_str().unwrap()).try_into().unwrap(),
                if l["hash_type"] == "type" { 1 } else { 0 },
                &hx(l["args"].as_str().unwrap()),
            );
            let cap =
                u64::from_str_radix(o["capacity"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap();
            molecule::cell_output(cap, &lock, None)
        })
        .collect();
    let out_data: Vec<Vec<u8>> = tx["outputs_data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| molecule::bytes(&hx(d.as_str().unwrap())))
        .collect();
    let raw = molecule::raw_transaction(&deps, &inputs, &outputs, &out_data);
    let tx_hash = ckb_blake2b(&raw);
    println!("my tx_hash: {}", hex(&tx_hash));
    println!("real hash:  336a247f0481f9dc88bda15e246fa22d0ddd7598e24873456129af60931ad1d5");

    let witnesses: Vec<Vec<u8>> = tx["witnesses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| hx(w.as_str().unwrap()))
        .collect();
    let hdr = u32::from_le_bytes(witnesses[0][4..8].try_into().unwrap()) as usize;
    let llen = u32::from_le_bytes(witnesses[0][hdr..hdr + 4].try_into().unwrap()) as usize;
    let mut blank0 = witnesses[0].clone();
    for b in &mut blank0[hdr + 4..hdr + 4 + llen] {
        *b = 0;
    }
    let sig65 = witnesses[0][hdr + 4..hdr + 4 + llen].to_vec();

    // Variant A: u64 length prefixes for every witness.
    let mut buf = tx_hash.to_vec();
    buf.extend_from_slice(&(blank0.len() as u64).to_le_bytes());
    buf.extend_from_slice(&blank0);
    for w in &witnesses[1..] {
        buf.extend_from_slice(&(w.len() as u64).to_le_bytes());
        buf.extend_from_slice(w);
    }
    let secp = Secp256k1::new();
    let try_rec = |m: [u8; 32], tag: &str| {
        if let Ok(rec) = ecdsa::RecoverableSignature::from_compact(
            &sig65[..64],
            ecdsa::RecoveryId::from_i32(i32::from(sig65[64])).unwrap(),
        ) {
            if let Ok(pk) = secp.recover_ecdsa(&Message::from_digest_slice(&m).unwrap(), &rec) {
                println!(
                    "{tag}: recovered {} match={}",
                    hex(&ckb_blakeb160(&pk.serialize())),
                    ckb_blakeb160(&pk.serialize())[..]
                        == [
                            0xc1, 0x55, 0xc0, 0x11, 0x33, 0x55, 0xa0, 0x61, 0x17, 0x3d, 0x1f, 0xf2,
                            0x10, 0x75, 0xec, 0x37, 0x75, 0x4e, 0xc1, 0xca
                        ][..]
                );
                return;
            }
        }
        println!("{tag}: recover FAILED");
    };
    try_rec(ckb_blake2b(&buf), "A u64 lens");

    // Variant B: skip empty trailing witnesses entirely.
    let mut b2 = tx_hash.to_vec();
    b2.extend_from_slice(&(blank0.len() as u64).to_le_bytes());
    b2.extend_from_slice(&blank0);
    for w in &witnesses[1..] {
        if w.is_empty() {
            continue;
        }
        b2.extend_from_slice(&(w.len() as u64).to_le_bytes());
        b2.extend_from_slice(w);
    }
    try_rec(ckb_blake2b(&b2), "B skip empties");
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
