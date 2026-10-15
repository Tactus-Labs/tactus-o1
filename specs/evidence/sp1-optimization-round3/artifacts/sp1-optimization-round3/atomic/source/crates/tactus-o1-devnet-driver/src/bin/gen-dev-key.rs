//! Generates the devnet-only secp256k1 key and prints its lock args
//! (blake160 of the compressed public key). Devnet tier only — never mainnet.

use secp256k1::{Secp256k1, SecretKey};
use tactus_o1_ordering_script::ckb_blakeb160;

fn main() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[0x21u8; 32]).expect("fixed dev key");
    let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let serialized = public.serialize();
    let args = ckb_blakeb160(&serialized);
    println!("privkey: 0x{}", hex(&[0x21u8; 32]));
    println!("pubkey:  0x{}", hex(&serialized));
    println!("blake160 args: 0x{}", hex(&args));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
