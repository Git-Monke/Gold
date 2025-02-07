use gold::structs::*;
use gold::*;

use ripemd::{Digest, Ripemd160};
use secp256k1::rand::rngs::OsRng;
use secp256k1::Keypair;
use sha2::{Digest as ShaDigest, Sha256};

fn main() {
    let data = [1, 2, 3];
    let hash1 = Sha256::digest(data);
    let hash = Ripemd160::digest(hash1);
    println!("{:?}", hash);
}
