pub mod structs;
pub mod txn;

use secp256k1::rand::rngs::OsRng;
use secp256k1::{schnorr::Signature, Keypair};
use secp256k1::{PublicKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use structs::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

macro_rules! string_error {
    ( $string:literal ) => {
        Err($string.try_into().unwrap())
    };
}

// takes a valid new_block
fn push_block(new_block: &Block, utxo_set: &mut UtxoSet) {
    // validate new_block based on prev_block and utxo_set.
    // when a new block is pushed, functions can hook into this and take in data
    // this is how features like indexes will be implemented
}

// fn create_genesis_block() -> Block {
//     Block {
//         header: Header {
//             prev_block_hash: [0; 32],
//             merkle_root: todo!(),

//         }
//     }
// }

fn validate_block(
    new_block: &Block,
    prev_block: &Block,
    utxo_set: &mut UtxoSet,
    median_time: usize,
    target: [u8; 32],
) -> Result<()> {
    check_header_hash(new_block, target)?;
    check_prev_block_hash(new_block, prev_block)?;

    if new_block.header.timestamp <= median_time as u64 {
        return string_error!("Timestamp is not greater than median of last 10 blocks");
    }

    if calc_merkle_root(&new_block.txn_list) != new_block.header.merkle_root {
        return string_error!("Merkle root was invalid");
    }

    // check_txns(new_block, utxo_set)?;

    Ok(())
}

pub fn check_prev_block_hash(new_block: &Block, prev_block: &Block) -> Result<()> {
    let prev_block_hash = hash_header(&prev_block.header);

    // check the hash is what is included in new_block
    if prev_block_hash != new_block.header.prev_block_hash {
        return string_error!("Header previous block hash didn't match previous block");
    }

    Ok(())
}

// todo! Create a u256 number type.
// this function assumes target is in big-endian byte form
pub fn check_header_hash(new_block: &Block, target: [u8; 32]) -> Result<()> {
    let current_block_hash = hash_header(&new_block.header);

    for i in 0..32 {
        if target[i] < current_block_hash[i] {
            return string_error!("Header hash does not meet required difficulty");
        } else if target[i] > current_block_hash[i] {
            break;
        }
    }

    Ok(())
}

pub fn hash_header(block_header: &Header) -> [u8; 32] {
    let data = encode_header(block_header);
    let hash = sha2::Sha256::digest(data);
    hash.try_into().unwrap()
}

pub fn encode_header(header: &Header) -> [u8; 80] {
    let mut data = [0_u8; 80];

    data[0..32].copy_from_slice(&header.prev_block_hash[0..32]);
    data[32..64].copy_from_slice(&header.merkle_root[0..32]);
    data[64..72].copy_from_slice(&header.nonce.to_le_bytes());
    data[72..80].copy_from_slice(&header.timestamp.to_le_bytes());

    data
}

pub fn calc_merkle_root(txn_list: &Vec<Txn>) -> [u8; 32] {
    let mut hashes: Vec<[u8; 32]> = txn_list.iter().map(|txn| get_txn_hash(&txn)).collect();
    println!("{:?}", hashes);
    let mut new_hashes = vec![];

    while hashes.len() > 1 {
        for i in (0..hashes.len()).step_by(2) {
            let mut data = [0; 64];
            data[0..32].copy_from_slice(&hashes[i]);

            if i + 1 < hashes.len() {
                data[32..64].copy_from_slice(&hashes[i + 1]);
            } else {
                data[32..64].copy_from_slice(&hashes[i]);
            }

            new_hashes.push(sha2::Sha256::digest(data).try_into().unwrap());
        }

        hashes = new_hashes;
        new_hashes = vec![];
    }

    hashes[0]
}

pub fn get_txn_hash(txn: &Txn) -> [u8; 32] {
    let data = encode_txn(txn);
    let hash = sha2::Sha256::digest(data);
    hash.try_into().unwrap()
}

pub fn encode_txn(txn: &Txn) -> Vec<u8> {
    let mut data = Vec::new();

    data.push(txn.inputs.len() as u8);

    for input in txn.inputs.iter() {
        data.extend_from_slice(&input.output_txid);
        data.push(input.output_index as u8);
        data.extend(to_compact_int_bytes(input.unlocking_script.len()).iter());
        data.extend(input.unlocking_script.iter());
    }

    data.push(txn.outputs.len() as u8);

    for output in txn.outputs.iter() {
        data.extend(to_compact_int_bytes(output.locking_script.len()).iter());
        data.extend(output.locking_script.iter());
        data.extend(to_compact_int_bytes(output.amount as usize))
    }

    data
}

// ENCODE DATA THIS WAY WHEN SIGNING TRANSACTIONS
// When providing a signature for CHECKSIG and CHECKMULTISIG, you sign the data of the complete transaction
// However, the complete data also includes the sig itself. This creates a recursive dependency.
// If we don't include the input script into the txn, someone could theoretically change the input script data.
// Turns out this doesn't matter. Since we include the # inputs, # outputs, and all output data in our sigs, if someone tries to replace our script inputs
// They would ONLY be able to change the script inputs to another equally valid script, keeping the outputs the same. This means the txns have the same effect.
// In other words: We don't care if they change the input scripts. As long as they can't change anything else.
pub fn encode_txn_without_input_scripts(txn: &Txn) -> Vec<u8> {
    let mut data = Vec::new();

    data.push(txn.inputs.len() as u8);

    for input in txn.inputs.iter() {
        data.extend_from_slice(&input.output_txid);
        data.push(input.output_index as u8);
    }

    data.push(txn.outputs.len() as u8);

    for output in txn.outputs.iter() {
        data.extend(to_compact_int_bytes(output.locking_script.len()).iter());
        data.extend(output.locking_script.iter());
        data.extend(to_compact_int_bytes(output.amount as usize))
    }

    data
}

pub fn sign_transaction(txn: &Txn, keypair: &Keypair) -> Signature {
    let secp = secp256k1::Secp256k1::new();
    let data = encode_txn_without_input_scripts(txn);
    let hash = Sha256::digest(data);
    secp.sign_schnorr_with_rng(&hash, keypair, &mut OsRng)
}

pub fn check_txn_sig(txn: &Txn, sig: &Signature, pubkey: &XOnlyPublicKey) -> bool {
    let msg = Sha256::digest(encode_txn_without_input_scripts(txn));
    check_schnorr_sig(sig, &msg, pubkey)
}

pub fn check_schnorr_sig(sig: &Signature, msg: &[u8], pubkey: &XOnlyPublicKey) -> bool {
    let secp = secp256k1::Secp256k1::new();
    secp.verify_schnorr(sig, msg, pubkey).is_ok()
}

pub fn to_compact_int_bytes(n: usize) -> Vec<u8> {
    let bytes = n.to_le_bytes();

    match n {
        0..=252 => vec![bytes[0]],
        253..=0xFFFF => vec![253, bytes[0], bytes[1]],
        0x10000..=0xFFFFFFFF => vec![254, bytes[0], bytes[1], bytes[2], bytes[3]],
        _ => {
            let mut int = vec![255];
            int.extend(bytes.iter());
            int
        }
    }
}

fn check_txns(new_block: &Block, utxo_set: &UtxoSet) -> Result<()> {
    todo!()
}
