use std::time::Duration;

use secp256k1::hashes::sha256::Hash;

use crate::tx::Transaction;

pub struct Block {
    prev_block_hash: Hash,
    timestamp: Duration,
    merkle_root: Hash,
    nonce: u32,
    difficulty: usize,
    txs: Vec<Transaction>,
}
