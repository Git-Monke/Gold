use secp256k1::{ecdsa::Signature, PublicKey};

mod error;
mod prelude;
mod utils;

// These aliases are so the code can describe itself. They get optimized away at compile time.
type HashAsBytes = [u8; 32];
type Txid = [u8; 32];

pub struct Block {
    header: Header,
    tx_list: Vec<Transaction>,
}

pub struct Header {
    prev_block_hash: HashAsBytes,
    timestamp: u32,
    merkle_root: HashAsBytes,
    nonce: u32,
}

pub struct Transaction {
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
}

pub struct TxInput {
    txid: Txid,
    index: u8,
    sigs: Vec<Signature>,
}

pub struct TxOutput {
    amount: usize,
    keys: Vec<PublicKey>,
    sig_requirement: usize,
}
