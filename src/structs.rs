pub struct Block {
    pub header: Header,
    pub txn_list: Vec<Txn>,
}

pub struct Header {
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub nonce: u64,
    pub timestamp: u64,
}

#[derive(Clone)]
pub struct Txn {
    pub inputs: Vec<TxnInput>,
    pub outputs: Vec<TxnOutput>,
}

// output_txid is the txid of the referenced Utxo
#[derive(Clone)]
pub struct TxnInput {
    pub output_txid: [u8; 32],
    pub output_index: usize,
    pub unlocking_script: Vec<u8>,
}

#[derive(Clone)]
pub struct TxnOutput {
    pub locking_script: Vec<u8>,
    pub amount: u64,
}

pub type UtxoSet = std::collections::HashMap<[u8; 32], Vec<Utxo>>;

pub struct Utxo {
    pub txn_output: TxnOutput,
    pub block_height: usize,
    pub block_time: usize,
}
