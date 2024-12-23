use secp256k1::{ecdsa::Signature, hashes::sha256::Hash, PublicKey};

pub struct Transaction {
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
}

pub struct TxInput {
    txid: Hash,
    output_index: usize,
    sigs: Vec<Signature>,
}

// amount should be encoded as a compact size int
// max # of required sigs = 255, however the fees should get unfeasable at around 10+ required sigs.
pub struct TxOutput {
    amount: u64,
    new_owners: Vec<PublicKey>,
    required_sigs: u8,
}
