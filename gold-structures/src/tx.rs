use rand::{rngs::OsRng, Rng, RngCore};
use secp256k1::{
    ecdsa::Signature,
    hashes::{
        sha256::{self, Hash},
        Hash as HashTrait, HashEngine,
    },
    Message, PublicKey, Secp256k1, SecretKey,
};

pub mod txid;
pub mod txinput;
pub mod txoutput;

pub use txid::Txid;
pub use txinput::TxInput;
pub use txoutput::TxOutput;

use crate::{byte_reader::ByteReader, compact::to_compact_bytes};
use crate::{
    compact::{self, from_compact_bytes},
    Result,
};

#[derive(Debug)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

impl Transaction {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer: Vec<u8> = Vec::new();

        let mut input_data = Vec::new();

        for input in self.inputs.iter() {
            input_data.extend_from_slice(&input.serialize());
        }

        let mut output_data = Vec::new();

        for output in self.outputs.iter() {
            output_data.extend_from_slice(&output.serialize());
        }

        buffer.extend_from_slice(&to_compact_bytes(input_data.len()));
        buffer.extend_from_slice(&input_data);
        buffer.extend_from_slice(&to_compact_bytes(output_data.len()));
        buffer.extend_from_slice(&output_data);

        buffer.into_boxed_slice()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Transaction> {
        let byte_reader = ByteReader::new(bytes);
        Transaction::deserialize_from_byte_reader(&byte_reader)
    }

    pub fn deserialize_from_byte_reader(bytes: &ByteReader) -> Result<Transaction> {
        let inputs_byte_len = compact::from_byte_reader(bytes)?;
        let input_bytes = bytes.slice(inputs_byte_len)?;
        let inputs = TxInput::deseralize_inputs_from_byte_reader(input_bytes)?;

        let outputs_byte_len = compact::from_byte_reader(bytes)?;
        let output_bytes = bytes.slice(outputs_byte_len)?;
        let outputs = TxOutput::deseralize_outputs_from_byte_reader(output_bytes)?;

        Ok(Transaction { inputs, outputs })
    }

    // get_txid does not include inputs signature data. get_hash does include sig data
    pub fn get_txid(&self) -> Hash {
        let mut buffer = Vec::new();

        for input in self.inputs.iter() {
            buffer.extend(input.serialize_without_sigs());
        }

        for output in self.outputs.iter() {
            buffer.extend(output.serialize());
        }

        sha256::Hash::hash(&buffer)
    }

    pub fn sign(&self, sk: &SecretKey) -> Signature {
        let secp256k1 = secp256k1::Secp256k1::signing_only();
        secp256k1.sign_ecdsa(&Message::from_digest(self.get_txid().to_byte_array()), &sk)
    }

    pub fn get_hash(&self) -> Hash {
        let mut buffer = Vec::new();

        for input in self.inputs.iter() {
            buffer.extend(input.serialize());
        }

        for output in self.outputs.iter() {
            buffer.extend(output.serialize());
        }

        sha256::Hash::hash(&buffer)
    }

    pub fn merkle_root(txs: &Vec<Transaction>) -> Hash {
        if txs.len() == 0 {
            panic!("Attempted to get merkle root of size 0 Vec")
        }

        let mut txids: Vec<Hash> = txs.into_iter().map(|t| t.get_txid()).collect();

        if txids.len() % 2 == 1 {
            txids.push(txids[txids.len() - 1].clone());
        }

        let mut current_hashes = txids;

        while current_hashes.len() != 1 {
            let mut new_hashes: Vec<Hash> = vec![];

            for group in current_hashes.chunks(2) {
                let mut new_data = [0; 64];
                new_data[0..32].copy_from_slice(&group[0].to_byte_array());
                new_data[32..64].copy_from_slice(&group[1].to_byte_array());
                new_hashes.push(sha256::Hash::hash(&new_data));
            }

            current_hashes = new_hashes;
        }

        current_hashes[0]
    }
}
