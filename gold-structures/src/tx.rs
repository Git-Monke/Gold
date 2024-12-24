use secp256k1::{
    ecdsa::Signature,
    hashes::{
        sha256::{self, Hash},
        Hash as HashTrait,
    },
    PublicKey,
};

pub mod txid;
pub mod txinput;
pub mod txoutput;

pub use txid::Txid;
pub use txinput::TxInput;
pub use txoutput::TxOutput;

use crate::Result;
use crate::{byte_reader::ByteReader, compact::to_compact_bytes};

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

    pub fn from_bytes(bytes: &[u8]) -> Result<Transaction> {
        let byte_reader = ByteReader::new(bytes);
        let inputs_byte_len = byte_reader.read(1)?[0] as usize;
        let input_bytes = byte_reader.slice(inputs_byte_len)?;
        let inputs = TxInput::deseralize_inputs_from_byte_reader(input_bytes)?;
    }

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
}
