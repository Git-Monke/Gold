use secp256k1::{
    ecdsa::Signature,
    hashes::{
        sha256::{self, Hash},
        Hash as HashTrait,
    },
    PublicKey,
};

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

    pub fn from_bytes(bytes: &[u8]) -> Result<Transaction, Box<dyn std::error::Error>> {
        let byte_reader = ByteReader::new(bytes);
        let inputs_byte_len = byte_reader.read(1)?[0] as usize;
        let input_bytes = byte_reader.read(inputs_byte_len)?;
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

pub struct TxInput {
    pub txid: Hash,
    pub output_index: u8,
    pub sigs: Vec<Signature>,
}

// amount should be encoded as a compact size int
// max # of required sigs = 255, however the fees should get unfeasable at around 10+ required sigs.
pub struct TxOutput {
    pub amount: usize,
    pub new_owners: Vec<PublicKey>,
    pub required_sigs: u8,
}

impl TxInput {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(self.txid.as_byte_array());
        buffer.push(self.output_index);
        buffer.push(self.sigs.len() as u8);

        for sig in self.sigs.iter() {
            buffer.extend_from_slice(&sig.serialize_compact());
        }

        buffer.into_boxed_slice()
    }

    pub fn serialize_without_sigs(&self) -> Box<[u8]> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(self.txid.as_byte_array());
        buffer.push(self.output_index);

        buffer.into_boxed_slice()
    }

    pub fn deseralize_inputs_from_bytes(
        bytes: &[u8],
    ) -> Result<Vec<TxInput>, Box<dyn std::error::Error>> {
    }
}

impl TxOutput {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer = Vec::new();
        let amount = to_compact_bytes(self.amount);

        buffer.extend_from_slice(&amount);
        buffer.push(self.new_owners.len() as u8);

        for owner in self.new_owners.iter() {
            buffer.extend_from_slice(&owner.serialize());
        }

        buffer.push(self.required_sigs);

        buffer.into_boxed_slice()
    }
}
