use secp256k1::{ecdsa::Signature, PublicKey};

use crate::prelude::*;

use super::Txid;
use crate::utils::compact::Compact;
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

impl Transaction {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer = Vec::new();

        let input_data: Vec<Box<[u8]>> = self.inputs.iter().map(|t| t.serialize()).collect();
        let output_data: Vec<Box<[u8]>> = self.outputs.iter().map(|t| t.serialize()).collect();

        // compact
        buffer.extend_from_slice(Compact::to_compact(input_data.len() as u64).bytes());
        input_data.iter().for_each(|d| buffer.extend_from_slice(d));

        buffer.extend_from_slice(Compact::to_compact(output_data.len() as u64).bytes());
        output_data.iter().for_each(|d| buffer.extend_from_slice(d));

        buffer.into_boxed_slice()
    }
}

impl TxInput {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.txid);
        buffer.push(self.index);
        buffer.push(self.sigs.len() as u8);

        for sig in self.sigs.iter() {
            buffer.extend_from_slice(&sig.serialize_compact());
        }

        buffer.into_boxed_slice()
    }
}

impl TxOutput {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(Compact::to_compact(self.amount as u64).bytes());
        buffer.push(self.keys.len() as u8);

        for pk in self.keys.iter() {
            buffer.extend_from_slice(&pk.serialize());
        }

        buffer.push(self.sig_requirement as u8);

        buffer.into_boxed_slice()
    }
}
