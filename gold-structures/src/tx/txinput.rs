use crate::byte_reader::ByteReader;

use super::txid::Txid;
use crate::Result;
use secp256k1::ecdsa::Signature;

pub struct TxInput {
    pub txid: Txid,
    pub output_index: u8,
    pub sigs: Vec<Signature>,
}

impl TxInput {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.txid);
        buffer.push(self.output_index);
        buffer.push(self.sigs.len() as u8);

        for sig in self.sigs.iter() {
            buffer.extend_from_slice(&sig.serialize_compact());
        }

        buffer.into_boxed_slice()
    }

    pub fn serialize_without_sigs(&self) -> Box<[u8]> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.txid);
        buffer.push(self.output_index);

        buffer.into_boxed_slice()
    }

    pub fn deseralize_inputs_from_byte_reader(mut bytes: ByteReader) -> Result<Vec<TxInput>> {
        let mut inputs = Vec::new();

        while bytes.data_left() {
            let txid = bytes.read(32)?;
            let output_index = bytes.read(1)?[0];
            let sig_count = bytes.read(1)?[0] as usize;
            let mut sigs = Vec::new();

            for _ in 0..sig_count {
                let sig_bytes = bytes.read(64)?;
                sigs.push(Signature::from_compact(&sig_bytes)?);
            }

            inputs.push(TxInput {
                txid: Txid::new(&txid)?,
                output_index,
                sigs,
            })
        }

        Ok(inputs)
    }
}
