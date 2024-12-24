use secp256k1::PublicKey;

use crate::{byte_reader::ByteReader, compact::to_compact_bytes};
use crate::{compact, Result};

// amount should be encoded as a compact size int
// max # of required sigs = 255, however the fees should get unfeasable at around 10+ required sigs.
#[derive(Debug)]
pub struct TxOutput {
    pub amount: usize,
    pub new_owners: Vec<PublicKey>,
    pub required_sigs: u8,
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

    pub fn deseralize_outputs_from_byte_reader(bytes: ByteReader) -> Result<Vec<TxOutput>> {
        let mut outputs = Vec::new();

        while bytes.data_left() {
            let amount = compact::from_byte_reader(&bytes)?;
            let pk_count = bytes.read(1)?[0] as usize;
            let mut pks = Vec::new();

            for _ in 0..pk_count {
                let sig_bytes: [u8; 33] = bytes.read(33)?.try_into()?;
                pks.push(PublicKey::from_byte_array_compressed(&sig_bytes)?);
            }

            let required_sigs = bytes.read_byte()?;

            outputs.push(TxOutput {
                amount,
                new_owners: pks,
                required_sigs,
            })
        }

        Ok(outputs)
    }
}
