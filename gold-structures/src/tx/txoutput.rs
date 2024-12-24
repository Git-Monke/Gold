use secp256k1::PublicKey;

use crate::compact::to_compact_bytes;

// amount should be encoded as a compact size int
// max # of required sigs = 255, however the fees should get unfeasable at around 10+ required sigs.
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
}
