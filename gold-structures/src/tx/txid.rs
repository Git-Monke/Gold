use crate::Result;
use std::ops::Deref;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]

pub struct Txid(pub [u8; 32]);

impl Deref for Txid {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Txid {
    pub fn new(bytes: &[u8]) -> Result<Txid> {
        if bytes.len() != 32 {
            return Err(format!(
                "Txid must have exactly 32 bytes: {} were provided: {:?}",
                bytes.len(),
                bytes
            )
            .try_into()?);
        }

        Ok(Txid(bytes[0..32].try_into().unwrap()))
    }
}

impl AsRef<[u8]> for Txid {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self))
    }
}
