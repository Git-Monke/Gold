use crate::Result;
use std::ops::Deref;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]

pub struct Txid([u8; 32]);

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
