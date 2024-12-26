use super::transaction::Transaction;
use super::HashBytes;
use crate::prelude::*;

pub struct Block {
    header: Header,
    tx_list: Vec<Transaction>,
}

pub struct Header {
    prev_block_hash: HashBytes,
    timestamp: u32,
    merkle_root: HashBytes,
    nonce: u32,
}

impl Block {
    pub fn genesis() -> Block {
        Block {
            header: Header {
                prev_block_hash: [0; 32],
                timestamp: 0,
                merkle_root: [0; 32],
                nonce: 0,
            },
            tx_list: vec![],
        }
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let mut data: Vec<u8> = Vec::new();

        data.extend(self.header.serialize());

        for tx in self.tx_list.iter() {
            data.extend(tx.serialize());
        }

        data.into_boxed_slice()
    }
}

impl Header {
    pub fn serialize(&self) -> Box<[u8]> {
        let mut data: Vec<u8> = Vec::new();

        data.extend(self.prev_block_hash);
        data.extend(self.timestamp.to_le_bytes());
        data.extend(self.merkle_root);
        data.extend(self.nonce.to_le_bytes());

        data.into_boxed_slice()
    }
}
