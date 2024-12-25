use std::time::Duration;

use secp256k1::hashes::{sha256::Hash, Hash as Sha256Hash};

use crate::Result;
use crate::{byte_reader::ByteReader, tx::Transaction};

pub struct Block {
    header: Header,
    txs: Vec<Transaction>,
}

pub struct Header {
    prev_block_hash: Hash,
    timestamp: Duration,
    merkle_root: Hash,
    nonce: u32,
}

impl Block {
    pub fn genesis_block() -> Block {
        Block {
            header: Header::genesis_header(),
            txs: vec![],
        }
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer = self.header.get_bytes();

        for tx in self.txs.iter() {
            buffer.extend(tx.serialize());
        }

        buffer.into_boxed_slice()
    }

    // pub fn deserialize(bytes: &[u8]) -> Block {

    // }
}

impl Header {
    pub fn genesis_header() -> Header {
        Header {
            prev_block_hash: Sha256Hash::from_byte_array([0; 32]),
            timestamp: Duration::from_secs(0),
            merkle_root: Sha256Hash::from_byte_array([0; 32]),
            nonce: 0,
        }
    }

    // get_bytes is seperate from serialize so the construction of blocks can just extend an existing vec instead of cloning
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend(self.prev_block_hash.as_byte_array());
        buffer.extend((self.timestamp.as_secs() as u32).to_le_bytes());
        buffer.extend(self.merkle_root.as_byte_array());
        buffer.extend(self.nonce.to_le_bytes());

        buffer
    }

    pub fn serialize(&self) -> Box<[u8]> {
        self.get_bytes().into_boxed_slice()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Header> {
        let reader = ByteReader::new(bytes);
        Header::from_byte_reader(&reader)
    }

    // from_byte_reader is seperate here but not Block is because Block uses a byte reader, and header naturally extends Block deserialization
    pub fn from_byte_reader(bytes: &ByteReader) -> Result<Header> {
        let prev_block_hash = Sha256Hash::from_byte_array(bytes.read(32)?.try_into()?);
        let timestamp = Duration::from_secs(u32::from_le_bytes(bytes.read(4)?.try_into()?) as u64);
        let merkle_root = Sha256Hash::from_byte_array(bytes.read(32)?.try_into()?);
        let nonce = u32::from_le_bytes(bytes.read(4)?.try_into()?);

        Ok(Header {
            prev_block_hash,
            timestamp,
            merkle_root,
            nonce,
        })
    }
}
