use std::time::{SystemTime, UNIX_EPOCH};

use secp256k1::hashes::sha256;
use secp256k1::hashes::{sha256::Hash, Hash as Sha256Hash};

use crate::Result;
use crate::{byte_reader::ByteReader, tx::Transaction};

#[derive(Debug)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Transaction>,
}

#[derive(Debug)]

pub struct Header {
    pub prev_block_hash: Hash,
    pub timestamp: u32,
    pub merkle_root: Hash,
    pub nonce: u32,
}

impl Block {
    pub fn genesis_block() -> Block {
        Block {
            header: Header::genesis_header(),
            txs: vec![],
        }
    }

    pub fn new(prev_hash: Hash, txs: Option<Vec<Transaction>>) -> Block {
        let merkle_root = match &txs {
            Some(txs) => Transaction::merkle_root(&txs),
            None => Hash::from_byte_array([0_u8; 32]),
        };

        Block {
            header: Header {
                prev_block_hash: prev_hash,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as u32,
                merkle_root,
                nonce: 0,
            },
            txs: txs.unwrap_or(vec![]),
        }
    }

    pub fn push_tx(&mut self, tx: Transaction) {
        self.txs.push(tx);
        self.header.merkle_root = Transaction::merkle_root(&self.txs)
    }

    pub fn hash(&self) -> Hash {
        let data = self.serialize();
        sha256::Hash::hash(&data)
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let mut buffer = self.header.get_bytes();

        for tx in self.txs.iter() {
            buffer.extend(tx.serialize());
        }

        buffer.into_boxed_slice()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Block> {
        let reader = ByteReader::new(bytes);
        let header = Header::from_byte_reader(&reader)?;
        let mut txs: Vec<Transaction> = Vec::new();

        while reader.data_left() {
            let tx = Transaction::deserialize_from_byte_reader(&reader)?;
            txs.push(tx);
        }

        Ok(Block { header, txs })
    }
}

impl Header {
    pub fn genesis_header() -> Header {
        Header {
            prev_block_hash: Sha256Hash::from_byte_array([0; 32]),
            timestamp: 0,
            merkle_root: sha256::Hash::from_byte_array([0_u8; 32]),
            nonce: 0,
        }
    }

    // get_bytes is seperate from serialize so the construction of blocks can just extend an existing vec instead of cloning
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend(self.prev_block_hash.as_byte_array());
        buffer.extend(self.timestamp.to_le_bytes());
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
        let timestamp = u32::from_le_bytes(bytes.read(4)?.try_into()?);
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
