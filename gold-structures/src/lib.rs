use std::{collections::HashMap, fs::File};

pub mod block;
pub mod error;
pub mod prelude;
pub mod transaction;
pub mod utils;

use prelude::*;

pub type Txid = [u8; 32];
pub type HashBytes = [u8; 32];

pub struct UtxoId([u8; 33]);

pub struct UtxoSet {
    data: HashMap<UtxoId, transaction::TxOutput>,
}

impl UtxoSet {
    pub fn new() -> UtxoSet {
        todo!()
    }

    pub fn from_file(file: &File) -> UtxoSet {
        todo!()
    }

    pub fn add_block(block: block::Block) -> Result<()> {
        todo!()
    }

    pub fn rollback_block(block: block::Block) -> Result<()> {
        todo!()
    }
}
