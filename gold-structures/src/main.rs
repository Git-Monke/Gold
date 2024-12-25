use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gold_structures::block::Block;
use gold_structures::tx::{Transaction, TxInput, TxOutput, Txid};
use secp256k1::hashes::{sha256::Hash, Hash as HashTrait};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let (sk, pk) = secp.generate_keypair(&mut OsRng);

    let input = TxInput {
        txid: Txid(Hash::hash(&[1]).to_byte_array()),
        output_index: 0,
        sigs: vec![secp.sign_ecdsa(&Message::from_digest(Hash::hash(&[0]).to_byte_array()), &sk)],
    };

    let output = TxOutput {
        amount: 1234,
        new_owners: vec![pk],
        required_sigs: 1,
    };

    let tx = Transaction {
        inputs: vec![input],
        outputs: vec![output],
    };

    let input = TxInput {
        txid: Txid(Hash::hash(&[1]).to_byte_array()),
        output_index: 0,
        sigs: vec![secp.sign_ecdsa(&Message::from_digest(Hash::hash(&[0]).to_byte_array()), &sk)],
    };

    let output = TxOutput {
        amount: 10000,
        new_owners: vec![pk],
        required_sigs: 1,
    };

    let tx2 = Transaction {
        inputs: vec![input],
        outputs: vec![output],
    };

    let genesis = Block::genesis_block();
    let hash = genesis.hash();

    let new_block = Block::new(hash, Some(vec![tx, tx2]));
    let data = new_block.serialize();
    let test_deser = Block::deserialize(&data)?;

    println!("{:?}", test_deser);

    Ok(())
}
