use std::time::{SystemTime, UNIX_EPOCH};

use gold_structures::tx::{Transaction, TxInput, TxOutput};
use secp256k1::hashes::{sha256::Hash, Hash as HashTrait};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let (sk, pk) = secp.generate_keypair(&mut OsRng);

    let input = TxInput {
        txid: Hash::hash(&[1]),
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

    println!("{}", hex::encode(tx.serialize()));

    Ok(())
}
