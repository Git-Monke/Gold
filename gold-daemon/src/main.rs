use secp256k1::rand::rngs::OsRng;
use secp256k1::Secp256k1;

use gold_structures::tx;

fn main() {
    let secp = Secp256k1::new();

    let (person1_key, person1_address) = secp.generate_keypair(&mut OsRng);
    let (_, person2_address) = secp.generate_keypair(&mut OsRng);

    let txbuilder = tx::TransactionBuilder::new(person1_key.clone());
    let txvalidator = tx::TransactionValidator::new();

    let new_transaction = txbuilder.build(&person1_address, &person2_address, 1500, 12);
    // new_transaction.amount = 1501;
    let bytes = new_transaction.to_bytes();

    let tx = txvalidator.validate_bytes(bytes);

    match tx {
        Ok(tx) => println!("{tx}"),
        Err(e) => println!("{e}"),
    }
}
