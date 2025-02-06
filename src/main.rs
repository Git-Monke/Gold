use gold::structs::*;
use gold::*;

use secp256k1::rand::rngs::OsRng;
use secp256k1::Keypair;
use txn::*;

fn main() {
    let input = TxnInput {
        output_txid: vec![0; 32].try_into().unwrap(),
        output_index: 0,
        unlocking_script: vec![],
    };

    let output = TxnOutput {
        locking_script: vec![],
        amount: 10,
    };

    let txn = Txn {
        inputs: vec![input],
        outputs: vec![output],
    };

    let secp = secp256k1::Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut OsRng);
    let pk = keypair.x_only_public_key();

    let sig = sign_transaction(&txn, &keypair);

    let mut locking_script = vec![80];
    locking_script.extend(pk.0.serialize().iter());
    locking_script.push(237);

    let mut unlocking_script = vec![80];
    unlocking_script.extend(sig.as_byte_array().iter());

    println!("{:?}", check_txn_sig(&txn, &sig, &pk.0));
}
