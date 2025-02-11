use gold::structs::*;
use gold::txn::*;

use gold::*;
use secp256k1::rand::rngs::OsRng;
use secp256k1::Keypair;

use std::rc::Rc;

// testing data encoding and decoding

#[test]
fn test_to_compact_int_bytes() {
    assert_eq!(to_compact_int_bytes(0), vec![0]); // Minimum possible value
    assert_eq!(to_compact_int_bytes(1), vec![1]); // Simple case
    assert_eq!(to_compact_int_bytes(252), vec![252]); // Upper boundary for single-byte encoding

    assert_eq!(to_compact_int_bytes(253), vec![253, 253, 0]); // Lower boundary for two-byte encoding
    assert_eq!(to_compact_int_bytes(254), vec![253, 254, 0]); // Just above 253
    assert_eq!(to_compact_int_bytes(65535), vec![253, 255, 255]); // Upper boundary for two-byte encoding

    assert_eq!(to_compact_int_bytes(65536), vec![254, 0, 0, 1, 0]); // Lower boundary for four-byte encoding
    assert_eq!(to_compact_int_bytes(100_000), vec![254, 160, 134, 1, 0]); // Example case from original test
    assert_eq!(
        to_compact_int_bytes(4_294_967_295),
        vec![254, 255, 255, 255, 255]
    );

    assert_eq!(
        to_compact_int_bytes(4_294_967_296),
        vec![255, 0, 0, 0, 0, 1, 0, 0, 0]
    );
    assert_eq!(
        to_compact_int_bytes(10_000_000_000),
        vec![255, 0, 228, 11, 84, 2, 0, 0, 0]
    );
    assert_eq!(
        to_compact_int_bytes(u64::MAX as usize),
        vec![255, 255, 255, 255, 255, 255, 255, 255, 255]
    );
}

#[test]
fn test_encode_txn() {
    let example_input = TxnInput {
        output_txid: (0..32).collect::<Vec<u8>>().try_into().unwrap(),
        output_index: 0,
        unlocking_script: vec![255, 254, 253, 252, 251, 250],
    };

    let example_input_2 = TxnInput {
        output_txid: (0..32)
            .map(|i| i * 2)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
        output_index: 2,
        unlocking_script: vec![192, 193, 192, 0, 0, 1],
    };

    let example_output = TxnOutput {
        locking_script: vec![0, 2, 4, 6, 8, 10],
        amount: 100_000,
    };

    let example_txn = Txn {
        inputs: vec![example_input, example_input_2],
        outputs: vec![example_output],
    };

    let data = encode_txn(&example_txn);

    assert_eq!(
        data,
        vec![
            2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 6, 255, 254, 253, 252, 251, 250, 0, 2, 4, 6, 8,
            10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52,
            54, 56, 58, 60, 62, 2, 6, 192, 193, 192, 0, 0, 1, 1, 6, 0, 2, 4, 6, 8, 10, 254, 160,
            134, 1, 0
        ]
    )
}

#[test]
fn test_calc_merkle_root() {
    let example_input = TxnInput {
        output_txid: (0..32).collect::<Vec<u8>>().try_into().unwrap(),
        output_index: 0,
        unlocking_script: vec![255, 254, 253, 252, 251, 250],
    };

    let example_output = TxnOutput {
        locking_script: vec![0, 2, 4, 6, 8, 10],
        amount: 100_000,
    };

    let example_txn = Txn {
        inputs: vec![example_input],
        outputs: vec![example_output],
    };

    let even_txn_list = vec![example_txn.clone(), example_txn.clone()];
    let odd_txn_list = vec![
        example_txn.clone(),
        example_txn.clone(),
        example_txn.clone(),
    ];

    let mr1 = calc_merkle_root(&even_txn_list);
    let mr2 = calc_merkle_root(&odd_txn_list);

    assert_eq!(
        mr1.to_vec(),
        vec![
            206, 142, 171, 152, 140, 207, 243, 135, 142, 234, 255, 244, 183, 190, 144, 236, 48,
            114, 212, 63, 120, 24, 149, 131, 208, 82, 239, 234, 164, 154, 252, 211
        ]
    );

    assert_eq!(
        mr2.to_vec(),
        vec![
            99, 64, 211, 164, 189, 86, 156, 211, 88, 59, 4, 87, 1, 195, 68, 186, 14, 81, 201, 219,
            106, 151, 249, 26, 147, 74, 46, 244, 166, 48, 30, 167
        ]
    );
}

#[test]
fn test_encode_header() {
    let header = Header {
        prev_block_hash: (0..32).collect::<Vec<u8>>().try_into().unwrap(),
        merkle_root: (0..32).collect::<Vec<u8>>().try_into().unwrap(),
        nonce: 0,
        timestamp: 0,
    };

    assert_eq!(
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        ],
        encode_header(&header)
    );
}

#[test]
fn test_check_header_hash() {
    let header = Header {
        prev_block_hash: (0..32).collect::<Vec<u8>>().try_into().unwrap(),
        merkle_root: (0..32).collect::<Vec<u8>>().try_into().unwrap(),
        nonce: 5_800_533,
        timestamp: 0,
    };

    let block = Block {
        header,
        txn_list: vec![],
    };

    assert_eq!(
        check_header_hash(
            &block,
            vec![
                0, 0, 0, 67, 38, 244, 17, 1, 138, 47, 212, 237, 54, 227, 146, 224, 0, 149, 27, 217,
                210, 27, 50, 229, 104, 208, 94, 87, 41, 227, 176, 180
            ]
            .try_into()
            .unwrap(),
        )
        .is_err(),
        true
    );

    assert_eq!(
        check_header_hash(
            &block,
            vec![
                0, 0, 0, 69, 38, 244, 17, 1, 138, 47, 212, 237, 54, 227, 146, 224, 0, 149, 27, 217,
                210, 27, 50, 229, 104, 208, 94, 87, 41, 227, 176, 180
            ]
            .try_into()
            .unwrap(),
        )
        .is_ok(),
        true
    )
}

// testing script evaluation

// creates an example utxo set with an example txn, and a txn that tries to spend the example txn
fn construct_simple_txn_context(
    locking_script: Vec<u8>,
    unlocking_script: Vec<u8>,
) -> (UtxoSet, Context) {
    let mut utxo_set: UtxoSet = std::collections::HashMap::new();

    let old_output = TxnOutput {
        locking_script,
        amount: 0,
    };

    let input = TxnInput {
        output_txid: vec![0; 32].try_into().unwrap(),
        output_index: 0,
        unlocking_script,
    };

    let output = TxnOutput {
        locking_script: vec![],
        amount: 10,
    };

    utxo_set.insert(
        vec![0; 32].try_into().unwrap(),
        vec![Utxo {
            txn_output: old_output,
            block_height: 0,
        }],
    );

    let txn = Rc::new(Txn {
        inputs: vec![input],
        outputs: vec![output],
    });

    (
        utxo_set,
        Context {
            txn: Rc::clone(&txn),
            blockheight: 1,
            utxo_blockheight: 0,
        },
    )
}

fn construct_simple_txn_with_utxo(locking_script: Vec<u8>) -> (UtxoSet, Txn) {
    let mut utxo_set: UtxoSet = std::collections::HashMap::new();

    let old_output = TxnOutput {
        locking_script,
        amount: 0,
    };

    let input = TxnInput {
        output_txid: vec![0; 32].try_into().unwrap(),
        output_index: 0,
        unlocking_script: vec![],
    };

    let output = TxnOutput {
        locking_script: vec![],
        amount: 10,
    };

    utxo_set.insert(
        vec![0; 32].try_into().unwrap(),
        vec![Utxo {
            txn_output: old_output,
            block_height: 0,
        }],
    );

    let txn = Txn {
        inputs: vec![input],
        outputs: vec![output],
    };

    (utxo_set, txn)
}

#[test]
fn test_unknown_opcode() {
    let (utxo_set, context) = construct_simple_txn_context(vec![252], vec![0]);

    let result = validate_script(&context, 0, &utxo_set);

    assert!(result.is_err());
    assert!(result == Err(ScriptFailure::UnknownOpcode(252)));
}

#[test]
fn test_eq_opcode_success() {
    let locking_script = vec![1, 248];
    let unlocking_script = vec![1];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let result = validate_script(&context, 0, &utxo_set);

    assert!(result.is_ok());
}

#[test]
fn test_eq_opcode_fail() {
    let locking_script = vec![2, 248];
    let unlocking_script = vec![1];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let result = validate_script(&context, 0, &utxo_set);

    assert!(result.is_err());
    assert!(result == Err(ScriptFailure::GeneralScriptFailure));
}

#[test]
fn test_op_push_next_byte() {
    let locking_script = vec![0];
    let unlocking_script = vec![17, 255];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == [255]);
}

#[test]
fn test_op_push_next_byte_multiple_bytes() {
    let locking_script = vec![0];
    let unlocking_script = vec![18, 255];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());

    let script_state = script_state.unwrap();
    assert!(script_state.stack[0] == [255, 0]);
    assert!(script_state.index == 3);

    let locking_script = vec![255; 64];
    let unlocking_script = vec![80];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == [255; 64]);
}

#[test]
fn test_op_push_next_byte_bytes() {
    let locking_script = vec![0, 0, 0, 0];
    let unlocking_script = vec![81, 4];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());

    let script_state = script_state.unwrap();
    assert!(script_state.stack[0] == [0, 0, 0, 0]);
    assert!(script_state.index == 6);
}

#[test]
fn test_op_push_next_2_bytes_bytes() {
    let locking_script = vec![0; 65535];
    let unlocking_script = vec![82, 255, 255];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == [0; 65535]);
}

#[test]
fn test_op_push_next_2_bytes_bytes_fail() {
    let locking_script = vec![0; 65534];
    let unlocking_script = vec![82, 255, 255];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_op_push_next_2_bytes_bytes_missing_args() {
    let locking_script = vec![];
    let unlocking_script = vec![82, 255];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_op_push_next_byte_bytes_fail() {
    let locking_script = vec![0];
    let unlocking_script = vec![81, 2];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_op_push_next_byte_fail() {
    let locking_script = vec![];
    let unlocking_script = vec![17];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_op_dup() {
    let locking_script = vec![218, 248];
    let unlocking_script = vec![18, 2, 2];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = validate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
}

#[test]
fn test_op_drop() {
    let locking_script = vec![219];
    let unlocking_script = vec![18, 2, 2];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack.len() == 0);
}

#[test]
fn test_op_verify() {
    // pushes 2 1's, checks for equality, verifies
    // If working properly, the stack should be empty
    let locking_script = vec![1, 248, 220];
    let unlocking_script = vec![1];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack.len() == 0);
}

#[test]
fn test_op_verify_fail_branch() {
    let locking_script = vec![2, 248, 220];
    let unlocking_script = vec![1];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_checksig() {
    // set up crypto functions
    let secp = secp256k1::Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut OsRng);
    let pk = keypair.x_only_public_key();

    // create a basic locking script
    let mut locking_script = vec![16 + 32];
    locking_script.extend(pk.0.serialize().iter());
    locking_script.push(237);

    let (utxo_set, context) = construct_simple_txn_context(locking_script, vec![]);

    // clone the transaction so we can complete the intput scripts and create new context later
    // this is pretty janky, but I don't want to rewrite all that txn building code
    let mut txn = (*context.txn).clone();

    // Take the txn, create the sig for it, set the unlocking script to use this sig
    let sig = sign_transaction(&context.txn, &keypair);
    let mut unlocking_script = vec![80];
    unlocking_script.extend(sig.as_byte_array().iter());

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    // Check that its valid
    let script_state = evaluate_script(&context, 0, &utxo_set);
    println!("{:?}", script_state);

    assert!(script_state.is_ok());

    let script_state = script_state.unwrap();

    assert!(script_state.stack.len() == 1);
    assert!(script_state.stack[0][0] == 1);
}

// Todo: Break up this monster test into multiple smaller tests
#[test]
fn test_checksig_failures() {
    let secp = secp256k1::Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut OsRng);
    let pk = keypair.x_only_public_key();

    let mut locking_script = vec![16 + 32];
    locking_script.extend(pk.0.serialize().iter());
    locking_script.push(237);

    let (utxo_set, context) = construct_simple_txn_context(locking_script, vec![]);

    let mut txn = (*context.txn).clone();

    // --- Invalid sig error ---

    let mut unlocking_script = vec![80];
    unlocking_script.extend(0..64);

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());

    let script_state = script_state.unwrap();

    assert!(script_state.stack.len() == 1);
    assert!(script_state.stack[0][0] == 0);

    // --- Invalid pk error ---

    let mut locking_script = vec![16 + 32];
    locking_script.extend(0..32);
    locking_script.push(237);

    let (utxo_set, context) = construct_simple_txn_context(locking_script, vec![]);

    let mut txn = (*context.txn).clone();
    let mut unlocking_script = vec![80];
    unlocking_script.extend(0..64);

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());

    // Invalid pk length (not 32 bytes) pushed to stack

    let mut locking_script = vec![16 + 31];
    locking_script.extend(0..31);
    locking_script.push(237);

    let (utxo_set, context) = construct_simple_txn_context(locking_script, vec![]);

    let mut txn = (*context.txn).clone();
    let mut unlocking_script = vec![80];
    unlocking_script.extend(0..64);

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());

    // Invalid sig length (not 64 bytes) pushed to stack

    let mut locking_script = vec![16 + 32];
    locking_script.extend(0..32);
    locking_script.push(237);

    let (utxo_set, context) = construct_simple_txn_context(locking_script, vec![]);

    let mut txn = (*context.txn).clone();
    let mut unlocking_script = vec![79];
    unlocking_script.extend(0..63);

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());

    // Not enough stack items

    let mut locking_script = vec![16 + 32];
    locking_script.extend(0..32);
    locking_script.push(237);

    let (utxo_set, context) = construct_simple_txn_context(locking_script, vec![]);

    let mut txn = (*context.txn).clone();
    let unlocking_script = vec![];

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());
}

fn gen_random_keypair() -> Keypair {
    let secp = secp256k1::Secp256k1::new();
    Keypair::new(&secp, &mut OsRng)
}

#[test]
fn check_multisig() {
    let kp1 = gen_random_keypair();
    let kp2 = gen_random_keypair();
    let kp3 = gen_random_keypair();

    let pk1 = kp1.x_only_public_key().0;
    let pk2 = kp2.x_only_public_key().0;
    let pk3 = kp3.x_only_public_key().0;

    let mut locking_script = vec![2, 48];

    // This is a basic implementation of a multisig locking script
    // First num (2) is the number of public keys the user has to provide to spend the coin
    // Then ALL of the valid pk's are pushed to the stack
    // Finally, you push the number of pks, topped off with a checkmultisig opcode
    // To solve this, the user must provide a script which pushes (2) unique and valid sigs to the top of the stack
    // Ex. [80, <Sig 1>, 80, <Sig 2>]
    locking_script.extend(pk1.serialize().iter());
    locking_script.push(48);
    locking_script.extend(pk2.serialize().iter());
    locking_script.push(48);
    locking_script.extend(pk3.serialize().iter());
    locking_script.push(3);
    locking_script.push(238);

    let (utxo_set, mut txn) = construct_simple_txn_with_utxo(locking_script);

    let sig1 = sign_transaction(&txn, &kp1);
    let sig2 = sign_transaction(&txn, &kp2);

    let mut unlocking_script = vec![80];
    unlocking_script.extend(sig1.as_byte_array().iter());
    unlocking_script.push(80);
    unlocking_script.extend(sig2.as_byte_array().iter());

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());

    let script_state = script_state.unwrap();

    assert!(script_state.stack.len() == 1);
    assert!(script_state.stack[0][0] == 1);
}

#[test]
fn check_multisig_invalid_sig() {
    let kp1 = gen_random_keypair();
    let kp2 = gen_random_keypair();
    let kp3 = gen_random_keypair();

    let pk1 = kp1.x_only_public_key().0;
    let pk2 = kp2.x_only_public_key().0;
    let pk3 = kp3.x_only_public_key().0;

    let mut locking_script = vec![2, 48];

    locking_script.extend(pk1.serialize().iter());
    locking_script.push(48);
    locking_script.extend(pk2.serialize().iter());
    locking_script.push(48);
    locking_script.extend(pk3.serialize().iter());
    locking_script.push(3);
    locking_script.push(238);

    let (utxo_set, mut txn) = construct_simple_txn_with_utxo(locking_script);

    let sig1 = [0; 64];
    let sig2 = sign_transaction(&txn, &kp2);

    let mut unlocking_script = vec![80];
    unlocking_script.extend(sig1.iter());
    unlocking_script.push(80);
    unlocking_script.extend(sig2.as_byte_array().iter());

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());

    let script_state = script_state.unwrap();

    assert!(script_state.stack.len() == 1);
    assert!(script_state.stack[0][0] == 0);
}

#[test]
fn check_multisig_reused_pk() {
    let kp1 = gen_random_keypair();
    let kp2 = gen_random_keypair();
    let kp3 = gen_random_keypair();

    let pk1 = kp1.x_only_public_key().0;
    let pk3 = kp3.x_only_public_key().0;

    let mut locking_script = vec![2, 48];

    locking_script.extend(pk1.serialize().iter());
    locking_script.push(48);
    locking_script.extend(pk1.serialize().iter());
    locking_script.push(48);
    locking_script.extend(pk3.serialize().iter());
    locking_script.push(3);
    locking_script.push(238);

    let (utxo_set, mut txn) = construct_simple_txn_with_utxo(locking_script);

    let sig1 = [0; 64];
    let sig2 = sign_transaction(&txn, &kp2);

    let mut unlocking_script = vec![80];
    unlocking_script.extend(sig1.iter());
    unlocking_script.push(80);
    unlocking_script.extend(sig2.as_byte_array().iter());

    txn.inputs[0].unlocking_script = unlocking_script;

    let context = Context {
        txn: Rc::new(txn),
        blockheight: 1,
        utxo_blockheight: 0,
    };

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn check_hashripemd160() {
    // The locking script is asking for some data where RIPEMD160(SHA256(data)) == [155,196,134,...];
    let locking_script = vec![
        239,
        16 + 20,
        155,
        196,
        134,
        11,
        185,
        54,
        171,
        242,
        98,
        215,
        165,
        31,
        116,
        180,
        48,
        72,
        51,
        254,
        227,
        178,
        248,
    ];

    // The data is [1, 2, 3]. This script should pass.
    let unlocking_script = vec![16 + 3, 1, 2, 3];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = validate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
}

#[test]
fn check_hashripemd160_fail() {
    // The locking script is asking for some data where RIPEMD160(SHA256(data)) == [155,196,134,...];
    let locking_script = vec![
        239,
        16 + 20,
        155,
        196,
        134,
        11,
        185,
        54,
        171,
        242,
        98,
        215,
        165,
        31,
        116,
        180,
        48,
        72,
        51,
        254,
        227,
        178,
        248,
    ];

    // The data is [1, 2, 3]. This script should fail.
    let unlocking_script = vec![16 + 3, 1, 2, 4];
    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = validate_script(&context, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn check_locktime() {
    // A coin with this script can be spent by anyone during or after block 10
    let locking_script = vec![16 + 4, 10, 0, 0, 0, 249];
    let unlocking_script = vec![];

    let (utxo_set, mut context) = construct_simple_txn_context(locking_script, unlocking_script);

    context.blockheight = 11;

    let script_state = evaluate_script(&context, 0, &utxo_set);

    // Block height = 11, Required block height = 10. Spendable!
    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == vec![1]);

    // Block height = 9, Required block height = 10. Fail.
    context.blockheight = 9;

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == vec![0]);
}

#[test]
fn check_locktimerelative() {
    // This script can be spent by anyone as soon as the coin is 10 blocks old
    let locking_script = vec![16 + 4, 10, 0, 0, 0, 250];
    let unlocking_script = vec![];

    let (utxo_set, mut context) = construct_simple_txn_context(locking_script, unlocking_script);

    context.blockheight = 11;
    context.utxo_blockheight = 1;

    let script_state = evaluate_script(&context, 0, &utxo_set);

    // Block height = 11, UTXO created on block 1. 11 - 1 = 10. Spendable!
    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == vec![1]);

    // Block height = 9, UTXO created on block 1. 9 - 1 = 8. Fail!
    context.blockheight = 9;
    context.utxo_blockheight = 1;

    let script_state = evaluate_script(&context, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == vec![0]);
}

#[test]
fn check_if() {
    let locking_script = vec![1, 253, 1, 1, 1, 254, 2, 2, 2, 255];
    let unlocking_script = vec![];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);

    let script_state = evaluate_script(&context, 0, &utxo_set).unwrap();

    assert_eq!(
        script_state.script,
        vec![1, 253, 1, 1, 1, 254, 0, 0, 0, 255]
    );

    // fail case

    let locking_script = vec![17, 0, 253, 1, 1, 1, 254, 2, 2, 2, 255, 1, 2];
    let unlocking_script = vec![];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);

    let script_state = evaluate_script(&context, 0, &utxo_set).unwrap();

    assert_eq!(
        script_state.script,
        vec![17, 0, 253, 0, 0, 0, 254, 2, 2, 2, 255, 1, 2]
    );

    // edge cases

    // no else
    let locking_script = vec![1, 253, 1, 1, 1, 2, 2, 2, 255, 1, 2, 3];
    let unlocking_script = vec![];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);

    let script_state = evaluate_script(&context, 0, &utxo_set).unwrap();

    assert_eq!(
        script_state.script,
        vec![1, 253, 1, 1, 1, 2, 2, 2, 255, 1, 2, 3]
    );

    // no endif 0 case
    let locking_script = vec![17, 0, 253, 1, 1, 1, 2, 2, 2];
    let unlocking_script = vec![];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);

    let script_state = evaluate_script(&context, 0, &utxo_set).unwrap();

    assert_eq!(script_state.script, vec![17, 0, 253, 0, 0, 0, 0, 0, 0]);

    // succesful if, else, no endif
    let locking_script = vec![1, 253, 1, 1, 1, 254, 2, 2, 2];
    let unlocking_script = vec![];

    let (utxo_set, context) = construct_simple_txn_context(locking_script, unlocking_script);

    let script_state = evaluate_script(&context, 0, &utxo_set).unwrap();

    assert_eq!(script_state.script, vec![1, 253, 1, 1, 1, 254, 0, 0, 0]);
}

#[cfg(test)]
mod block_txn_validation {
    use std::collections::HashMap;

    use gold::structs::*;

    fn create_dummy_utxo(locking_script: Vec<u8>, amount: u64) -> Utxo {
        Utxo {
            txn_output: TxnOutput {
                locking_script,
                amount,
            },
            block_height: 0,
        }
    }

    fn create_dummy_utxo_set(utxo: Utxo) -> UtxoSet {
        let set: UtxoSet = HashMap::new();
        set
    }

    fn create_dummy_txn(
        output_txid: [u8; 32],
        unlocking_script: Vec<u8>,
        output_index: usize,
        amount: u64,
    ) -> Txn {
        let txn_input = TxnInput {
            output_txid,
            output_index,
            unlocking_script,
        };

        let txn_output = TxnOutput {
            locking_script: vec![1],
            amount,
        };

        Txn {
            inputs: vec![txn_input],
            outputs: vec![txn_output],
        }
    }

    #[test]
    fn example_test() {
        assert!(true)
    }
}

#[cfg(test)]
mod helper_functions {
    use gold::*;

    #[test]
    fn test_calc_coinbase() {
        let median_block_size = 100_000;

        assert_eq!(calc_coinbase(90_000, median_block_size), 1_000_000_000_000);
        assert_eq!(calc_coinbase(110_000, median_block_size), 810_000_000_000);
        assert_eq!(calc_coinbase(187_284, median_block_size), 16_169_665_000);
        assert_eq!(calc_coinbase(198_726, median_block_size), 162_307_000);
        assert_eq!(calc_coinbase(200_000, median_block_size), 0);
    }
}
