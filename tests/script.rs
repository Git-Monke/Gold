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
            block_time: 0,
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
            block_time: 0,
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
mod txn_validation {
    use super::*;
    use gold::*;
    use std::rc::Rc;

    // Dummy helpers to build blocks/transactions quickly.
    // Adjust as necessary in your codebase.
    fn dummy_utxo(
        txid: [u8; 32],
        index: usize,
        amount: u64,
        block_height: usize,
    ) -> ([u8; 32], Utxo) {
        (
            txid,
            Utxo {
                txn_output: TxnOutput {
                    locking_script: vec![0x01], // valid script pushes 0x01 for success
                    amount,
                },
                block_height,
                block_time: 0,
            },
        )
    }

    fn dummy_block(prev_block_hash: [u8; 32], nonce: u64, timestamp: u64, txns: Vec<Txn>) -> Block {
        Block {
            header: Header {
                prev_block_hash,
                merkle_root: [0; 32],
                nonce,
                timestamp,
            },
            txn_list: txns,
        }
    }

    /// Encode the block as if for real usage.
    /// For testing, let's just do something that returns a consistent size
    /// based on how many transactions we have, plus some overhead.
    fn encode_block(block: &Block) -> Vec<u8> {
        let mut v = vec![];
        // Minimal "header size" for demonstration
        v.extend_from_slice(&block.header.prev_block_hash);
        v.extend_from_slice(&block.header.merkle_root);
        v.extend_from_slice(&block.header.nonce.to_le_bytes());
        v.extend_from_slice(&block.header.timestamp.to_le_bytes());
        // Then each txn will add some bytes
        for txn in &block.txn_list {
            // Just length-based logic for demonstration
            v.extend_from_slice(&(txn.inputs.len() as u64).to_le_bytes());
            v.extend_from_slice(&(txn.outputs.len() as u64).to_le_bytes());
        }
        v
    }

    /// Script passes if the top byte is 0x01, fails if it’s 0x02.
    /// (Real script logic will be more involved.)
    fn validate_script(
        _context: &Context,
        input_i: usize,
        utxo_set: &UtxoSet,
    ) -> std::result::Result<(), String> {
        let top_byte = if let Some((_, utxo_vec)) = utxo_set.iter().next() {
            // Just a naive example – real script logic would combine input.unlock + output.locking
            // Here we pretend the top byte in the unlocking script is what we check.
            utxo_vec
                .get(input_i)
                .map(|u| u.txn_output.locking_script.first().cloned())
                .unwrap_or(Some(0x01)) // fallback
        } else {
            Some(0x01) // default
        };

        match top_byte {
            Some(0x01) => Ok(()),
            Some(0x02) => Err("Script failed.".to_string()),
            _ => Ok(()), // everything else is a no-op
        }
    }

    // Convenience constructors
    fn coinbase_txn(amount: u64) -> Txn {
        Txn {
            inputs: vec![],
            outputs: vec![TxnOutput {
                locking_script: vec![0x01], // valid script
                amount,
            }],
        }
    }

    fn normal_txn(inputs: Vec<TxnInput>, outputs: Vec<TxnOutput>) -> Txn {
        Txn { inputs, outputs }
    }

    fn default_median_size() -> usize {
        1000
    }

    #[test]
    fn test_coinbase_no_penalty_no_spends() {
        // Block is intentionally tiny => no penalty
        // No normal txns => coinbase remains 1_000_000_000_000
        let utxo_set = UtxoSet::new();
        let median_block_size = default_median_size();

        // Just a single coinbase txn
        let coinbase = coinbase_txn(1_000_000_000_000);
        let block = dummy_block([0; 32], 0, 0, vec![coinbase]);

        let res = check_txns(&block, &utxo_set, 1, median_block_size);
        assert!(res.is_ok());
    }

    #[test]
    fn test_coinbase_with_penalty_no_spends() {
        // Make the encoded block artificially large to exceed median_block_size => triggers penalty
        let utxo_set = UtxoSet::new();
        let median_block_size = default_median_size();

        // Use multiple dummy txns to bloat the block size in `encode_block`
        let mut big_vec = vec![coinbase_txn(1_000_000_000_000)];
        for _ in 0..50 {
            big_vec.push(normal_txn(vec![], vec![]));
        }
        let block = dummy_block([0; 32], 0, 0, big_vec);

        let block_size = encode_block(&block).len();
        assert!(
            block_size > median_block_size,
            "Ensure block is indeed bigger than median."
        );

        let res = check_txns(&block, &utxo_set, 1, median_block_size);
        assert!(res.is_ok());
        // The coinbase gets slashed. We could compute exact penalty and check it by re-running
        // but here we just want to confirm it doesn't fail.
    }

    #[test]
    fn test_valid_block_with_spends_and_no_penalty() {
        // This scenario: block is small => no penalty.
        // Normal txns: spending existing UTXOs => final coinbase = 1_000_000_000_000 + (inputs - outputs).
        let mut utxo_set: UtxoSet = UtxoSet::new();
        // Provide a few UTXOs for spending:
        let spend_txid1 = [1u8; 32];
        let (key1, utxo1) = dummy_utxo(spend_txid1, 0, 500, 0);
        utxo_set.insert(key1, vec![utxo1]);

        let spend_txid2 = [2u8; 32];
        let (key2, utxo2) = dummy_utxo(spend_txid2, 0, 1000, 0);
        utxo_set.insert(key2, vec![utxo2]);

        // Normal transactions
        let normal1 = normal_txn(
            vec![TxnInput {
                output_txid: spend_txid1,
                output_index: 0,
                unlocking_script: vec![0x01], // top byte => success
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 300,
            }],
        ); // inputs=500, outputs=300 => leftover 200

        let normal2 = normal_txn(
            vec![TxnInput {
                output_txid: spend_txid2,
                output_index: 0,
                unlocking_script: vec![0x01], // top byte => success
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 700,
            }],
        ); // inputs=1000, outputs=700 => leftover 300

        // sum leftover across both = 200 + 300 = 500
        // final coinbase should be 1_000_000_000_000 + 500 = 1_000_000_000_500
        let coinbase = coinbase_txn(1_000_000_000_500);

        let block = dummy_block([0; 32], 1, 42, vec![coinbase, normal1, normal2]);
        let res = check_txns(&block, &utxo_set, 1, default_median_size());
        assert!(res.is_ok());
    }

    #[test]
    fn test_block_exceeds_median_with_spends() {
        // Create a large block to slash coinbase, plus normal transactions with leftover inputs
        // so final coinbase = (slashed base) + leftover
        let mut utxo_set: UtxoSet = UtxoSet::new();

        let spend_txid = [3u8; 32];
        let (key, utxo) = dummy_utxo(spend_txid, 0, 500, 0);
        utxo_set.insert(key, vec![utxo]);

        // A normal spend: 500 in, 100 out => leftover 400
        let normal = normal_txn(
            vec![TxnInput {
                output_txid: spend_txid,
                output_index: 0,
                unlocking_script: vec![0x01], // success
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 100,
            }],
        );

        // Start with base coinbase
        let base_coinbase = 1_000_000_000_000;

        // We'll artificially bloat the block with some dummy txns
        let mut txns = vec![coinbase_txn(base_coinbase)];
        // Add the normal spend
        txns.push(normal);
        // Add extra dummy txns to inflate block size
        for _ in 0..60 {
            txns.push(normal_txn(vec![], vec![]));
        }
        let block = dummy_block([0; 32], 0, 0, txns);

        let block_size = encode_block(&block).len();
        let median_block_size = default_median_size();
        assert!(
            block_size > median_block_size,
            "Ensure it's actually bigger."
        );

        // If penalty factor = block_size / median_block_size
        // final coinbase = (base_coinbase * penalty_factor) + leftover
        // leftover = 500 - 100 = 400
        // We don't do an exact check here, but we ensure it doesn't fail.
        let res = check_txns(&block, &utxo_set, 0, median_block_size);
        assert!(res.is_ok());
    }

    #[test]
    fn test_fail_sum_of_outputs_exceeds_sum_of_inputs() {
        // The leftover check (value_of_outputs > value_of_inputs).
        let mut utxo_set: UtxoSet = UtxoSet::new();
        let spend_txid = [4u8; 32];
        let (key, utxo) = dummy_utxo(spend_txid, 0, 500, 0);
        utxo_set.insert(key, vec![utxo]);

        // Normal Txn attempts to spend 500 but creates 600
        let normal = normal_txn(
            vec![TxnInput {
                output_txid: spend_txid,
                output_index: 0,
                unlocking_script: vec![0x01], // valid
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 600,
            }],
        );

        // We start coinbase as something (1_000_000_000_000)
        // but we'll fail before we even finalize coinbase
        let coinbase = coinbase_txn(1_000_000_000_000);
        let block = dummy_block([0; 32], 0, 0, vec![coinbase, normal]);

        let res = check_txns(&block, &utxo_set, 0, default_median_size());
        assert!(res.is_err());
        let err_str = format!("{:?}", res.err().unwrap());
        assert!(err_str.contains("The sum of the outputs was greater"));
    }

    #[test]
    fn test_fail_missing_utxo() {
        // Referencing a nonexistent utxo => fail
        let utxo_set: UtxoSet = UtxoSet::new();

        let normal = normal_txn(
            vec![TxnInput {
                output_txid: [9u8; 32],
                output_index: 0,
                unlocking_script: vec![0x01],
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 100,
            }],
        );

        let coinbase = coinbase_txn(1_000_000_000_000);
        let block = dummy_block([0; 32], 0, 0, vec![coinbase, normal]);
        let res = check_txns(&block, &utxo_set, 0, default_median_size());
        assert!(res.is_err());
        assert!(format!("{:?}", res.err().unwrap()).contains("Referenced UTXO does not exist"));
    }

    #[test]
    fn test_fail_invalid_output_index() {
        // UTXO set has only index 0, but we try to spend index 1
        let mut utxo_set: UtxoSet = UtxoSet::new();
        let spend_txid = [5u8; 32];
        let (key, utxo) = dummy_utxo(spend_txid, 0, 500, 0);
        utxo_set.insert(key, vec![utxo]);

        let normal = normal_txn(
            vec![TxnInput {
                output_txid: spend_txid,
                output_index: 1,
                unlocking_script: vec![0x01],
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 300,
            }],
        );

        let coinbase = coinbase_txn(1_000_000_000_000);
        let block = dummy_block([0; 32], 0, 0, vec![coinbase, normal]);

        let res = check_txns(&block, &utxo_set, 0, default_median_size());
        assert!(res.is_err());
        assert!(format!("{:?}", res.err().unwrap())
            .contains("Input tried to spend an output at an index that doesn't exist"));
    }

    #[test]
    fn test_fail_script() {
        // Script fails if top byte is 0x02
        let mut utxo_set: UtxoSet = UtxoSet::new();
        let spend_txid = [6u8; 32];
        // We'll store the UTXO as if it's a valid locking script, but we supply an unlocking script that fails
        let (key, utxo) = dummy_utxo(spend_txid, 0, 500, 0);
        utxo_set.insert(key, vec![utxo]);

        let normal = normal_txn(
            vec![TxnInput {
                output_txid: spend_txid,
                output_index: 0,
                // We'll pretend 0x02 is the top byte that triggers a fail in your validate_script
                unlocking_script: vec![0x02],
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 100,
            }],
        );

        let coinbase = coinbase_txn(1_000_000_000_000);
        let block = dummy_block([0; 32], 0, 0, vec![coinbase, normal]);

        let res = check_txns(&block, &utxo_set, 0, default_median_size());
        assert!(res.is_err());
        assert!(format!("{:?}", res.err().unwrap()).contains("Script failed."));
    }

    #[test]
    fn test_extra_dummy_normal_txns() {
        // Confirm we handle multiple normal txns with big leftover properly
        let mut utxo_set: UtxoSet = UtxoSet::new();

        // Provide a couple of UTXOs for multiple normal txns
        let txid1 = [0x11u8; 32];
        let (k1, u1) = dummy_utxo(txid1, 0, 600, 0);
        utxo_set.insert(k1, vec![u1]);

        let txid2 = [0x22u8; 32];
        let (k2, u2) = dummy_utxo(txid2, 0, 900, 0);
        utxo_set.insert(k2, vec![u2]);

        // Txn1: spend 600 => output 100 leftover 500
        let normal1 = normal_txn(
            vec![TxnInput {
                output_txid: txid1,
                output_index: 0,
                unlocking_script: vec![0x01],
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 100,
            }],
        );

        // Txn2: spend 900 => output 600 leftover 300
        let normal2 = normal_txn(
            vec![TxnInput {
                output_txid: txid2,
                output_index: 0,
                unlocking_script: vec![0x01],
            }],
            vec![TxnOutput {
                locking_script: vec![0x01],
                amount: 600,
            }],
        );

        // total leftover = 500 + 300 = 800
        // final coinbase = base + leftover = 1_000_000_000_000 + 800
        let coinbase = coinbase_txn(1_000_000_000_800);

        let block = dummy_block([0; 32], 99, 99, vec![coinbase, normal1, normal2]);
        let res = check_txns(&block, &utxo_set, 0, default_median_size());
        assert!(res.is_ok());
    }
}
