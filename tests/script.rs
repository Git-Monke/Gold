use std::env::consts::OS;

use gold::structs::*;
use gold::txn::*;

use gold::*;

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
) -> (UtxoSet, Txn) {
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

    (
        utxo_set,
        Txn {
            inputs: vec![input],
            outputs: vec![output],
        },
    )
}

#[test]
fn test_unknown_opcode() {
    let (utxo_set, txn) = construct_simple_txn_context(vec![252], vec![0]);

    let result = validate_script(txn, 0, &utxo_set);

    assert!(result.is_err());
    assert!(result == Err(ScriptFailure::UnknownOpcode(252)));
}

#[test]
fn test_eq_opcode_success() {
    let locking_script = vec![1, 248];
    let unlocking_script = vec![1];
    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let result = validate_script(txn, 0, &utxo_set);

    assert!(result.is_ok());
}

#[test]
fn test_eq_opcode_fail() {
    let locking_script = vec![2, 248];
    let unlocking_script = vec![1];
    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let result = validate_script(txn, 0, &utxo_set);

    assert!(result.is_err());
    assert!(result == Err(ScriptFailure::GeneralScriptFailure));
}

#[test]
fn test_op_push_next_byte() {
    let locking_script = vec![0];
    let unlocking_script = vec![17, 255];
    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == [255]);
}

#[test]
fn test_op_push_next_byte_multiple_bytes() {
    let locking_script = vec![0];
    let unlocking_script = vec![18, 255];
    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_ok());

    let script_state = script_state.unwrap();
    assert!(script_state.stack[0] == [255, 0]);
    assert!(script_state.index == 3);

    let locking_script = vec![255; 64];
    let unlocking_script = vec![80];
    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == [255; 64]);
}

#[test]
fn test_op_push_next_byte_bytes() {
    let locking_script = vec![0, 0, 0, 0];
    let unlocking_script = vec![81, 4];

    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_ok());

    let script_state = script_state.unwrap();
    assert!(script_state.stack[0] == [0, 0, 0, 0]);
    assert!(script_state.index == 6);
}

#[test]
fn test_op_push_next_2_bytes_bytes() {
    let locking_script = vec![0; 65535];
    let unlocking_script = vec![82, 255, 255];

    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_ok());
    assert!(script_state.unwrap().stack[0] == [0; 65535]);
}

#[test]
fn test_op_push_next_2_bytes_bytes_fail() {
    let locking_script = vec![0; 65534];
    let unlocking_script = vec![82, 255, 255];

    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_op_push_next_2_bytes_bytes_missing_args() {
    let locking_script = vec![];
    let unlocking_script = vec![82, 255];

    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_op_push_next_byte_bytes_fail() {
    let locking_script = vec![0];
    let unlocking_script = vec![81, 2];

    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_op_push_next_byte_fail() {
    let locking_script = vec![];
    let unlocking_script = vec![17];
    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = evaluate_script(txn, 0, &utxo_set);

    assert!(script_state.is_err());
}

#[test]
fn test_op_dup() {
    let locking_script = vec![218, 248];
    // push a 1, duplicate it, check that the top two stack items are equal (both 1's)
    let unlocking_script = vec![18, 2, 2];
    let (utxo_set, txn) = construct_simple_txn_context(locking_script, unlocking_script);
    let script_state = validate_script(txn, 0, &utxo_set);

    assert!(script_state.is_ok());
}
