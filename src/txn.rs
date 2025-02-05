// everything in this file will be related to transaction verification
use crate::structs::*;
use thiserror;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ScriptFailure {
    #[error("The referenced Utxo could not be found in the UtxoSet")]
    UtxoNotFound,
    #[error("The input index number is greater than the number of inputs")]
    InputIndexOutOfRange,
    #[error("The output index number is greater than the number of outputs")]
    OutputIndexOutOfRange,
    #[error("{0} is not a valid opcode")]
    UnknownOpcode(u8),
    #[error("Opcode {0} tried to push more bytes than available in the script")]
    NotEnoughBytesToPush(u8),
    #[error("Opcode {0} requires data to follow it, which was not provided")]
    OpcodeMissingRequiredData(u8),
    #[error("The script failed to produce a stack with 1 at the top after executing")]
    GeneralScriptFailure,
    #[error("Opcode requires more stack items than are in the stack")]
    NotEnoughStackItems,
}

#[derive(Debug)]
pub struct ScriptState {
    pub stack: Vec<Vec<u8>>,
    pub index: usize,
    pub script: Vec<u8>,
}

// evaluation and validation have been seperated so they can be tested
pub fn validate_script(
    txn: Txn,
    input_index: usize,
    utxo_set: &UtxoSet,
) -> Result<(), ScriptFailure> {
    let script_state = evaluate_script(txn, input_index, utxo_set)?;

    if script_state.stack.len() == 0 {
        return Err(ScriptFailure::GeneralScriptFailure);
    }

    match script_state.stack[0][..] {
        [1] => Ok(()),
        _ => Err(ScriptFailure::GeneralScriptFailure),
    }
}

pub fn evaluate_script(
    txn: Txn,
    input_index: usize,
    utxo_set: &UtxoSet,
) -> Result<ScriptState, ScriptFailure> {
    // Get the input
    let input = &txn
        .inputs
        .get(input_index)
        .ok_or(ScriptFailure::InputIndexOutOfRange)?;

    let utxo = utxo_set
        .get(&input.output_txid)
        .ok_or(ScriptFailure::UtxoNotFound)?;

    // Get the old unspent output (UTXO) referenced by the new txn input
    let output = &utxo
        .get(input.output_index)
        .ok_or(ScriptFailure::OutputIndexOutOfRange)?
        .txn_output;

    // Combine their scripts to see if the txn input successfully unlocks an existing unspent output
    let locking_script = &output.locking_script;
    let unlocking_script = &input.unlocking_script;

    let mut full_script = vec![];
    full_script.extend_from_slice(unlocking_script);
    full_script.extend_from_slice(locking_script);

    println!("{:?}", full_script);
    let mut script_state = ScriptState {
        stack: vec![],
        index: 0,
        script: full_script,
    };

    // Perform opcodes until the end of the script is reached.
    while script_state.index < script_state.script.len() {
        match perform_next_opcode(&mut script_state) {
            Err(e) => return Err(e),
            _ => continue,
        }
    }

    Ok(script_state)
}

fn perform_next_opcode(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    let opcode = script_state.script[script_state.index];
    println!("{:?}", opcode);

    match opcode {
        0 => opcode_do_nothing(script_state),
        1..=16 => opcode_push_byte(script_state),
        17..=80 => opcode_push_n_bytes(script_state),
        81 => opcode_push_next_byte_bytes(script_state),
        82 => opcode_push_next_2_byte_bytes(script_state),
        218 => opcode_dup(script_state),
        219 => opcode_drop(script_state),
        220 => opcode_verify(script_state),
        248 => opcode_check_equal(script_state),
        _ => Err(ScriptFailure::UnknownOpcode(opcode)),
    }
}

// For opcodes 0-64, push that byte onto the top of the stack
fn opcode_push_byte(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    script_state
        .stack
        .push(vec![current_script_byte(&script_state)]);

    script_state.index += 1;

    Ok(())
}

// take the current opcode, and push OPCODE - 16 bytes to the top of the stack
// Example: OPCODE = 17, push the next byte to the stack. OPCODE = 80, push the next 64 bytes to the top of the stack
fn opcode_push_n_bytes(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    let opcode = current_script_byte(script_state);
    let num_bytes_to_push = (opcode as usize) - 16;

    if script_state.script.len() - script_state.index < (num_bytes_to_push as usize) + 1 {
        return Err(ScriptFailure::NotEnoughBytesToPush(opcode));
    }

    let data =
        &script_state.script[script_state.index + 1..script_state.index + 1 + num_bytes_to_push];

    script_state.stack.push(data.to_owned());

    script_state.index += 1 + num_bytes_to_push;

    Ok(())
}

// Take the byte after the opcode. Push that many bytes onto the stack
fn opcode_push_next_byte_bytes(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    let opcode = current_script_byte(script_state);

    let index = script_state.index;
    let script = &script_state.script;

    // this means that there is no more data after the opcode
    if index == script.len() {
        return Err(ScriptFailure::OpcodeMissingRequiredData(opcode));
    }

    let bytes_to_push = script_state.script[index + 1] as usize;

    if index + 1 + bytes_to_push >= script.len() {
        return Err(ScriptFailure::NotEnoughBytesToPush(opcode));
    }

    let data = &script[index + 2..=index + 1 + bytes_to_push];

    script_state.stack.push(data.to_owned());

    script_state.index += 2 + bytes_to_push;

    Ok(())
}

// Interpret the 2 bytes after the opcode as a u16. Push that many bytes to the top of the stack.
// This is the largest amount of data that can be pushed as a single item onto the stack. 65,535 bytes.
// This will only be used for Pay-To-Script-Hash.
fn opcode_push_next_2_byte_bytes(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    let opcode = current_script_byte(script_state);

    let index = script_state.index;
    let script = &script_state.script;

    // at least 2 bytes of data are required after the opcode
    if index + 2 >= script.len() {
        return Err(ScriptFailure::OpcodeMissingRequiredData(opcode));
    }

    let bytes_to_push = u16::from_le_bytes([
        script_state.script[index + 1],
        script_state.script[index + 2],
    ]) as usize;

    if index + 3 + bytes_to_push > script.len() {
        return Err(ScriptFailure::NotEnoughBytesToPush(opcode));
    }

    let data = &script[index + 3..index + 3 + bytes_to_push];

    script_state.stack.push(data.to_owned());

    script_state.index += 4 + bytes_to_push;

    Ok(())
}

fn opcode_check_equal(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    if script_state.stack.len() < 2 {
        return Err(ScriptFailure::NotEnoughStackItems);
    }

    let mut stack = &mut script_state.stack;

    let item1 = stack.pop().unwrap();
    let item2 = stack.pop().unwrap();

    let result = match item1.eq(&item2) {
        true => 1,
        false => 0,
    };

    stack.push(vec![result]);
    script_state.index += 1;

    Ok(())
}

fn opcode_do_nothing(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    script_state.index += 1;
    Ok(())
}

fn opcode_dup(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    let stack = &mut script_state.stack;

    if stack.len() == 0 {
        return Err(ScriptFailure::NotEnoughStackItems);
    }

    stack.push(stack[stack.len() - 1].clone());
    script_state.index += 1;

    Ok(())
}

fn opcode_drop(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    let stack = &mut script_state.stack;

    if stack.len() > 0 {
        stack.pop();
    }

    script_state.index += 1;

    Ok(())
}

fn opcode_verify(script_state: &mut ScriptState) -> Result<(), ScriptFailure> {
    let stack = &mut script_state.stack;

    if stack.len() == 0 {
        return Err(ScriptFailure::NotEnoughStackItems);
    }

    let item = stack.pop().unwrap();

    if item != [1] {
        return Err(ScriptFailure::GeneralScriptFailure);
    }

    script_state.index += 1;
    Ok(())
}

fn current_script_byte(script_state: &ScriptState) -> u8 {
    script_state.script[script_state.index]
}
