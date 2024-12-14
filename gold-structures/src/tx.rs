use core::fmt;
use std::fmt::Debug;

use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{Message, PublicKey, SecretKey, VerifyOnly};
use secp256k1::{Secp256k1, SignOnly};

// Two 33 byte signatures, 4 byte amount, 2 byte fee, 64 byte signature
const TX_DATA_SIZE: usize = 33 * 2 + 4 + 2;
const TX_SIZE: usize = TX_DATA_SIZE + 64;

// Building

pub struct TransactionBuilder {
    sk: SecretKey,
    secp: Secp256k1<SignOnly>,
}

impl TransactionBuilder {
    pub fn new(sk: SecretKey) -> Self {
        TransactionBuilder {
            sk: sk,
            secp: Secp256k1::signing_only(),
        }
    }

    pub fn build(
        &self,
        sender: &PublicKey,
        receiver: &PublicKey,
        amount: u32,
        fee: u16,
    ) -> Transaction {
        Transaction::new(sender, receiver, amount, fee, &self.sk, &self.secp)
    }
}

// Validation

pub struct TransactionValidator {
    sepc: Secp256k1<VerifyOnly>,
}

impl TransactionValidator {
    pub fn new() -> Self {
        TransactionValidator {
            sepc: Secp256k1::verification_only(),
        }
    }

    pub fn validate_bytes(&self, tx: [u8; TX_SIZE]) -> Result<Transaction, secp256k1::Error> {
        let transaction = parse(&tx)?;
        let message_hash = sha256::Hash::hash(&tx[..TX_DATA_SIZE]).to_byte_array();
        let message = Message::from_digest(message_hash);
        self.sepc
            .verify_ecdsa(&message, &transaction.sig, &transaction.sender)?;

        Ok(transaction)
    }
}

pub fn parse(tx: &[u8; TX_SIZE]) -> Result<Transaction, secp256k1::Error> {
    let mut tx_deserializer = TransactionDeserializer::new(tx);

    let sender = PublicKey::from_byte_array_compressed(&tx_deserializer.take(33))?;
    let receiver = PublicKey::from_byte_array_compressed(&tx_deserializer.take(33))?;
    let amount = u32::from_le_bytes(tx_deserializer.take(4));
    let fee = u16::from_le_bytes(tx_deserializer.take(2));

    let sig = Signature::from_compact(&tx_deserializer.take::<64>(64))?;

    Ok(Transaction {
        sender,
        receiver,
        amount,
        fee,
        sig,
    })
}

// Data

#[derive(Debug)]
pub struct Transaction {
    pub sender: PublicKey,
    pub receiver: PublicKey,
    pub amount: u32,
    pub fee: u16,
    pub sig: Signature,
}

impl Transaction {
    pub fn new(
        sender: &PublicKey,
        receiver: &PublicKey,
        amount: u32,
        fee: u16,
        sk: &SecretKey,
        secp: &Secp256k1<SignOnly>,
    ) -> Transaction {
        let sender_data = sender.serialize();
        let reciever_data = receiver.serialize();

        let tx_data = TransactionSerializer::new()
            .add(&sender_data)
            .add(&reciever_data)
            .add(&amount.to_le_bytes())
            .add(&fee.to_le_bytes())
            .serialize();

        let message_hash = sha256::Hash::hash(&tx_data[..(TX_SIZE - 64)]);
        let message = Message::from_digest(message_hash.to_byte_array());
        let signature = secp.sign_ecdsa(&message, &sk);

        Transaction {
            sender: sender.to_owned(),
            receiver: receiver.to_owned(),
            amount,
            fee,
            sig: signature,
        }
    }

    pub fn to_bytes(&self) -> [u8; TX_SIZE] {
        TransactionSerializer::new()
            .add(&self.sender.serialize())
            .add(&self.receiver.serialize())
            .add(&self.amount.to_le_bytes())
            .add(&self.fee.to_le_bytes())
            .add(&self.sig.serialize_compact())
            .serialize()
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
    "Sender": "{}",
    "Receiver": "{}",
    "Amount": {},
    "Fee": {},
    "Signature": "{}"
}}"#,
            hex::encode(&self.sender.serialize()),
            hex::encode(&self.receiver.serialize()),
            self.amount,
            self.fee,
            hex::encode(&self.sig.serialize_compact())
        )
    }
}

// Utils

struct TransactionSerializer {
    data: [u8; TX_SIZE],
    offset: usize,
}

impl TransactionSerializer {
    fn new() -> Self {
        TransactionSerializer {
            data: [0; TX_SIZE],
            offset: 0,
        }
    }

    fn add(mut self, data: &[u8]) -> Self {
        let end = self.offset + data.len();
        self.data[self.offset..end].copy_from_slice(data);
        self.offset += data.len();
        self
    }

    fn serialize(self) -> [u8; TX_SIZE] {
        self.data
    }
}

struct TransactionDeserializer<'a> {
    data: &'a [u8; TX_SIZE],
    offset: usize,
}

impl<'a> TransactionDeserializer<'a> {
    fn new(data: &'a [u8; TX_SIZE]) -> Self {
        TransactionDeserializer { data, offset: 0 }
    }

    fn take<const N: usize>(&mut self, n: usize) -> [u8; N] {
        if self.data.len() < self.offset + n {
            panic!("Attempted to take more data than was given")
        }

        let data = &self.data[self.offset..self.offset + n];
        self.offset += n;
        data.try_into()
            .expect("Error trying to convert data chunk to [u8; N]")
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
