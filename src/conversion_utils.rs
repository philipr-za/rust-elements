//! Conversion between bitcoin and elements types
//!

use crate::confidential::Value;
use crate::{confidential, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness, TxOut, Txid, TxMerkleNode};
use bitcoin::hashes::Hash;
use core::fmt::{Display, Formatter};
use std::convert::TryFrom;
use std::error::Error;

/// Error describing issues converting between bitcoin and elements types
#[derive(Debug)]
pub enum TransactionConversionError {
    /// Witness contains Elements specific data that cannot be converted
    IncompatibleWitness,
    /// Output contains Elements speicific data that cannot be converted
    IncompatibleOutputType,
}

impl Display for TransactionConversionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionConversionError::IncompatibleWitness => {
                write!(f, "Elements witness not compatible with bitcoin")
            }
            TransactionConversionError::IncompatibleOutputType => {
                write!(f, "Elements output type not compatible with bitcoin")
            }
        }
    }
}

impl Error for TransactionConversionError {}

impl From<bitcoin::Script> for Script {
    fn from(bitcoin_script: bitcoin::Script) -> Self {
        bitcoin_script.to_bytes().into()
    }
}

impl From<Script> for bitcoin::Script {
    fn from(script: Script) -> Self {
        script.to_bytes().into()
    }
}

impl From<bitcoin::Txid> for Txid {
    fn from(bitcoin_txid: bitcoin::Txid) -> Self {
        Txid::from_slice(bitcoin_txid.as_ref()).expect("txid")
    }
}

impl From<Txid> for bitcoin::Txid {
    fn from(elements_txid: Txid) -> Self {
        bitcoin::Txid::from_slice(elements_txid.as_ref()).expect("txid")
    }
}

impl From<bitcoin::OutPoint> for OutPoint {
    fn from(bitcoin_outpoint: bitcoin::OutPoint) -> Self {
        OutPoint {
            txid: bitcoin_outpoint.txid.into(),
            vout: bitcoin_outpoint.vout,
        }
    }
}

impl From<OutPoint> for bitcoin::OutPoint {
    fn from(elements_outpoint: OutPoint) -> Self {
        bitcoin::OutPoint {
            txid: elements_outpoint.txid.into(),
            vout: elements_outpoint.vout,
        }
    }
}

impl From<BlockHash> for bitcoin::BlockHash {
    fn from(blockhash: BlockHash) -> Self {
        bitcoin::BlockHash::from_slice(blockhash.as_ref()).expect("blockhash")
    }
}

impl From<bitcoin::Transaction> for Transaction {
    fn from(bitcoin_tx: bitcoin::Transaction) -> Self {
        let tx_ins = bitcoin_tx
            .input
            .iter()
            .map(|i| TxIn {
                previous_output: i.previous_output.into(),
                is_pegin: false,
                script_sig: Script::from(i.script_sig.as_bytes().to_vec()),
                sequence: Sequence::from_consensus(i.sequence.to_consensus_u32()),
                asset_issuance: Default::default(),
                witness: TxInWitness {
                    amount_rangeproof: None,
                    inflation_keys_rangeproof: None,
                    script_witness: i.witness.to_vec(),
                    pegin_witness: vec![],
                },
            })
            .collect::<Vec<_>>();

        let tx_outs = bitcoin_tx
            .output
            .iter()
            .map(|o| TxOut {
                asset: Default::default(),
                value: confidential::Value::Explicit(o.value),
                nonce: Default::default(),
                script_pubkey: Script::from(o.script_pubkey.as_bytes().to_vec()),
                witness: Default::default(),
            })
            .collect::<Vec<_>>();

        Transaction {
            version: bitcoin_tx.version as u32,
            lock_time: LockTime::from_consensus(bitcoin_tx.lock_time.to_u32()).into(),
            input: tx_ins,
            output: tx_outs,
        }
    }
}

impl TryFrom<Transaction> for bitcoin::Transaction {
    type Error = TransactionConversionError;

    fn try_from(elements_tx: Transaction) -> Result<Self, Self::Error> {
        let tx_ins = elements_tx
            .input
            .iter()
            .map(|i| {
                if !i.witness.pegin_witness.is_empty()
                    || i.witness.amount_rangeproof.is_some()
                    || i.witness.inflation_keys_rangeproof.is_some()
                {
                    return Err(TransactionConversionError::IncompatibleWitness);
                }
                Ok(bitcoin::TxIn {
                    previous_output: i.previous_output.into(),
                    script_sig: bitcoin::Script::from(i.script_sig.as_bytes().to_vec()),
                    sequence: bitcoin::Sequence::from_consensus(i.sequence.to_consensus_u32()),
                    witness: bitcoin::Witness::from_vec(i.witness.script_witness.clone()),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let tx_outs = elements_tx
            .output
            .iter()
            .map(|o| {
                let value = match o.value {
                    Value::Null | Value::Confidential(_) => {
                        return Err(TransactionConversionError::IncompatibleOutputType)
                    }
                    Value::Explicit(v) => v,
                };
                Ok(bitcoin::TxOut {
                    value,
                    script_pubkey: bitcoin::Script::from(o.script_pubkey.as_bytes().to_vec()),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(bitcoin::Transaction {
            version: elements_tx.version as i32,
            lock_time: bitcoin::PackedLockTime::from(bitcoin::LockTime::from_consensus(
                elements_tx.lock_time.to_u32(),
            )),
            input: tx_ins,
            output: tx_outs,
        })
    }
}

impl From<TxMerkleNode> for bitcoin::TxMerkleNode {
    fn from(merkle_node: TxMerkleNode) -> Self {
        bitcoin::TxMerkleNode::from_slice(merkle_node.as_ref()).expect("tx_merkle_node hash")
    }
}

impl From<bitcoin::TxMerkleNode> for TxMerkleNode {
    fn from(merkle_node: bitcoin::TxMerkleNode) -> Self {
        TxMerkleNode::from_slice(merkle_node.as_ref()).expect("tx_merkle_node hash")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use std::convert::TryInto;

    #[test]
    fn elements_bitcoin_transaction_conversion_roundtrip() {
        let tx_bytes = Vec::from_hex(
            "02000000000101595895ea20179de87052b4046dfe6fd515860505d6511a9004cf12a1f93cac7c01000000\
            00ffffffff01deb807000000000017a9140f3444e271620c736808aa7b33e370bd87cb5a078702483045022\
            100fb60dad8df4af2841adc0346638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd271\
            0e626347d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c007176ed89410\
            55d3bcb8627d085e94553e62f057dcc00000000"
        ).unwrap();
        let btc_tx: bitcoin::Transaction = deserialize(&tx_bytes).unwrap();
        let elements_tx: Transaction = btc_tx.clone().into();
        let converted_btc_tx: bitcoin::Transaction = elements_tx.try_into().unwrap();
        assert_eq!(btc_tx, converted_btc_tx);
    }
}
