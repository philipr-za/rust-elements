//! Canonical conversion between bitcoin and elements types
//! This is useful to leverage libraries that can generate bitcoin scripts and validate bitcoin
//! policies that can be applied to explicit elements transactions i.e. Lightning signers

use crate::confidential::Value;
use crate::genesis::NetworkParams;
use crate::{
    confidential, AssetId, BlockHash, LockTime, Network, OutPoint, Script, Sequence, Transaction,
    TxIn, TxInWitness, TxMerkleNode, TxOut, Txid,
};
use core::fmt::{Display, Formatter};
use std::convert::{TryFrom, TryInto};
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

impl From<bitcoin::ScriptBuf> for Script {
    fn from(bitcoin_script: bitcoin::ScriptBuf) -> Self {
        bitcoin_script.to_bytes().into()
    }
}

impl From<Script> for bitcoin::ScriptBuf {
    fn from(script: Script) -> Self {
        script.to_bytes().into()
    }
}

impl From<bitcoin::Txid> for Txid {
    fn from(bitcoin_txid: bitcoin::Txid) -> Self {
        Txid::from_raw_hash(bitcoin_txid.to_raw_hash())
    }
}

impl From<Txid> for bitcoin::Txid {
    fn from(elements_txid: Txid) -> Self {
        bitcoin::Txid::from_raw_hash(elements_txid.to_raw_hash())
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
        bitcoin::BlockHash::from_raw_hash(blockhash.to_raw_hash())
    }
}

impl From<bitcoin::BlockHash> for BlockHash {
    fn from(blockhash: bitcoin::BlockHash) -> Self {
        BlockHash::from_raw_hash(blockhash.to_raw_hash())
    }
}

/// Trait defining how to turn a struct into an Elements transaction
pub trait ToElementsTransaction {

    /// Convert to Elements transaction
    fn to_elements_transaction(&self, network: Network) -> Transaction;
}

impl ToElementsTransaction for bitcoin::Transaction {
    fn to_elements_transaction(&self, network: Network) -> Transaction {
        let tx_ins = self
            .input
            .iter()
            .cloned()
            .map(Into::into)
            .collect::<Vec<_>>();

        let tx_outs = self
            .output
            .iter()
            .cloned()
            .map(|out| out.to_elements_txout(network.clone()))
            .collect::<Vec<_>>();

        Transaction {
            version: self.version as u32,
            lock_time: LockTime::from_consensus(self.lock_time.to_consensus_u32()),
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
                let txin: bitcoin::TxIn = i.clone().try_into()?;
                Ok(txin)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let tx_outs = elements_tx
            .output
            .iter()
            .filter(|o| !o.is_fee())// Bitcoin transaction don't include explicit fee outputs
            .map(|o| {
                let txout: bitcoin::TxOut = o.clone().try_into()?;
                Ok(txout)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(bitcoin::Transaction {
            version: elements_tx.version as i32,
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(
                elements_tx.lock_time.to_consensus_u32(),
            ),
            input: tx_ins,
            output: tx_outs,
        })
    }
}

impl TryFrom<TxIn> for bitcoin::TxIn {
    type Error = TransactionConversionError;

    fn try_from(elements_txin: TxIn) -> Result<Self, Self::Error> {
        if !elements_txin.witness.pegin_witness.is_empty()
            || elements_txin.witness.amount_rangeproof.is_some()
            || elements_txin.witness.inflation_keys_rangeproof.is_some()
        {
            return Err(TransactionConversionError::IncompatibleWitness);
        }
        Ok(bitcoin::TxIn {
            previous_output: elements_txin.previous_output.into(),
            script_sig: bitcoin::ScriptBuf::from(elements_txin.script_sig.as_bytes().to_vec()),
            sequence: bitcoin::Sequence::from_consensus(elements_txin.sequence.to_consensus_u32()),
            witness: bitcoin::Witness::from_slice(elements_txin.witness.script_witness.as_slice()),
        })
    }
}

impl From<bitcoin::TxIn> for TxIn {
    fn from(bitcoin_txin: bitcoin::TxIn) -> Self {
        TxIn {
            previous_output: bitcoin_txin.previous_output.into(),
            is_pegin: false,
            script_sig: Script::from(bitcoin_txin.script_sig.as_bytes().to_vec()),
            sequence: Sequence::from_consensus(bitcoin_txin.sequence.to_consensus_u32()),
            asset_issuance: Default::default(),
            witness: TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness: bitcoin_txin.witness.to_vec(),
                pegin_witness: vec![],
            },
        }
    }
}

impl TryFrom<TxOut> for bitcoin::TxOut {
    type Error = TransactionConversionError;

    fn try_from(elements_txout: TxOut) -> Result<Self, Self::Error> {
        let value = match elements_txout.value {
            Value::Null | Value::Confidential(_) => {
                return Err(TransactionConversionError::IncompatibleOutputType)
            }
            Value::Explicit(v) => v,
        };
        Ok(bitcoin::TxOut {
            value,
            script_pubkey: bitcoin::ScriptBuf::from(
                elements_txout.script_pubkey.as_bytes().to_vec(),
            ),
        })
    }
}

/// Trait defining how to turn a struct into an Elements transaction output
pub trait ToElementsTxOut {
    /// Convert to Elements transaction output
    fn to_elements_txout(&self, network: Network) -> TxOut;
}

impl ToElementsTxOut for bitcoin::TxOut {
    fn to_elements_txout(&self, network: Network) -> TxOut {
        let asset_id = match NetworkParams::new(network) {
            None => Default::default(),
            Some(params) => AssetId::pegged_asset_id_for_network_params(params).unwrap_or_default(),
        };

        TxOut {
            asset: confidential::Asset::Explicit(asset_id),
            value: confidential::Value::Explicit(self.value),
            nonce: Default::default(),
            script_pubkey: Script::from(self.script_pubkey.as_bytes().to_vec()),
            witness: Default::default(),
        }
    }
}

impl From<TxMerkleNode> for bitcoin::hash_types::TxMerkleNode {
    fn from(merkle_node: TxMerkleNode) -> Self {
        bitcoin::hash_types::TxMerkleNode::from_raw_hash(merkle_node.to_raw_hash())
    }
}

impl From<bitcoin::hash_types::TxMerkleNode> for TxMerkleNode {
    fn from(merkle_node: bitcoin::hash_types::TxMerkleNode) -> Self {
        TxMerkleNode::from_raw_hash(merkle_node.to_raw_hash())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use std::convert::TryInto;

    #[test]
    fn bitcoin_elements_transaction_conversion_roundtrip() {
        let tx_bytes = Vec::from_hex(
            "02000000000101595895ea20179de87052b4046dfe6fd515860505d6511a9004cf12a1f93cac7c01000000\
            00ffffffff01deb807000000000017a9140f3444e271620c736808aa7b33e370bd87cb5a078702483045022\
            100fb60dad8df4af2841adc0346638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd271\
            0e626347d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c007176ed89410\
            55d3bcb8627d085e94553e62f057dcc00000000"
        ).unwrap();
        let btc_tx: bitcoin::Transaction = deserialize(&tx_bytes).unwrap();
        let elements_tx: Transaction = btc_tx.clone().to_elements_transaction(Network::Liquidv1);
        let converted_btc_tx: bitcoin::Transaction = elements_tx.try_into().unwrap();
        assert_eq!(btc_tx, converted_btc_tx);
    }
}
