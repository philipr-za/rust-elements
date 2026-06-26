// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction Encoders
//!
//! These are encapsulated because there are many of them, but in the end we
//! only expose the top-level ones outside of this module.

use super::{TxOut, TxOutWitness};
use crate::encoding::{encoder_newtype_exact, Encode, Encoder, Encoder2, Encoder4, EncoderStatus};

encoder_newtype_exact! {
    /// Encoder for the [`TxOutWitness`] type.
    #[derive(Clone, Debug)]
    pub struct TxOutWitnessEncoder<'e>(Encoder2<
        crate::confidential::SurjectionProofEncoder<'e>,
        crate::confidential::RangeProofEncoder<'e>,
    >);
}

impl Encode for TxOutWitness {
    type Encoder<'e> = TxOutWitnessEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        TxOutWitnessEncoder::new(Encoder2::new(
            self.surjection_proof.encoder(),
            self.rangeproof.encoder(),
        ))
    }
}

/// An encoder for the witnesses in a sequence of [`TxOut`]s.
#[derive(Clone, Debug)]
struct TxOutWitnessesEncoder<'e> {
    txouts: &'e [TxOut],
    cur_enc: Option<TxOutWitnessEncoder<'e>>,
}

impl<'e> TxOutWitnessesEncoder<'e> {
    #[allow(dead_code)] // will be used in the Transaction Encode/Decode commit
    fn new(txouts: &'e [TxOut]) -> Self {
        Self { txouts, cur_enc: txouts.first().map(|txout| txout.witness.encoder()) }
    }
}

impl Encoder for TxOutWitnessesEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        self.cur_enc.as_ref().map(Encoder::current_chunk).unwrap_or_default()
    }

    fn advance(&mut self) -> EncoderStatus {
        let Some(cur) = self.cur_enc.as_mut() else {
            return EncoderStatus::Finished;
        };

        loop {
            if cur.advance().has_more() {
                return EncoderStatus::HasMore;
            }
            // self.inputs guaranteed to be non-empty if cur_enc is non-None.
            self.txouts = &self.txouts[1..];
            if let Some(txout) = self.txouts.first() {
                *cur = txout.witness.encoder();
                if !cur.current_chunk().is_empty() {
                    return EncoderStatus::HasMore;
                }
            } else {
                self.cur_enc = None;
                return EncoderStatus::Finished;
            }
        }
    }
}

encoder_newtype_exact! {
    /// Encoder for the [`TxOut`] type.
    #[derive(Clone, Debug)]
    pub struct TxOutEncoder<'e>(Encoder4<
        crate::confidential::AssetEncoder<'e>,
        crate::confidential::ValueEncoder<'e>,
        crate::confidential::NonceEncoder<'e>,
        crate::script::ScriptEncoder<'e>,
    >);
}

impl Encode for TxOut {
    type Encoder<'e> = TxOutEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        TxOutEncoder::new(Encoder4::new(
            self.asset.encoder(),
            self.value.encoder(),
            self.nonce.encoder(),
            self.script_pubkey.encoder(),
        ))
    }
}
