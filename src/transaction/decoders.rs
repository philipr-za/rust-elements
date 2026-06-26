// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction Decoders
//!
//! These are encapsulated because there are many of them, but in the end we
//! only expose the top-level ones outside of this module.

use core::fmt;

use super::{TxOut, TxOutWitness};
use crate::encoding::{
    Decode, Decoder, Decoder2, Decoder2Error, Decoder4, Decoder4Error, DecoderStatus,
};

decoder_newtype! {
    /// Decoder for the [`TxOutWitness`] type.
    #[derive(Default)]
    pub struct TxOutWitnessDecoder(Decoder2<
        crate::confidential::SurjectionProofDecoder,
        crate::confidential::RangeProofDecoder,
    >);

    /// Decoder error for the [`TxOutWitness`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TxOutWitnessDecoderError(Decoder2Error<
        crate::confidential::SurjectionProofDecoderError,
        crate::confidential::RangeProofDecoderError,
    >);
    const ERROR_DISPLAY = "error decoding transaction output witness";

    impl Decode for TxOutWitness {
        fn convert_inner(output) -> Result<_, TxOutWitnessDecoderErrorInner> {
            let (surjection_proof, rangeproof) = output;
            Ok(TxOutWitness {surjection_proof, rangeproof })
        }
    }
}

/// An decoder for the witnesses in a sequence of [`TxOut`]s.
///
/// Comsumes a vec of [`TxOut`]s on construction and then yields that
/// same vector, with the witness fields overwritten.
#[derive(Default)]
struct TxOutWitnessesDecoder {
    txouts: Vec<TxOut>,
    index: usize,
    // Invariant: if this is Some then
    decoder: Option<TxOutWitnessDecoder>,
}

impl TxOutWitnessesDecoder {
    #[allow(dead_code)] // will be used in the Transaction Encode/Decode commit
    fn new(txouts: Vec<TxOut>) -> Self { Self { txouts, index: 0, decoder: None } }
}

impl Decoder for TxOutWitnessesDecoder {
    type Output = Vec<TxOut>;
    type Error = TxOutWitnessDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        loop {
            let Some(next_txout) = self.txouts.get_mut(self.index) else {
                return Ok(DecoderStatus::Ready);
            };

            let mut decoder = self.decoder.take().unwrap_or_else(TxOutWitness::decoder);
            if decoder.push_bytes(bytes)?.needs_more() {
                self.decoder = Some(decoder);
                return Ok(DecoderStatus::NeedsMore);
            }
            next_txout.witness = decoder.end()?;
            self.index += 1;
        }
    }

    fn end(mut self) -> Result<Self::Output, Self::Error> {
        loop {
            let Some(last_txout) = self.txouts.get_mut(self.index) else {
                return Ok(self.txouts);
            };

            last_txout.witness = self.decoder.take().unwrap_or_else(TxOutWitness::decoder).end()?;
            self.index += 1;
        }
    }

    fn read_limit(&self) -> usize {
        self.decoder.as_ref().map_or(0, TxOutWitnessDecoder::read_limit)
    }
}

decoder_newtype! {
    /// Decoder for the [`TxOut`] type.
    #[derive(Default)]
    pub struct TxOutDecoder(Decoder4<
        crate::confidential::AssetDecoder,
        crate::confidential::ValueDecoder,
        crate::confidential::NonceDecoder,
        crate::script::ScriptDecoder,
    >);


    /// Decoder error for the [`TxOut`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TxOutDecoderError(Decoder4Error<
            crate::confidential::AssetDecoderError,
            crate::confidential::ValueDecoderError,
            crate::confidential::NonceDecoderError,
            crate::script::ScriptDecoderError,
    >);
    const ERROR_DISPLAY = "error decoding transaction output witness";

    impl Decode for TxOut {
        fn convert_inner(output) -> Result<_, TxOutDecoderErrorInner> {
            let (asset, value, nonce, script_pubkey) = output;
            Ok(TxOut { asset, value, nonce, script_pubkey, witness: TxOutWitness::empty() })
        }
    }
}
