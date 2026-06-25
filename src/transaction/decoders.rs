// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction Decoders
//!
//! These are encapsulated because there are many of them, but in the end we
//! only expose the top-level ones outside of this module.

use core::fmt;

use super::{
    AssetIssuance, OutPoint, Script, Sequence, TxIn, TxInWitness, TxOut, TxOutWitness, Txid,
};
use crate::encoding::{
    ArrayDecoder, Decode, Decoder, Decoder2, Decoder2Error, Decoder3, Decoder4, Decoder4Error,
    DecoderStatus, UnexpectedEofError,
};

/// Decoder for the [`OutPoint`] type.
///
/// This is a non-public struct and we do not implement [`Decode`] for [`OutPoint`]
/// because we can't actually encode/decode outpoints independently of the rest of
/// a [`TxIn`]. This is because we mask bits into the vout of the outpoint.
#[derive(Default)]
struct OutPointDecoder {
    inner: Decoder2<ArrayDecoder<32>, ArrayDecoder<4>>,
}

/// Decoder error for the [`OutPoint`] type.
#[derive(Clone, PartialEq, Eq, Debug)]
struct OutPointDecoderError(Decoder2Error<UnexpectedEofError, UnexpectedEofError>);

impl fmt::Display for OutPointDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("error decoding outpoint")
    }
}

impl std::error::Error for OutPointDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl Decoder for OutPointDecoder {
    type Output = OutPoint;
    type Error = OutPointDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(OutPointDecoderError)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (txid, vout) = self.inner.end().map_err(OutPointDecoderError)?;
        Ok(OutPoint { txid: Txid::from_byte_array(txid), vout: u32::from_le_bytes(vout) })
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

decoder_newtype! {
    /// Decoder for the [`Sequence`] type.
    #[derive(Default)]
    pub struct SequenceDecoder(ArrayDecoder<4>);

    /// Decoder error for the [`Sequence`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SequenceDecoderError(UnexpectedEofError);
    const ERROR_DISPLAY = "error decoding sequence";

    impl Decode for Sequence {
        fn convert_inner(bytes) -> Result<_, UnexpectedEofError> {
            Ok(Sequence::from_consensus(u32::from_le_bytes(bytes)))
        }
    }
}

decoder_newtype! {
    /// Decoder for the [`AssetIssuance`] type.
    #[derive(Default)]
    pub struct AssetIssuanceDecoder(Decoder4<
        ArrayDecoder<32>,
        ArrayDecoder<32>,
        crate::confidential::ValueDecoder,
        crate::confidential::ValueDecoder,
    >);
    /// Decoder error for the [`AssetIssuance`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct AssetIssuanceDecoderError(enum AssetIssuanceDecoderErrorInner {
        Decode(Decoder4Error<
            UnexpectedEofError,
            UnexpectedEofError,
            crate::confidential::ValueDecoderError,
            crate::confidential::ValueDecoderError,
        >),
        InvalidTweak(secp256k1_zkp::Error),
    });

    impl Decode for AssetIssuance {
        fn convert_inner(output) -> Result<_, AssetIssuanceDecoderError> {
            let (asset_blinding_nonce, asset_entropy, amount, inflation_keys) = output;
            Ok(AssetIssuance {
                asset_blinding_nonce: secp256k1_zkp::Tweak::from_inner(asset_blinding_nonce)
                    .map_err(AssetIssuanceDecoderErrorInner::InvalidTweak)
                    .map_err(AssetIssuanceDecoderError)?,
                asset_entropy,
                amount,
                inflation_keys,
            })
        }
    }
}

impl fmt::Display for AssetIssuanceDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AssetIssuanceDecoderErrorInner as Inner;
        match self.0 {
            Inner::Decode(_) => f.write_str("error decoding asset issuance"),
            Inner::InvalidTweak(_) => f.write_str("asset issuance had out-of-range blinding nonce"),
        }
    }
}

impl std::error::Error for AssetIssuanceDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use AssetIssuanceDecoderErrorInner as Inner;
        match self.0 {
            Inner::Decode(ref e) => Some(e),
            Inner::InvalidTweak(ref e) => Some(e),
        }
    }
}

fn vout_is_pegin(vout: u32) -> bool { vout != 0xffff_ffff && vout & (1 << 30) != 0 }
fn vout_has_issuance(vout: u32) -> bool { vout != 0xffff_ffff && vout & (1 << 31) != 0 }

decoder_state_machine! {
    /// Decoder for the [`TxIn`] type.
    pub struct TxInDecoder(enum TxInDecoderInner {
        Done(TxIn),
        Errored,
        Initial {
            decoder: Decoder3<
                OutPointDecoder,
                crate::script::ScriptDecoder,
                SequenceDecoder,
            >,
            => transition_initial(output, ...) -> Result {
                let (mut outpoint, script_sig, sequence) = output;
                if vout_has_issuance(outpoint.vout) {
                    Ok(TxInDecoderInner::AssetIssuance {
                        decoder: AssetIssuanceDecoder::default(),
                        outpoint, script_sig, sequence,
                    })
                } else {
                    let orig_vout = outpoint.vout;
                    outpoint.vout &= !((1 << 30) | (1 << 31));
                    Ok(TxInDecoderInner::Done(TxIn {
                        previous_output: outpoint,
                        is_pegin: vout_is_pegin(orig_vout),
                        script_sig,
                        sequence,
                        asset_issuance: AssetIssuance::null(),
                        witness: TxInWitness::default(),
                    }))
                }
            }
        },
        AssetIssuance {
            decoder: AssetIssuanceDecoder,
            outpoint: OutPoint,
            script_sig: Script,
            sequence: Sequence
            => transition_asset_issuance(asset_issuance, ...) -> Result {
                if asset_issuance.is_null() {
                    return Err(TxInDecoderErrorInner::SuperfluousIssuance);
                }

                let orig_vout = outpoint.vout;
                let mut outpoint = outpoint;
                outpoint.vout &= !((1 << 30) | (1 << 31));
                Ok(TxInDecoderInner::Done(TxIn {
                    previous_output: outpoint,
                    is_pegin: vout_is_pegin(orig_vout),
                    script_sig,
                    sequence,
                    asset_issuance,
                    witness: TxInWitness::default(),
                }))
            }
        },
    });

    /// Decoder error for the [`TxIn`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TxInDecoderError(enum TxInDecoderErrorInner {
        [macro-inserted decoder variants]
        SuperfluousIssuance,
    });
}

impl Default for TxInDecoder {
    fn default() -> Self { Self(TxInDecoderInner::Initial { decoder: Decoder3::default() }) }
}

impl fmt::Display for TxInDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TxInDecoderErrorInner as Inner;
        match self.0 {
            Inner::Initial(..) => f.write_str("error decoding outpoint, scriptsig or sequence"),
            Inner::AssetIssuance(..) => f.write_str("error decoding asset issuance"),
            Inner::SuperfluousIssuance =>
                f.write_str("input had issuance flag set, but null issuance"),
        }
    }
}

impl std::error::Error for TxInDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TxInDecoderErrorInner as Inner;
        match self.0 {
            Inner::Initial(ref e) => Some(e),
            Inner::AssetIssuance(ref e) => Some(e),
            Inner::SuperfluousIssuance => None,
        }
    }
}

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
