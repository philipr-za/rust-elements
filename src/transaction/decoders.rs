// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction Decoders
//!
//! These are encapsulated because there are many of them, but in the end we
//! only expose the top-level ones outside of this module.

use core::fmt;

use super::{TxOut, TxOutWitness};
use crate::encoding::{Decoder4, Decoder4Error};

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
