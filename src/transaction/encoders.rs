// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction Encoders
//!
//! These are encapsulated because there are many of them, but in the end we
//! only expose the top-level ones outside of this module.

use super::TxOut;
use crate::encoding::{encoder_newtype_exact, Encode, Encoder4};

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
