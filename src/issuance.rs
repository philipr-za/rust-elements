// Rust Elements Library
// Written in 2019 by
//   The Elements developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Asset Issuance

use std::io;
use std::str::FromStr;
use bitcoin::constants::ChainHash;
use crate::encode::{self, Encodable, Decodable};
use crate::hashes::{self, hash_newtype, sha256, sha256d, Hash};
use crate::fast_merkle_root::fast_merkle_root;
use secp256k1_zkp::Tag;
use crate::genesis::{commit_to_custom_network_parameters, NetworkParams};
use crate::{Network, Txid};
use crate::transaction::OutPoint;

/// The zero hash.
const ZERO32: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// The one hash.
const ONE32: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// The two hash.
const TWO32: [u8; 32] = [
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

hash_newtype!(
    /// The hash of an asset contract.", tru)
    #[hash_newtype(backward)]
    pub struct ContractHash(sha256::Hash);
);

impl ContractHash {
    /// Calculate the contract hash of a JSON contract object.
    ///
    /// This method does not perform any validation of the contents of the contract.
    /// After basic JSON syntax validation, the object is formatted in a standard way to calculate
    /// the hash.
    #[cfg(feature = "json-contract")]
    pub fn from_json_contract(json: &str) -> Result<ContractHash, ::serde_json::Error> {
        // Parsing the JSON into a BTreeMap will recursively order object keys
        // lexicographically. This order is respected when we later serialize
        // it again.
        let ordered: ::std::collections::BTreeMap<String, ::serde_json::Value> =
            ::serde_json::from_str(json)?;

        let mut engine = ContractHash::engine();
        ::serde_json::to_writer(&mut engine, &ordered).expect("engines don't error");
        Ok(ContractHash::from_engine(engine))
    }
}

/// An issued asset ID.
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct AssetId(sha256::Midstate);

impl AssetId {
    /// The asset ID for L-BTC, Bitcoin on the Liquid network.
    pub const LIQUID_BTC: AssetId = AssetId(sha256::Midstate([
        0x6d, 0x52, 0x1c, 0x38, 0xec, 0x1e, 0xa1, 0x57,
        0x34, 0xae, 0x22, 0xb7, 0xc4, 0x60, 0x64, 0x41,
        0x28, 0x29, 0xc0, 0xd0, 0x57, 0x9f, 0x0a, 0x71,
        0x3d, 0x1c, 0x04, 0xed, 0xe9, 0x79, 0x02, 0x6f,
    ]));

    /// The asset ID for L-BTC, Bitcoin on the Liquidtestnet network.
    pub const LIQUIDTESTNET_BTC: AssetId = AssetId(sha256::Midstate([
        0x49, 0x9a, 0x81, 0x85, 0x45, 0xf6, 0xba, 0xe3,
        0x9f, 0xc0, 0x3b, 0x63, 0x7f, 0x2a, 0x4e, 0x1e,
        0x64, 0xe5, 0x90, 0xca, 0xc1, 0xbc, 0x3a, 0x6f,
        0x6d, 0x71, 0xaa, 0x44, 0x43, 0x65, 0x4c, 0x14,
    ]));

    /// Create an [AssetId] from its inner type.
    pub fn from_inner(midstate: sha256::Midstate) -> AssetId {
        AssetId(midstate)
    }

    /// Convert the [AssetId] into its inner type.
    pub fn into_inner(self) -> sha256::Midstate {
        self.0
    }

    /// Copies a byte slice into an AssetId object
    pub fn from_slice(sl: &[u8]) -> Result<AssetId, hashes::Error> {
        sha256::Midstate::from_slice(sl).map(AssetId)
    }

    /// Generate the asset entropy from the issuance prevout and the contract hash.
    pub fn generate_asset_entropy(
        prevout: OutPoint,
        contract_hash: ContractHash,
    ) -> sha256::Midstate {
        // E : entropy
        // I : prevout
        // C : contract
        // E = H( H(I) || H(C) )
        let prevout_hash = {
            let mut enc = sha256d::Hash::engine();
            prevout.consensus_encode(&mut enc).unwrap();
            sha256d::Hash::from_engine(enc)
        };
        fast_merkle_root(&[prevout_hash.to_byte_array(), contract_hash.to_byte_array()])
    }

    /// Calculate the asset ID from the asset entropy.
    pub fn from_entropy(entropy: sha256::Midstate) -> AssetId {
        // H_a : asset tag
        // E   : entropy
        // H_a = H( E || 0 )
        AssetId(fast_merkle_root(&[entropy.to_byte_array(), ZERO32]))
    }

    /// Computes the asset ID when issuing asset from issuing input and contract hash
    pub fn new_issuance(prevout: OutPoint, contract_hash: ContractHash) -> Self {
        let entropy = AssetId::generate_asset_entropy(prevout, contract_hash);
        AssetId::from_entropy(entropy)
    }

    /// Computes the re-issuance token from input and contract hash
    pub fn new_reissuance_token(prevout: OutPoint, contract_hash: ContractHash, confidential: bool) -> Self {
        let entropy = AssetId::generate_asset_entropy(prevout, contract_hash);
        AssetId::reissuance_token_from_entropy(entropy, confidential)
    }

    /// Calculate the reissuance token asset ID from the asset entropy.
    pub fn reissuance_token_from_entropy(entropy: sha256::Midstate, confidential: bool) -> AssetId {
        // H_a : asset reissuance tag
        // E   : entropy
        // if not fConfidential:
        //     H_a = H( E || 1 )
        // else
        //     H_a = H( E || 2 )
        let second = match confidential {
            false => ONE32,
            true => TWO32,
        };
        AssetId(fast_merkle_root(&[entropy.to_byte_array(), second]))
    }

    /// Convert an asset into [Tag]
    pub fn into_tag(self) -> Tag {
        self.0.to_byte_array().into()
    }

    /// Pegged asset id for given network parameters
    pub fn pegged_asset_id_for_network_params(params: NetworkParams) -> Option<AssetId> {
        match params.network {
            Network::Liquidv1 => Some(Self::LIQUID_BTC),
            Network::Liquidtestnet => Some(Self::LIQUIDTESTNET_BTC),
            Network::Elementsregtest(ref network_str) => {
                // Check the two most common Regtest network strings used by CLN and Liquid and
                // return precalculated AssetId's for them
                if network_str.as_str() == "elementsregtest" {
                    return Some(AssetId(sha256::Midstate([
                        0x23, 0x0f, 0x4f, 0x5d, 0x4b, 0x7c, 0x6f, 0xa8, 0x45, 0x80, 0x6e, 0xe4,
                        0xf6, 0x77, 0x13, 0x45, 0x9e, 0x1b, 0x69, 0xe8, 0xe6, 0x0f, 0xce, 0xe2,
                        0xe4, 0x94, 0x0c, 0x7a, 0x0d, 0x5d, 0xe1, 0xb2,
                    ])));
                }

                if network_str.as_str() == "liquid-regtest" {
                    return Some(AssetId(sha256::Midstate([
                        0x5c, 0xe7, 0xb9, 0x63, 0xd3, 0x7f, 0x8f, 0x2d, 0x51, 0xca, 0xfb, 0xba,
                        0x92, 0x8a, 0xaa, 0x9e, 0x22, 0x0b, 0x8b, 0xbc, 0x66, 0x05, 0x71, 0x49,
                        0x9c, 0x03, 0x62, 0x8a, 0x38, 0x51, 0xb8, 0xce,
                    ])));
                }

                // Current liquidv1test testnet
                if network_str.as_str() == "liquidv1test" {
                    return Some(AssetId(sha256::Midstate([
                        0x0d, 0xc0, 0x42, 0x8c, 0xd0, 0x9f, 0x51, 0xea, 0x24, 0x89, 0x7b, 0xc0,
                        0x58, 0xa8, 0x61, 0x6e, 0x38, 0xd7, 0x53, 0x81, 0x9c, 0xd0, 0xb7, 0xe3,
                        0xb0, 0x78, 0x72, 0xff, 0x1c, 0xcc, 0x32, 0x25,
                    ])));
                }

                // Else calculate the asset_id
                let asset_id = Self::pegged_asset_id_for_params_and_parent_chain_hash(
                    &params,
                    bitcoin::Network::Regtest.chain_hash()
                );
                Some(asset_id)
            }
            _ => None,
        }
    }

    /// Calculate the AssetId for the pegged asset for a given set of network parameters assuming
    /// a Regtest parent network
    fn pegged_asset_id_for_params_and_parent_chain_hash(params: &NetworkParams, parent_chainhash: bitcoin::blockdata::constants::ChainHash) -> AssetId {
        let commit = commit_to_custom_network_parameters(params);
        let asset_outpoint = OutPoint::new(Txid::from_slice(commit.as_slice()).expect("txid"), 0);
        let asset_entropy = AssetId::generate_asset_entropy(asset_outpoint, ContractHash::from_slice(parent_chainhash.to_bytes().as_slice()).unwrap());
        AssetId::from_entropy(asset_entropy)
    }
}

impl ::std::fmt::Display for AssetId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self.0, f)
    }
}

impl ::std::fmt::Debug for AssetId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}

impl ::std::fmt::LowerHex for AssetId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl FromStr for AssetId {
    type Err = crate::hashes::hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        sha256::Midstate::from_str(s).map(AssetId)
    }
}

impl Encodable for AssetId {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, encode::Error> {
        self.0.consensus_encode(e)
    }
}

impl Decodable for AssetId {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        Ok(Self::from_inner(sha256::Midstate::consensus_decode(d)?))
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for AssetId {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use crate::hex::ToHex;
        if s.is_human_readable() {
            s.serialize_str(&self.to_hex())
        } else {
            s.serialize_bytes(&self.0[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for AssetId {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<AssetId, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = AssetId;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if let Ok(hex) = ::std::str::from_utf8(v) {
                        AssetId::from_str(hex).map_err(E::custom)
                    } else {
                        return Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self));
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    AssetId::from_str(v).map_err(E::custom)
                }
            }

            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = AssetId;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if v.len() != 32 {
                        Err(E::invalid_length(v.len(), &stringify!($len)))
                    } else {
                        let mut ret = [0; 32];
                        ret.copy_from_slice(v);
                        Ok(AssetId(sha256::Midstate::from_byte_array(ret)))
                    }
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    use crate::hashes::sha256;
    use crate::hex::FromHex;
    use crate::Script;

    #[test]
    fn example_elements_core() {
        // example test data from Elements Core 0.17
        let prevout_str = "05a047c98e82a848dee94efcf32462b065198bebf2404d201ba2e06db30b28f4:0";
        let entropy_hex = "746f447f691323502cad2ef646f932613d37a83aeaa2133185b316648df4b70a";
        let asset_id_hex = "dcd60818d863b5c026c40b2bc3ba6fdaf5018bcc8606c18adf7db4da0bcd8533";
        let token_id_hex = "c1adb114f4f87d33bf9ce90dd4f9ca523dd414d6cd010a7917903e2009689530";

        let contract_hash = ContractHash::from_byte_array(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_str(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_str(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_str(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, false), token_id);

        // example test data from Elements Core 0.21 with prevout vout = 1
        let prevout_str = "c76664aa4be760056dcc39b59637eeea8f3c3c3b2aeefb9f23a7b99945a2931e:1";
        let entropy_hex = "bc67a13736341d8ad19e558433483a38cae48a44a5a8b5598ca0b01b5f9f9f41";
        let asset_id_hex = "2ec6c1a06e895b06fffb8dc36084255f890467fb906565b0c048d4c807b4a129";
        let token_id_hex = "d09d205ff7c626ca98c91fed24787ff747fec62194ed1b7e6ef6cc775a1a1fdc";

        let contract_hash = ContractHash::from_byte_array(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_str(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_str(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_str(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, true), token_id);


        // example test data from Elements Core 0.21 with a given contract hash and non-blinded issuance
        let prevout_str = "ee45365ddb62e8822182fbdd132fb156b4991e0b7411cff4aab576fd964f2edb:0"; // txid parsed reverse
        let contract_hash_hex = "e06e6d4933e76afd7b9cc6a013e0855aa60bbe6d2fca1c27ec6951ff5f1a20c9"; // parsed reverse
        let entropy_hex = "1922da340705eef526640b49d28b08928630d1ad52db0f945f3c389267e292c9"; // parsed reverse
        let asset_id_hex = "8eebf6109bca0331fe559f0cbd1ef846a2bbb6812f3ae3d8b0b610170cc21a4e"; // parsed reverse
        let token_id_hex = "eb02cbc591c9ede071625c129f0a1fab386202cb27a894a45be0d564e961d6bc"; // parsed reverse

        let contract_hash = ContractHash::from_str(contract_hash_hex).unwrap();
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_str(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_str(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_str(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, false), token_id);

        // example test data from Elements Core 0.21
        // with confidential re-issuance
        let prevout_str = "8903ee739b52859877fbfedc58194c2d59d0f5a4ea3c2774dc3cba3031cec757:0";
        let entropy_hex = "b9789de8589dc1b664e4f2bda4d04af9d4d2180394a8c47b1f889acfb5e0acc4";
        let asset_id_hex = "bdab916e8cda17781bcdb84505452e44d0ab2f080e9e5dd7765ffd5ce0c07cd9";
        let token_id_hex = "f144868169dfc7afc024c4d8f55607ac8dfe925e67688650a9cdc54c3cfa5b1c";

        let contract_hash = ContractHash::from_byte_array(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_str(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_str(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_str(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, true), token_id);
    }

    #[cfg(feature = "json-contract")]
    #[test]
    fn test_json_contract() {
        let tether = ContractHash::from_str("3c7f0a53c2ff5b99590620d7f6604a7a3a7bfbaaa6aa61f7bfc7833ca03cde82").unwrap();

        let correct = r#"{"entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0}"#;
        let expected = ContractHash::hash(correct.as_bytes());
        assert_eq!(tether, expected);
        assert_eq!(expected, ContractHash::from_json_contract(correct).unwrap());

        let invalid_json = r#"{"entity":{"domain":"tether.to"},"issuer_pubkey:"#;
        assert!(ContractHash::from_json_contract(invalid_json).is_err());

        let unordered = r#"{"precision":8,"ticker":"USDt","entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","version":0}"#;
        assert_eq!(expected, ContractHash::from_json_contract(unordered).unwrap());

        let unordered = r#"{"precision":8,"name":"Tether USD","ticker":"USDt","entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","version":0}"#;
        assert_eq!(expected, ContractHash::from_json_contract(unordered).unwrap());

        let spaces = r#"{"precision":8, "name" : "Tether USD", "ticker":"USDt",  "entity":{"domain":"tether.to" }, "issuer_pubkey" :"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","version":0} "#;
        assert_eq!(expected, ContractHash::from_json_contract(spaces).unwrap());

        let nested_correct = r#"{"entity":{"author":"Tether Inc","copyright":2020,"domain":"tether.to","hq":"Mars"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0}"#;
        let nested_expected = ContractHash::hash(nested_correct.as_bytes());
        assert_eq!(nested_expected, ContractHash::from_json_contract(nested_correct).unwrap());

        let nested_unordered = r#"{"ticker":"USDt","entity":{"domain":"tether.to","hq":"Mars","author":"Tether Inc","copyright":2020},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"version":0}"#;
        assert_eq!(nested_expected, ContractHash::from_json_contract(nested_unordered).unwrap());
    }

    #[test]
    fn liquid() {
        assert_eq!(
            AssetId::LIQUID_BTC.to_string(),
            "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
        );
    }

    #[test]
    fn lquid_testnet() {
        // Manually calculate the AssetID for liquid testnet, it different from the regtest networks
        // in that its parent chainhash is [0u8; 32]
        let testnet_network_params = NetworkParams::new(Network::Liquidtestnet).unwrap();

        let asset_id = AssetId::pegged_asset_id_for_params_and_parent_chain_hash(
            &testnet_network_params,
            ChainHash::from([0u8;32])
        );

        assert_eq!(asset_id, AssetId::LIQUIDTESTNET_BTC);
    }

    #[test]
    fn liquid_regtest() {
        let network_params = NetworkParams::new(Network::Elementsregtest("elementsregtest".to_string())).unwrap();
        let asset_id = AssetId::pegged_asset_id_for_params_and_parent_chain_hash(
            &network_params,
            bitcoin::Network::Regtest.chain_hash()
        );
        assert_eq!(asset_id, AssetId::pegged_asset_id_for_network_params(network_params).unwrap());

        let network_params = NetworkParams::new(Network::Elementsregtest("liquid-regtest".to_string())).unwrap();
        let asset_id = AssetId::pegged_asset_id_for_params_and_parent_chain_hash(
            &network_params,
            bitcoin::Network::Regtest.chain_hash()
        );
        assert_eq!(asset_id, AssetId::pegged_asset_id_for_network_params(network_params).unwrap());

        // These are the current network parameters for liquidv1test
        let liquidv1test_fedpeg_script_str = "745c87635b21022944b3c8d83d743e83e12b8a5654a9a48d741bae19f0498dd390b038502666b021023927b2c7716358d4f46cc1f8ca753f35818f593bd62ab2e19137522c35d671b721024c726615f549b02ea1db0fd2ab1973bfe20c296aa4ef14f8979da609b88caa6121027d8facb30d8648cbcea166f6094d1631053800332469827f90c5338368e48e3d2102a5ffc6da600cf25ebc01c4dfbe8ba220a0d35615db1a2c306ba06a355c34902b2102ab5b0b8e18d0dd7933176bbe0d0883a360ade9f45403accf7bdfa9c5439514f62102b0ffa5f8a78dd356afecc371bd826acb3671d8627561289d89a627a121a9c2272102b3278e89c3d5c19cbe5956d4a70a93a3bb0da4e8598d13c034ec5d50cce06b542102b43e4bd6c19b984ef36db6a622eea478f955676fe26786c3141b001e8f91402c2102e5a7aedc7889cad6f14d4534b546cd55d1fde039b0dd1ccb4c58ceac246327f72102e5fe77826e39e69421a0b478419a984c45d94228702aeac2acd540839fd034742103595fa9737e2720b9f600926f2350b4b1315b2248b76ef27fa287022609caead82103f2bbf79daf114617f35e719c46790c301ade558c247ced15f745a40db256a1e62103f4f161336c18c9095aff80aa38ca0417c345f73c73937298d49859e5bf7066e02103fec9f90addc21da7fa30da1568c8a5432a2372e89e8616468d55196c6ea2a7a25f6702c00fb275522102aef2b8a39966d49183fdddaefdc75af6d81ea6d16f7aba745cc4855e88f830842102141d452c3deeb937efff9f3378cd50bbde0543b77bbc6df6fc0e0addbf5578c52103948d24a9622cb14b198aed0739783d7c03d74c32c05780a86b43429c65679def5368ae";
        let liquidv1test_signblock_script_str = "5b210208aab5bf120357aca12e5ea45b91f0e17899fb279d8b229b85144b2c6551847f210216dadbbcf20a75879a30395a8c9cdd38cd0425fbba9f9ffed6fb87b8567ce25a21022858265f4c09613a51d084bdc8de89bfd147626563435291317583246d70b7f1210263926c0110698e652d714436928ea3c3d5d00cc98672921b54ccba166138bfe421026f2a2094ad8b736a6238a2fc4bfe791436b0d4572521ed7b090d759b37bb960221028054e650d5daf2f8bbcbd9873384bf3c0c42118c6adaf8efdde3177d4538c3c12102ac6b43c5383a584ac96d00be92e0fd46edf3680391aad3b40aa72a296927f2472102df7b7e95765d4bc1242f336316e739f603408c5634924246c6726ef2e27300dd210345a2ab572c0471246d6a72cff095181ca10d47c64dd851a1243408b1dd9592f621035733ece61055d7530656f255f3af86b15e3a40eef946a9a640ddcf9cd7068cb12103651eecb547012ce45886c3178bacc683c065b62bdfd5a864b0759ab515af30cf2103a3589af52990e1407f3288ec295e00b1fb6f9df5f3bae37e91da3efd7fc0da8c2103ae5ef1d819281f6b0200d13e2a09cc567fb4cd088d0470f1a0d434eb45f2b2e52103d6265f258ddf00666c0e7ec1abd783e8f960066f5a0fe13e73f268fdf834b9ca2103ee0e6833bc8505c625bcec502a6eecc5eeed4898d176bf9abed9f7c21887e5cc5fae";
        let liquidv1test_params = NetworkParams::new_custom(
            Network::Elementsregtest("liquidv1test".to_string()),
            Script::from_hex(liquidv1test_fedpeg_script_str).unwrap(),
            Script::from_hex(liquidv1test_signblock_script_str).unwrap(),
            0,
        )
            .unwrap();
        let asset_id = AssetId::pegged_asset_id_for_params_and_parent_chain_hash(
            &liquidv1test_params,
            bitcoin::Network::Regtest.chain_hash()
        );
        assert_eq!(asset_id, AssetId::pegged_asset_id_for_network_params(liquidv1test_params).unwrap());
    }
}
