// Rust Elements Library
// Written by
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

//! Genesis Blocks
//!

use crate::opcodes::all::OP_RETURN;
use crate::opcodes::OP_TRUE;
use crate::{confidential, script, AssetId, Block, BlockExtData, BlockHash, BlockHeader, LockTime, Script, Transaction, TxIn, TxOut};
use crate::{AssetIssuance, ContractHash, Network, OutPoint, Txid};
use crate::hashes::{sha256, sha256d, Hash, HashEngine};
use crate::hex::{FromHex, ToHex};
use crate::pset::serialize::Serialize;

/// Parameters that influence chain consensus. These are these default values. Test and Regtest networks
/// can have consensus parameters altered via configuration which could alter these values and the resulting
/// genesis block.
pub struct NetworkParams {
    /// Network these parameters refer to
    pub network: Network,
    /// This network's Fedpeg script
    pub fedpeg_script: Script,
    /// This network's sign_block_script
    pub sign_block_script: Script,
    /// How many free coins are present in this network
    pub initial_free_coins: u64,
}

impl NetworkParams {
    /// Default values of consensus parameters, these can be modified in `elementsd` using configuration.
    pub fn new(network: Network) -> Option<Self> {
        match network {
            Network::Bitcoin | Network::Testnet | Network::Signet | Network::Regtest => None,
            Network::Liquidv1 => Some(NetworkParams {
                network,
                fedpeg_script: Script::from_hex("745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae").expect("constant fedpeg script parse"),
                sign_block_script: Script::from_hex("5b21026a2a106ec32c8a1e8052e5d02a7b0a150423dbd9b116fc48d46630ff6e6a05b92102791646a8b49c2740352b4495c118d876347bf47d0551c01c4332fdc2df526f1a2102888bda53a424466b0451627df22090143bbf7c060e9eacb1e38426f6b07f2ae12102aee8967150dee220f613de3b239320355a498808084a93eaf39a34dcd62024852102d46e9259d0a0bb2bcbc461a3e68f34adca27b8d08fbe985853992b4b104e27412102e9944e35e5750ab621e098145b8e6cf373c273b7c04747d1aa020be0af40ccd62102f9a9d4b10a6d6c56d8c955c547330c589bb45e774551d46d415e51cd9ad5116321033b421566c124dfde4db9defe4084b7aa4e7f36744758d92806b8f72c2e943309210353dcc6b4cf6ad28aceb7f7b2db92a4bf07ac42d357adf756f3eca790664314b621037f55980af0455e4fb55aad9b85a55068bb6dc4740ea87276dc693f4598db45fa210384001daa88dabd23db878dbb1ce5b4c2a5fa72c3113e3514bf602325d0c37b8e21039056d089f2fe72dbc0a14780b4635b0dc8a1b40b7a59106325dd1bc45cc70493210397ab8ea7b0bf85bc7fc56bb27bf85e75502e94e76a6781c409f3f2ec3d1122192103b00e3b5b77884bf3cae204c4b4eac003601da75f96982ffcb3dcb29c5ee419b92103c1f3c0874cfe34b8131af34699589aacec4093399739ae352e8a46f80a6f68375fae").expect("constant sign_block_script parse"),
                initial_free_coins: 0,
            }),
            Network::Liquidtestnet => Some(NetworkParams {
                network,
                fedpeg_script: script::Builder::new().push_opcode(OP_TRUE).into_script(),
                sign_block_script: Script::from_hex("51210217e403ddb181872c32a0cd468c710040b2f53d8cac69f18dad07985ee37e9a7151ae").expect("constant sign_block_script parse"),
                initial_free_coins: 2100000000000000,
            }),
            Network::Elementsregtest => Some(NetworkParams {
                network,
                fedpeg_script: script::Builder::new().push_opcode(OP_TRUE).into_script(),
                sign_block_script: script::Builder::new().push_opcode(OP_TRUE).into_script(),
                initial_free_coins: 0,
            }),
            Network::Liquidv1test => Some(NetworkParams {
                network,
                fedpeg_script: script::Builder::new().push_opcode(OP_TRUE).into_script(),
                sign_block_script: script::Builder::new().push_opcode(OP_TRUE).into_script(),
                initial_free_coins: 0,
            }),
        }
    }

    /// Parameters for a network where the consensus parameters can be chosen. This is possible for
    /// `liquidv1test` and `elementsregtest` where these parameter can be changed in `elementsd` via
    /// configuration
    pub fn new_custom(
        network: Network,
        fedpeg_script: Script,
        sign_block_script: Script,
        initial_free_coins: u64,
    ) -> Option<NetworkParams> {
        match network {
            Network::Bitcoin
            | Network::Testnet
            | Network::Signet
            | Network::Regtest
            | Network::Liquidv1 => None,
            network => Some(NetworkParams {
                network,
                fedpeg_script,
                sign_block_script,
                initial_free_coins,
            }),
        }
    }
}

/// Hash commitment of network parameters for a given Network
fn commit_to_network_parameters(network: Network) -> Vec<u8> {
    let params = match NetworkParams::new(network) {
        None => return vec![],
        Some(p) => p,
    };
    let mut eng = sha256::Hash::engine();
    eng.input(network.to_core_arg().as_bytes());
    eng.input(params.fedpeg_script.to_hex().as_bytes());
    eng.input(params.sign_block_script.to_hex().as_bytes());
    sha256::Hash::from_engine(eng).serialize()
}

/// Produce the genesis transaction for a given elements Network
fn liquid_genesis_tx(network: Network) -> Transaction {
    let commit = commit_to_network_parameters(network);
    let input = TxIn {
        previous_output: Default::default(),
        is_pegin: false,
        script_sig: script::Builder::new()
            .push_slice(commit.as_slice())
            .into_script(),
        sequence: Default::default(),
        asset_issuance: Default::default(),
        witness: Default::default(),
    };

    let output = TxOut {
        asset: confidential::Asset::Explicit(AssetId::default()),
        value: confidential::Value::Explicit(0),
        nonce: Default::default(),
        script_pubkey: script::Builder::new().push_opcode(OP_RETURN).into_script(),
        witness: Default::default(),
    };

    let ret = Transaction {
        version: 1,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };
    ret
}

/// Create the confidential asset transaction for the genesis block if required by the specified Network
fn liquid_genesis_asset_tx(network: Network) -> Option<Transaction> {
    let commit = commit_to_network_parameters(network);
    let asset_amount = match NetworkParams::new(network) {
        None => return None,
        Some(p) => p.initial_free_coins,
    };
    if asset_amount == 0 {
        return None;
    }
    let asset_outpoint = OutPoint::new(Txid::from_slice(commit.as_slice()).expect("txid"), 0);
    let contract_hash = ContractHash::from_byte_array([0u8; 32]);
    let asset_entropy = AssetId::generate_asset_entropy(asset_outpoint, contract_hash);
    let asset_id = AssetId::from_entropy(asset_entropy);

    let asset_issuance = AssetIssuance {
        asset_blinding_nonce: Default::default(),
        asset_entropy: [0u8; 32],
        amount: confidential::Value::Explicit(asset_amount),
        inflation_keys: confidential::Value::Explicit(0),
    };

    let input = TxIn {
        previous_output: asset_outpoint,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Default::default(),
        asset_issuance,
        witness: Default::default(),
    };

    let output = TxOut {
        asset: confidential::Asset::Explicit(asset_id),
        value: confidential::Value::Explicit(asset_amount),
        nonce: Default::default(),
        script_pubkey: script::Builder::new().push_opcode(OP_TRUE).into_script(),
        witness: Default::default(),
    };

    let ret = Transaction {
        version: 1,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };
    Some(ret)
}

/// Constructs and returns the Liquid genesis blocks assuming default consensus parameters
/// Does not return upstream bitcoin network blocks as they are a different format and can be
/// acquired from the `rust-bitcoin` library
pub fn genesis_block(params: NetworkParams) -> Option<Block> {
    match params.network {
        Network::Bitcoin | Network::Testnet | Network::Signet | Network::Regtest => None,
        network => {
            let tx = liquid_genesis_tx(network);
            let mut txdata = vec![tx.clone()];

            let merkle_root: sha256d::Hash =
                if let Some(asset_tx) = liquid_genesis_asset_tx(network) {
                    txdata.push(asset_tx.clone());
                    let tx_hashes = vec![tx.txid().to_raw_hash(), asset_tx.txid().to_raw_hash()];
                    bitcoin::merkle_tree::calculate_root(tx_hashes.into_iter()).map(|h| h.into())
                        .expect("merkle root")
                } else {
                    tx.txid().to_raw_hash().into()
                };

            Some(Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: merkle_root.into(),
                    time: 1296688602,
                    height: 0,
                    ext: BlockExtData::Proof {
                        challenge: params.sign_block_script,
                        solution: Default::default(),
                    },
                },
                txdata,
            })
        }
    }
}

/// The uniquely identifying hash of the target blockchain.
/// Liquid networks assume default consensus constants, Elements allows for modification of fedpeg and signblock scripts
/// via configuration argument which will cause these values to differ
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet bitcoin.
    pub const BITCOIN: Self = Self([
        111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247, 79, 147, 30, 131,
        101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0,
    ]);
    /// `ChainHash` for testnet bitcoin.
    pub const TESTNET: Self = Self([
        67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174, 186, 121, 151,
        32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0,
    ]);
    /// `ChainHash` for signet bitcoin.
    pub const SIGNET: Self = Self([
        246, 30, 238, 59, 99, 163, 128, 164, 119, 160, 99, 175, 50, 178, 187, 201, 124, 159, 249,
        240, 31, 44, 66, 37, 233, 115, 152, 129, 8, 0, 0, 0,
    ]);
    /// `ChainHash` for regtest bitcoin.
    pub const REGTEST: Self = Self([
        6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94,
        51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15,
    ]);
    /// `ChainHash` for regtest bitcoin.
    pub const LIQUIDV1: Self = Self([
        3, 96, 32, 138, 136, 150, 146, 55, 44, 141, 104, 176, 132, 166, 46, 253, 246, 14, 161, 163,
        89, 160, 76, 148, 178, 13, 34, 54, 88, 39, 102, 20,
    ]);
    /// `ChainHash` for regtest bitcoin.
    pub const LIQUIDTESTNET: Self = Self([
        193, 177, 106, 226, 79, 36, 35, 174, 162, 234, 52, 85, 34, 146, 121, 59, 91, 94, 130, 153,
        154, 30, 237, 129, 213, 106, 238, 82, 142, 218, 113, 167,
    ]);
    /// `ChainHash` for regtest bitcoin.
    pub const ELEMENTSREGTEST: Self = Self([
        111, 57, 9, 232, 171, 11, 143, 239, 182, 165, 68, 183, 206, 181, 83, 12, 95, 212, 24, 26,
        185, 163, 32, 95, 130, 81, 95, 195, 132, 156, 23, 205,
    ]);
    /// `ChainHash` for regtest bitcoin.
    pub const LIQUIDV1TEST: Self = Self([
        59, 39, 190, 40, 70, 123, 208, 117, 200, 45, 32, 29, 136, 140, 166, 101, 199, 167, 51, 232,
        151, 206, 161, 90, 193, 119, 37, 21, 254, 92, 164, 48,
    ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block_const(network: Network) -> Self {
        let hashes = [
            Self::BITCOIN,
            Self::TESTNET,
            Self::SIGNET,
            Self::REGTEST,
            Self::LIQUIDV1,
            Self::LIQUIDTESTNET,
            Self::ELEMENTSREGTEST,
            Self::LIQUIDV1TEST,
        ];
        hashes[network as usize]
    }
}

#[cfg(test)]
mod test {
    use crate::genesis::{genesis_block, ChainHash, NetworkParams};
    use crate::{Network, Script};

    #[test]
    fn genesis_block_hash() {
        assert!(NetworkParams::new(Network::Bitcoin).is_none());
        assert!(NetworkParams::new(Network::Regtest).is_none());
        assert!(NetworkParams::new(Network::Signet).is_none());
        assert!(NetworkParams::new(Network::Testnet).is_none());

        //Liquid networks
        let genesis_block = genesis_block(NetworkParams::new(Network::Liquidv1).unwrap()).unwrap();
        assert_eq!(
            genesis_block.block_hash().as_ref(),
            ChainHash::using_genesis_block_const(Network::Liquidv1).0
        );
        let genesis_block =
            crate::genesis::genesis_block(NetworkParams::new(Network::Liquidtestnet).unwrap())
                .unwrap();
        assert_eq!(
            genesis_block.block_hash().as_ref(),
            ChainHash::using_genesis_block_const(Network::Liquidtestnet).0
        );
        let genesis_block =
            crate::genesis::genesis_block(NetworkParams::new(Network::Elementsregtest).unwrap())
                .unwrap();
        assert_eq!(
            genesis_block.block_hash().as_ref(),
            ChainHash::using_genesis_block_const(Network::Elementsregtest).0
        );
        let genesis_block =
            crate::genesis::genesis_block(NetworkParams::new(Network::Liquidv1test).unwrap())
                .unwrap();
        assert_eq!(
            genesis_block.block_hash().as_ref(),
            ChainHash::using_genesis_block_const(Network::Liquidv1test).0
        );

        let custom_genesis = crate::genesis::genesis_block(
            NetworkParams::new_custom(Network::Liquidv1test, Script::new(), Script::new(), 2)
                .unwrap(),
        )
        .unwrap();

        assert_ne!(custom_genesis, genesis_block);
    }
}
