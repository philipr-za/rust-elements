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

//! Network
//!

use crate::error::write_err;
use crate::genesis::ChainHash;
use core::fmt;
use std::convert::TryFrom;
use std::fmt::Formatter;
use std::io;
use std::str::FromStr;

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Network {
    /// Mainnet Bitcoin.
    Bitcoin,
    /// Bitcoin's testnet network.
    Testnet,
    /// Bitcoin's signet network.
    Signet,
    /// Bitcoin's regtest network.
    Regtest,
    /// Liquid mainnet
    Liquidv1,
    /// Liquid testnet
    Liquidtestnet,
    /// Elements regtest
    Elementsregtest,
    /// Liquid v1 testing, as close to prod as possible while still being customizable. Uses
    /// Elementsregtest genesis block
    Liquidv1test,
}

impl Network {
    /// Converts a `Network` to its equivalent `elementsd -chain` argument name.
    ///
    /// ```bash
    /// $ elementsd --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest, liquidv1,
    /// liquidv1test, liquidtestnet, elementsregtest
    /// ```
    pub fn to_core_arg(self) -> &'static str {
        match self {
            Network::Bitcoin => "main",
            Network::Testnet => "test",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            Network::Liquidv1 => "liquidv1",
            Network::Liquidtestnet => "liquidtestnet",
            Network::Elementsregtest => "elementsregtest",
            Network::Liquidv1test => "liquidv1test",
        }
    }

    /// Converts a `elementsd -chain` argument name to its equivalent `Network`.
    ///
    /// ```bash
    /// $ elementsd --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest, liquidv1,
    /// liquidv1test, liquidtestnet, elementsregtest
    /// ```
    pub fn from_core_arg(core_arg: &str) -> Result<Self, ParseNetworkError> {
        use Network::*;

        let network = match core_arg {
            "main" => Bitcoin,
            "test" => Testnet,
            "signet" => Signet,
            "regtest" => Regtest,
            "liquidv1" => Liquidv1,
            "liquidv1test" => Liquidv1test,
            "liquidtestnet" => Liquidtestnet,
            "elementsregtest" => Elementsregtest,
            _ => return Err(ParseNetworkError(core_arg.to_owned())),
        };
        Ok(network)
    }

    /// Return the network's chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use elements::Network;
    /// use elements::genesis::ChainHash;
    ///
    /// let network = Network::Liquidv1;
    /// assert_eq!(network.chain_hash(), ChainHash::LIQUIDV1);
    /// ```
    pub fn chain_hash(self) -> ChainHash {
        ChainHash::using_genesis_block_const(self)
    }

    /// Creates a `Network` from the chain hash (genesis block hash).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use elements::Network;
    /// use elements::genesis::ChainHash;
    /// use std::convert::TryFrom;
    ///
    /// assert_eq!(Ok(Network::Liquidv1), Network::try_from(ChainHash::LIQUIDV1));
    /// ```
    pub fn from_chain_hash(chain_hash: ChainHash) -> Option<Network> {
        Network::try_from(chain_hash).ok()
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_core_arg())
    }
}

impl FromStr for Network {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Network::from_core_arg(s).map_err(|_e| io::Error::from(io::ErrorKind::InvalidInput))
    }
}

impl TryFrom<ChainHash> for Network {
    type Error = ParseNetworkError;

    fn try_from(chain_hash: ChainHash) -> Result<Self, Self::Error> {
        if chain_hash == ChainHash::BITCOIN {
            Ok(Network::Bitcoin)
        } else if chain_hash == ChainHash::TESTNET {
            Ok(Network::Testnet)
        } else if chain_hash == ChainHash::SIGNET {
            Ok(Network::Signet)
        } else if chain_hash == ChainHash::REGTEST {
            Ok(Network::Regtest)
        } else if chain_hash == ChainHash::LIQUIDV1 {
            Ok(Network::Liquidv1)
        } else if chain_hash == ChainHash::LIQUIDTESTNET {
            Ok(Network::Liquidtestnet)
        } else if chain_hash == ChainHash::ELEMENTSREGTEST {
            Ok(Network::Elementsregtest)
        } else {
            Err(ParseNetworkError(format!(
                "Chainhash {} not recognized",
                chain_hash
            )))
        }
    }
}

/// An error in parsing network string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseNetworkError(String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write_err!(f, "failed to parse {} as network", self.0; self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
