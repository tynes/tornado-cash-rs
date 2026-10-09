//! Where Tornado Cash Classic is deployed.
//!
//! Addresses come from tornado-cli's `config.js` and, for Sepolia, the
//! kohaku-cli pool catalog. USDC pools are omitted because Circle froze the
//! pool contracts in 2022 (withdrawals revert); cDAI pools are omitted because
//! Compound v2 is deprecated.

use crate::error::{Error, Result};
use alloy::primitives::{address, Address, U256};

/// How much testing and liquidity a chain has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Ethereum mainnet and Sepolia: tested, deep anonymity sets (mainnet).
    Primary,
    /// Same contracts, but small anonymity sets and few relayers.
    Secondary,
}

#[derive(Clone, Debug)]
pub struct Pool {
    /// Lower-case currency symbol used in notes.
    pub currency: &'static str,
    /// Human denomination, e.g. `"0.1"`.
    pub amount: &'static str,
    pub decimals: u8,
    pub address: Address,
    /// ERC-20 token, or `None` for the chain's native coin.
    pub token: Option<Address>,
    /// A block at or before the pool's first deposit; event scans start here.
    pub start_block: u64,
}

impl Pool {
    /// Denomination in base units.
    pub fn denomination(&self) -> U256 {
        parse_units(self.amount, self.decimals).expect("valid pool table")
    }

    pub fn is_native(&self) -> bool {
        self.token.is_none()
    }
}

#[derive(Clone, Debug)]
pub struct Chain {
    pub chain_id: u64,
    pub name: &'static str,
    pub native_symbol: &'static str,
    pub tier: Tier,
    pub explorer: &'static str,
    pub pools: Vec<Pool>,
}

impl Chain {
    pub fn pool(&self, currency: &str, amount: &str) -> Result<&Pool> {
        let c = currency.to_lowercase();
        self.pools
            .iter()
            .find(|p| p.currency == c && same_amount(p.amount, amount))
            .ok_or_else(|| Error::UnsupportedPool(format!("{currency} {amount} on {}", self.name)))
    }
}

fn same_amount(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        let s = s.trim();
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s.to_string()
        }
    };
    norm(a) == norm(b)
}

/// Parse a decimal string like `"0.1"` into base units.
pub fn parse_units(s: &str, decimals: u8) -> Option<U256> {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > decimals as usize {
        return None;
    }
    let digits = format!("{int}{frac:0<width$}", width = decimals as usize);
    U256::from_str_radix(&digits, 10).ok()
}

/// Format base units as a decimal string, trimming trailing zeros.
pub fn format_units(v: U256, decimals: u8) -> String {
    let s = format!("{:0>width$}", v.to_string(), width = decimals as usize + 1);
    let (int, frac) = s.split_at(s.len() - decimals as usize);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        int.to_string()
    } else {
        format!("{int}.{frac}")
    }
}

fn native(
    amount: &'static str,
    address: Address,
    start_block: u64,
    currency: &'static str,
) -> Pool {
    Pool {
        currency,
        amount,
        decimals: 18,
        address,
        token: None,
        start_block,
    }
}

fn erc20(
    currency: &'static str,
    amount: &'static str,
    decimals: u8,
    address: Address,
    token: Address,
    start_block: u64,
) -> Pool {
    Pool {
        currency,
        amount,
        decimals,
        address,
        token: Some(token),
        start_block,
    }
}

/// The four ETH-style pools that share addresses on BSC, Arbitrum and Optimism.
fn l2_eth_pools(currency: &'static str, starts: [u64; 4]) -> Vec<Pool> {
    vec![
        native(
            "0.1",
            address!("84443CFd09A48AF6eF360C6976C5392aC5023a1F"),
            starts[0],
            currency,
        ),
        native(
            "1",
            address!("d47438C816c9E7f2E2888E060936a499Af9582b3"),
            starts[1],
            currency,
        ),
        native(
            "10",
            address!("330bdFADE01eE9bF63C209Ee33102DD334618e0a"),
            starts[2],
            currency,
        ),
        native(
            "100",
            address!("1E34A77868E19A6647b1f2F47B51ed72dEDE95DD"),
            starts[3],
            currency,
        ),
    ]
}

/// The 100/1k/10k/100k pools shared by Gnosis and Polygon.
fn large_native_pools(currency: &'static str, starts: [u64; 4]) -> Vec<Pool> {
    vec![
        native(
            "100",
            address!("1E34A77868E19A6647b1f2F47B51ed72dEDE95DD"),
            starts[0],
            currency,
        ),
        native(
            "1000",
            address!("df231d99Ff8b6c6CBF4E9B9a945CBAcEF9339178"),
            starts[1],
            currency,
        ),
        native(
            "10000",
            address!("af4c0B70B2Ea9FB7487C7CbB37aDa259579fe040"),
            starts[2],
            currency,
        ),
        native(
            "100000",
            address!("a5C2254e4253490C54cef0a4347fddb8f75A4998"),
            starts[3],
            currency,
        ),
    ]
}

pub fn all_chains() -> Vec<Chain> {
    let dai = address!("6B175474E89094C44Da98b954EedeAC495271d0F");
    let usdt = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
    let wbtc = address!("2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599");
    vec![
        Chain {
            chain_id: 1,
            name: "mainnet",
            native_symbol: "ETH",
            tier: Tier::Primary,
            explorer: "https://etherscan.io",
            pools: vec![
                native(
                    "0.1",
                    address!("12D66f87A04A9E220743712cE6d9bB1B5616B8Fc"),
                    9116966,
                    "eth",
                ),
                native(
                    "1",
                    address!("47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936"),
                    9117609,
                    "eth",
                ),
                native(
                    "10",
                    address!("910Cbd523D972eb0a6f4cAe4618aD62622b39DbF"),
                    9117720,
                    "eth",
                ),
                native(
                    "100",
                    address!("A160cdAB225685dA1d56aa342Ad8841c3b53f291"),
                    9161895,
                    "eth",
                ),
                erc20(
                    "dai",
                    "100",
                    18,
                    address!("D4B88Df4D29F5CedD6857912842cff3b20C8Cfa3"),
                    dai,
                    9117612,
                ),
                erc20(
                    "dai",
                    "1000",
                    18,
                    address!("FD8610d20aA15b7B2E3Be39B396a1bC3516c7144"),
                    dai,
                    9161917,
                ),
                erc20(
                    "dai",
                    "10000",
                    18,
                    address!("07687e702b410Fa43f4cB4Af7FA097918ffD2730"),
                    dai,
                    12066007,
                ),
                erc20(
                    "dai",
                    "100000",
                    18,
                    address!("23773E65ed146A459791799d01336DB287f25334"),
                    dai,
                    12066048,
                ),
                erc20(
                    "usdt",
                    "100",
                    6,
                    address!("169AD27A470D064DEDE56a2D3ff727986b15D52B"),
                    usdt,
                    9162005,
                ),
                erc20(
                    "usdt",
                    "1000",
                    6,
                    address!("0836222F2B2B24A3F36f98668Ed8F0B38D1a872f"),
                    usdt,
                    9162012,
                ),
                erc20(
                    "wbtc",
                    "0.1",
                    8,
                    address!("178169B423a011fff22B9e3F3abeA13414dDD0F1"),
                    wbtc,
                    12067529,
                ),
                erc20(
                    "wbtc",
                    "1",
                    8,
                    address!("610B717796ad172B316836AC95a2ffad065CeaB4"),
                    wbtc,
                    12066652,
                ),
                erc20(
                    "wbtc",
                    "10",
                    8,
                    address!("bB93e510BbCD0B7beb5A853875f9eC60275CF498"),
                    wbtc,
                    12067591,
                ),
            ],
        },
        Chain {
            chain_id: 11155111,
            name: "sepolia",
            native_symbol: "ETH",
            tier: Tier::Primary,
            explorer: "https://sepolia.etherscan.io",
            pools: vec![
                native(
                    "0.1",
                    address!("8c4a04d872a6c1be37964A21Ba3A138525dFF50b"),
                    5594769,
                    "eth",
                ),
                native(
                    "1",
                    address!("8cc930096b4df705a007c4a039bdfa1320ed2508"),
                    5962064,
                    "eth",
                ),
                erc20(
                    "dai",
                    "100",
                    18,
                    address!("6921fd1A97441dd603A997ed6DdF388658daF754"),
                    address!("FF34B3d4Aee8ddCd6F9AFFFB6Fe49bD371b8a357"),
                    5594775,
                ),
            ],
        },
        Chain {
            chain_id: 56,
            name: "bsc",
            native_symbol: "BNB",
            tier: Tier::Secondary,
            explorer: "https://bscscan.com",
            pools: l2_eth_pools("bnb", [8159279, 8159286, 8159290, 8159296]),
        },
        Chain {
            chain_id: 100,
            name: "gnosis",
            native_symbol: "xDAI",
            tier: Tier::Secondary,
            explorer: "https://gnosisscan.io",
            pools: large_native_pools("xdai", [17754566, 17754568, 17754572, 17754574]),
        },
        Chain {
            chain_id: 137,
            name: "polygon",
            native_symbol: "MATIC",
            tier: Tier::Secondary,
            explorer: "https://polygonscan.com",
            pools: large_native_pools("matic", [16258013, 16258032, 16258046, 16258053]),
        },
        Chain {
            chain_id: 42161,
            name: "arbitrum",
            native_symbol: "ETH",
            tier: Tier::Secondary,
            explorer: "https://arbiscan.io",
            pools: l2_eth_pools("eth", [3300000; 4]),
        },
        Chain {
            chain_id: 10,
            name: "optimism",
            native_symbol: "ETH",
            tier: Tier::Secondary,
            explorer: "https://optimistic.etherscan.io",
            pools: l2_eth_pools("eth", [2243707, 2243709, 2243735, 2243749]),
        },
        Chain {
            chain_id: 43114,
            name: "avalanche",
            native_symbol: "AVAX",
            tier: Tier::Secondary,
            explorer: "https://snowtrace.io",
            pools: vec![
                native(
                    "10",
                    address!("330bdFADE01eE9bF63C209Ee33102DD334618e0a"),
                    4429830,
                    "avax",
                ),
                native(
                    "100",
                    address!("1E34A77868E19A6647b1f2F47B51ed72dEDE95DD"),
                    4429851,
                    "avax",
                ),
                native(
                    "500",
                    address!("af8d1839c3c67cf571aa74B5c12398d4901147B3"),
                    4429837,
                    "avax",
                ),
            ],
        },
    ]
}

pub fn chain_by_id(chain_id: u64) -> Result<Chain> {
    all_chains()
        .into_iter()
        .find(|c| c.chain_id == chain_id)
        .ok_or_else(|| Error::UnsupportedPool(format!("chain id {chain_id}")))
}

/// Look up by name (`mainnet`, `sepolia`, ...) or numeric chain id.
pub fn chain_by_name(name: &str) -> Result<Chain> {
    if let Ok(id) = name.parse::<u64>() {
        return chain_by_id(id);
    }
    let n = name.to_lowercase();
    let alias = match n.as_str() {
        "ethereum" | "eth" | "1" => "mainnet",
        "bnb" | "binance" => "bsc",
        "xdai" => "gnosis",
        "matic" => "polygon",
        "arb" => "arbitrum",
        "op" => "optimism",
        "avax" => "avalanche",
        other => other,
    };
    all_chains()
        .into_iter()
        .find(|c| c.name == alias)
        .ok_or_else(|| Error::UnsupportedPool(format!("unknown chain {name}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_roundtrip() {
        assert_eq!(
            parse_units("0.1", 18).unwrap(),
            U256::from(100_000_000_000_000_000u64)
        );
        assert_eq!(
            format_units(U256::from(100_000_000_000_000_000u64), 18),
            "0.1"
        );
        assert_eq!(format_units(U256::from(1_000_000u64), 6), "1");
        assert!(parse_units("0.0000001", 6).is_none());
    }

    #[test]
    fn pool_lookup() {
        let c = chain_by_name("mainnet").unwrap();
        assert_eq!(c.pool("ETH", "0.10").unwrap().amount, "0.1");
        assert!(c.pool("usdc", "100").is_err());
    }
}
