//! Test harness for running tornado-cash-rs against a mainnet fork.
//!
//! Each test spawns its own anvil node in-process, forked from `ETH_RPC_URL`
//! at a pinned block. Without `ETH_RPC_URL`, [`Fork::spawn`] returns `None`
//! and the tests return early, so offline runs still pass.

pub mod relayer;

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use anvil::eth::EthApi;
use foundry_primitives::FoundryNetwork;
use anvil::{NodeConfig, NodeHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};
use tornado_cash_rs::chains::Pool;
use tornado_cash_rs::eth::{DepositCache, SyncOptions, TornadoClient};
use tornado_cash_rs::prover::{artifacts, Prover};

/// Mainnet block the fork starts from. Override with `FORK_BLOCK`.
pub const DEFAULT_FORK_BLOCK: u64 = 26_150_000;

/// Mainnet DAI; `balanceOf` is the mapping at storage slot 2.
pub const DAI: Address = alloy::primitives::address!("6B175474E89094C44Da98b954EedeAC495271d0F");
const DAI_BALANCE_SLOT: u64 = 2;

pub fn fork_block() -> u64 {
    std::env::var("FORK_BLOCK")
        .ok()
        .map(|b| b.parse().expect("FORK_BLOCK must be a block number"))
        .unwrap_or(DEFAULT_FORK_BLOCK)
}

/// An anvil node forked from mainnet, running in this process.
pub struct Fork {
    pub api: EthApi<FoundryNetwork>,
    pub handle: NodeHandle,
    pub block: u64,
}

impl Fork {
    /// Fork mainnet at [`fork_block`], or `None` (after saying so) when
    /// `ETH_RPC_URL` is not set.
    pub async fn spawn() -> Option<Fork> {
        let Some(url) = std::env::var("ETH_RPC_URL").ok().filter(|u| !u.is_empty()) else {
            eprintln!("skipping: ETH_RPC_URL not set");
            return None;
        };
        Some(Self::spawn_at(&url, fork_block()).await)
    }

    async fn spawn_at(url: &str, block: u64) -> Fork {
        let config = NodeConfig::test()
            .with_eth_rpc_url(Some(url))
            .with_fork_block_number(Some(block));
        let (api, handle) = anvil::spawn(config).await;
        Fork { api, handle, block }
    }

    pub fn url(&self) -> String {
        self.handle.http_endpoint()
    }

    /// A client for the fork, optionally signing as `signer`.
    pub async fn client(&self, signer: Option<PrivateKeySigner>) -> TornadoClient {
        TornadoClient::connect(&self.url(), signer, None)
            .await
            .expect("connect to fork")
    }

    /// A fresh account holding `eth` wei. Anvil's default dev accounts are not
    /// used because on mainnet they carry EIP-7702 delegations.
    pub async fn funded_signer(&self, eth: U256) -> PrivateKeySigner {
        let s = PrivateKeySigner::random();
        self.set_balance(s.address(), eth).await;
        s
    }

    pub async fn set_balance(&self, who: Address, wei: U256) {
        self.api.anvil_set_balance(who, wei).await.unwrap();
    }

    /// Overwrite `who`'s DAI balance.
    pub async fn set_dai_balance(&self, who: Address, amount: U256) {
        let slot = keccak256((who, U256::from(DAI_BALANCE_SLOT)).abi_encode());
        self.api
            .anvil_set_storage_at(DAI, slot.into(), B256::from(amount))
            .await
            .unwrap();
    }

    pub async fn balance(&self, who: Address) -> U256 {
        self.api.balance(who, None).await.unwrap()
    }

    /// The pool's deposits up to this fork's latest block. Events up to the
    /// fork block come from an on-disk cache (see [`base_cache`]); only the
    /// blocks mined on the fork are scanned here.
    pub async fn synced_cache(&self, client: &TornadoClient, pool: &Pool) -> DepositCache {
        let mut cache = base_cache(pool).await;
        client
            .sync_deposits(pool, &mut cache, &SyncOptions::default(), |_, _| {})
            .await
            .expect("sync fork deposits");
        cache
    }
}

/// Directory for state shared between test runs: the deposit caches.
pub fn cache_root() -> PathBuf {
    std::env::var("FORK_TEST_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/fork-test-cache")
        })
        .join(fork_block().to_string())
}

/// Deposit events for `pool` from its deployment up to the fork block, the
/// same cache file layout the CLI uses under `<data>/cache`.
///
/// The first run reads ~14M blocks of logs, so the result is saved under
/// [`cache_root`] and reused. It is built on a separate, untouched fork so the
/// scan stops exactly at the fork block, whatever the calling test has mined.
pub async fn base_cache(pool: &Pool) -> DepositCache {
    static LOCK: Mutex<()> = Mutex::const_new(());
    let _guard = LOCK.lock().await;
    let dir = cache_root();
    let block = fork_block();
    let mut cache = DepositCache::load(&dir, pool, 1);
    if cache.last_block < block {
        let url = std::env::var("ETH_RPC_URL").expect("ETH_RPC_URL");
        let pristine = Fork::spawn_at(&url, block).await;
        let client = pristine.client(None).await;
        let opts = SyncOptions {
            max_block_span: 1_000_000,
        };
        let r = client
            .sync_deposits(pool, &mut cache, &opts, |_, _| {})
            .await;
        cache.save(&dir).expect("save deposit cache");
        r.expect("sync deposits up to the fork block");
        assert_eq!(cache.last_block, block);
    }
    cache
}

/// Directory holding the proving artifacts, downloading them if needed.
/// Shares `TORNADO_ARTIFACTS_DIR` / the temp-dir default with `prove.rs`.
pub async fn artifacts_dir() -> PathBuf {
    let dir = std::env::var("TORNADO_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("tornado-cash-rs-artifacts"));
    static READY: OnceCell<()> = OnceCell::const_new();
    READY
        .get_or_init(|| async {
            let client = reqwest::Client::new();
            artifacts::CIRCUIT.load(&dir, &client).await.unwrap();
            artifacts::PROVING_KEY.load(&dir, &client).await.unwrap();
        })
        .await;
    dir
}

/// The prover, loaded once per test binary.
pub async fn prover() -> Arc<Prover> {
    static PROVER: OnceCell<Arc<Prover>> = OnceCell::const_new();
    PROVER
        .get_or_init(|| async {
            let dir = artifacts_dir().await;
            Arc::new(Prover::load(&dir, None).await.expect("load prover"))
        })
        .await
        .clone()
}

pub fn ether(n: u64) -> U256 {
    U256::from(n) * U256::from(10u64).pow(U256::from(18))
}
