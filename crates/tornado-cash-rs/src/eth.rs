//! JSON-RPC client for Tornado Cash Classic pools: deposits, self-relayed
//! withdrawals, nullifier/root checks, and incremental deposit-event sync.

use crate::chains::{chain_by_id, Chain, Pool};
use crate::error::{Error, Result};
use crate::hash::fr_from_be_bytes;
use crate::merkle::MerkleTree;
use crate::note::Note;
use crate::prover::WithdrawProof;
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::client::RpcClient;
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use alloy::transports::http::Http;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod bindings {
    #![allow(clippy::too_many_arguments)]
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface ITornadoInstance {
            event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
            event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

            function deposit(bytes32 _commitment) external payable;
            function withdraw(
                bytes calldata _proof,
                bytes32 _root,
                bytes32 _nullifierHash,
                address _recipient,
                address _relayer,
                uint256 _fee,
                uint256 _refund
            ) external payable;
            function isKnownRoot(bytes32 _root) external view returns (bool);
            function isSpent(bytes32 _nullifierHash) external view returns (bool);
            function getLastRoot() external view returns (bytes32);
            function nextIndex() external view returns (uint32);
        }

        #[sol(rpc)]
        interface IERC20 {
            function approve(address spender, uint256 amount) external returns (bool);
            function allowance(address owner, address spender) external view returns (uint256);
            function balanceOf(address owner) external view returns (uint256);
        }
    }
}
use bindings::{ITornadoInstance, IERC20};

fn eth_err(e: impl std::fmt::Display) -> Error {
    Error::Eth(e.to_string())
}

/// Result of a confirmed deposit.
#[derive(Clone, Debug)]
pub struct DepositReceipt {
    pub tx_hash: B256,
    pub block_number: u64,
    pub leaf_index: u32,
}

/// Locally cached deposit commitments for one pool, ordered by leaf index.
/// This is public chain data, kept unencrypted so it can be shared or seeded.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DepositCache {
    pub chain_id: u64,
    pub pool: Address,
    /// Last block fully scanned.
    pub last_block: u64,
    pub commitments: Vec<B256>,
}

impl DepositCache {
    pub fn path(dir: &Path, chain_id: u64, pool: Address) -> PathBuf {
        dir.join(chain_id.to_string())
            .join(format!("deposits-{pool:#x}.json"))
    }

    pub fn load(dir: &Path, pool: &Pool, chain_id: u64) -> Self {
        let p = Self::path(dir, chain_id, pool.address);
        std::fs::read(&p)
            .ok()
            .and_then(|b| serde_json::from_slice::<DepositCache>(&b).ok())
            .filter(|c| c.pool == pool.address && c.chain_id == chain_id)
            .unwrap_or(DepositCache {
                chain_id,
                pool: pool.address,
                last_block: pool.start_block.saturating_sub(1),
                commitments: vec![],
            })
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let p = Self::path(dir, self.chain_id, self.pool);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(tmp, p)?;
        Ok(())
    }

    pub fn tree(&self) -> Result<MerkleTree> {
        MerkleTree::new(
            self.commitments
                .iter()
                .map(|c| fr_from_be_bytes(c.as_slice()))
                .collect(),
        )
    }
}

/// Options for event scanning.
#[derive(Clone, Debug)]
pub struct SyncOptions {
    /// Maximum blocks per `eth_getLogs` call; halved automatically on errors.
    pub max_block_span: u64,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions {
            max_block_span: 10_000,
        }
    }
}

pub struct TornadoClient {
    provider: DynProvider,
    pub chain: Chain,
    sender: Option<Address>,
}

impl TornadoClient {
    /// Connect to `rpc_url`, detect the chain, and optionally attach a signer.
    /// `http` lets callers route RPC traffic through a proxy (e.g. Tor).
    pub async fn connect(
        rpc_url: &str,
        signer: Option<PrivateKeySigner>,
        http: Option<reqwest::Client>,
    ) -> Result<Self> {
        let url: reqwest::Url = rpc_url.parse().map_err(eth_err)?;
        let transport = Http::with_client(http.unwrap_or_default(), url);
        let client = RpcClient::new(transport, false);
        let sender = signer.as_ref().map(|s| s.address());
        let provider: DynProvider = match signer {
            Some(s) => ProviderBuilder::new()
                .wallet(EthereumWallet::from(s))
                .connect_client(client)
                .erased(),
            None => ProviderBuilder::new().connect_client(client).erased(),
        };
        let chain_id = provider.get_chain_id().await.map_err(eth_err)?;
        let chain = chain_by_id(chain_id)?;
        Ok(TornadoClient {
            provider,
            chain,
            sender,
        })
    }

    pub fn provider(&self) -> &DynProvider {
        &self.provider
    }

    pub fn sender(&self) -> Result<Address> {
        self.sender
            .ok_or_else(|| Error::Eth("no private key configured".into()))
    }

    pub fn tx_url(&self, tx: &B256) -> String {
        format!("{}/tx/{tx:#x}", self.chain.explorer)
    }

    /// Native or token balance of `owner`, in base units.
    pub async fn balance_of(&self, pool: &Pool, owner: Address) -> Result<U256> {
        match pool.token {
            None => self.provider.get_balance(owner).await.map_err(eth_err),
            Some(t) => IERC20::new(t, &self.provider)
                .balanceOf(owner)
                .call()
                .await
                .map_err(eth_err),
        }
    }

    pub async fn gas_price(&self) -> Result<u128> {
        self.provider.get_gas_price().await.map_err(eth_err)
    }

    /// Send the deposit for `note` into `pool` and wait for it to be mined.
    /// For ERC-20 pools this first approves the pool if needed.
    pub async fn deposit(&self, pool: &Pool, note: &Note) -> Result<DepositReceipt> {
        let from = self.sender()?;
        let denomination = pool.denomination();
        let have = self.balance_of(pool, from).await?;
        if have < denomination {
            return Err(Error::Eth(format!(
                "insufficient {} balance in {from}",
                pool.currency.to_uppercase()
            )));
        }
        if let Some(token) = pool.token {
            let erc20 = IERC20::new(token, &self.provider);
            let allowance = erc20
                .allowance(from, pool.address)
                .call()
                .await
                .map_err(eth_err)?;
            if allowance < denomination {
                let pending = erc20
                    .approve(pool.address, denomination)
                    .send()
                    .await
                    .map_err(eth_err)?;
                let r = pending.get_receipt().await.map_err(eth_err)?;
                if !r.status() {
                    return Err(Error::Eth("approve transaction reverted".into()));
                }
            }
        }
        let instance = ITornadoInstance::new(pool.address, &self.provider);
        let commitment = note.commitment_bytes();
        let mut call = instance.deposit(commitment);
        if pool.is_native() {
            call = call.value(denomination);
        }
        let pending = call.send().await.map_err(eth_err)?;
        let tx_hash = *pending.tx_hash();
        let receipt = pending.get_receipt().await.map_err(eth_err)?;
        if !receipt.status() {
            return Err(Error::Eth(format!(
                "deposit transaction {tx_hash:#x} reverted"
            )));
        }
        let leaf_index = receipt
            .inner
            .logs()
            .iter()
            .filter(|l| l.address() == pool.address)
            .find_map(|l| ITornadoInstance::Deposit::decode_log_data(l.data()).ok())
            .filter(|ev| ev.commitment == commitment)
            .map(|ev| ev.leafIndex)
            .ok_or_else(|| Error::Eth("deposit event not found in receipt".into()))?;
        Ok(DepositReceipt {
            tx_hash,
            block_number: receipt.block_number.unwrap_or_default(),
            leaf_index,
        })
    }

    pub async fn is_spent(&self, pool: &Pool, nullifier_hash: B256) -> Result<bool> {
        ITornadoInstance::new(pool.address, &self.provider)
            .isSpent(nullifier_hash)
            .call()
            .await
            .map_err(eth_err)
    }

    /// Number of deposits ever made into the pool (the next free leaf index).
    pub async fn deposit_count(&self, pool: &Pool) -> Result<u32> {
        ITornadoInstance::new(pool.address, &self.provider)
            .nextIndex()
            .call()
            .await
            .map_err(eth_err)
    }

    pub async fn is_known_root(&self, pool: &Pool, root: B256) -> Result<bool> {
        ITornadoInstance::new(pool.address, &self.provider)
            .isKnownRoot(root)
            .call()
            .await
            .map_err(eth_err)
    }

    /// Bring `cache` up to the latest block. `progress` receives (scanned, target).
    pub async fn sync_deposits(
        &self,
        pool: &Pool,
        cache: &mut DepositCache,
        opts: &SyncOptions,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<()> {
        let latest = self.provider.get_block_number().await.map_err(eth_err)?;
        let mut span = opts.max_block_span.max(1);
        let mut from = cache.last_block + 1;
        while from <= latest {
            let to = (from + span - 1).min(latest);
            let filter = Filter::new()
                .address(pool.address)
                .event_signature(ITornadoInstance::Deposit::SIGNATURE_HASH)
                .from_block(from)
                .to_block(to);
            match self.provider.get_logs(&filter).await {
                Ok(logs) => {
                    for log in logs {
                        let ev = ITornadoInstance::Deposit::decode_log_data(log.data())
                            .map_err(eth_err)?;
                        let idx = ev.leafIndex as usize;
                        if idx < cache.commitments.len() {
                            continue; // overlap from a re-scan
                        }
                        if idx != cache.commitments.len() {
                            return Err(Error::Eth(format!(
                                "missing deposit events before leaf {idx}; try a smaller block span"
                            )));
                        }
                        cache.commitments.push(ev.commitment);
                    }
                    cache.last_block = to;
                    from = to + 1;
                    progress(to, latest);
                }
                Err(e) if span > 1 => {
                    tracing::debug!("getLogs {from}..{to} failed ({e}), halving span");
                    span /= 2;
                }
                Err(e) => return Err(eth_err(e)),
            }
        }
        Ok(())
    }

    /// Submit a withdrawal from this client's own account.
    pub async fn withdraw(&self, pool: &Pool, w: &WithdrawProof) -> Result<B256> {
        self.sender()?;
        let a = &w.args;
        let instance = ITornadoInstance::new(pool.address, &self.provider);
        let call = instance
            .withdraw(
                Bytes::copy_from_slice(&w.proof_bytes()),
                a.root,
                a.nullifier_hash,
                a.recipient,
                a.relayer,
                a.fee,
                a.refund,
            )
            .value(a.refund);
        let pending = call.send().await.map_err(eth_err)?;
        let tx = *pending.tx_hash();
        let r = pending.get_receipt().await.map_err(eth_err)?;
        if !r.status() {
            return Err(Error::Eth(format!("withdraw transaction {tx:#x} reverted")));
        }
        Ok(tx)
    }
}
