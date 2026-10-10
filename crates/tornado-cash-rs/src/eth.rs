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
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::http::Http;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Contract bindings for the pool and ERC-20 calls this client makes. Public
/// so other tools (e.g. a relayer) can submit the same calls.
pub mod bindings {
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
    /// Last block fully scanned. Only blocks at least
    /// [`SyncOptions::confirmations`] deep are cached.
    pub last_block: u64,
    /// Hash of `last_block` when it was scanned, used to detect reorgs.
    #[serde(default)]
    pub last_block_hash: Option<B256>,
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
            .unwrap_or_else(|| Self::empty(pool, chain_id))
    }

    pub fn empty(pool: &Pool, chain_id: u64) -> Self {
        DepositCache {
            chain_id,
            pool: pool.address,
            last_block: pool.start_block.saturating_sub(1),
            last_block_hash: None,
            commitments: vec![],
        }
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
}

/// Whether any of `logs` is a `Withdrawal` event from `pool` that reveals
/// `nullifier_hash`.
pub fn receipt_withdraws(
    logs: impl IntoIterator<Item = (Address, alloy::primitives::LogData)>,
    pool: Address,
    nullifier_hash: B256,
) -> bool {
    logs.into_iter().any(|(addr, data)| {
        addr == pool
            && ITornadoInstance::Withdrawal::decode_log_data(&data)
                .is_ok_and(|ev| ev.nullifierHash == nullifier_hash)
    })
}

/// Calldata for the pool's `deposit` call for `note`, for sending from another
/// wallet such as a Safe. A native-coin pool needs the pool's denomination as
/// the call's value; an ERC-20 pool needs an [`approve_calldata`] call first.
pub fn deposit_calldata(note: &Note) -> Bytes {
    ITornadoInstance::depositCall {
        _commitment: note.commitment_bytes(),
    }
    .abi_encode()
    .into()
}

/// Calldata for the pool's `withdraw` call with proof `w`. The call's value
/// must equal the proof's refund (zero unless a relayer pays one).
pub fn withdraw_calldata(w: &WithdrawProof) -> Bytes {
    let a = &w.args;
    ITornadoInstance::withdrawCall {
        _proof: Bytes::copy_from_slice(&w.proof_bytes()),
        _root: a.root,
        _nullifierHash: a.nullifier_hash,
        _recipient: a.recipient,
        _relayer: a.relayer,
        _fee: a.fee,
        _refund: a.refund,
    }
    .abi_encode()
    .into()
}

/// Calldata for an ERC-20 `approve(spender, amount)` call.
pub fn approve_calldata(spender: Address, amount: U256) -> Bytes {
    IERC20::approveCall { spender, amount }.abi_encode().into()
}

/// The `approve` calls needed to raise `allowance` to `needed`. Tokens like
/// mainnet USDT reject changing a nonzero allowance to another nonzero value,
/// so a nonzero but insufficient allowance is reset to zero first.
pub fn approvals_needed(allowance: U256, needed: U256) -> Vec<U256> {
    if allowance >= needed {
        vec![]
    } else if allowance.is_zero() {
        vec![needed]
    } else {
        vec![U256::ZERO, needed]
    }
}

/// Build the pool's Merkle tree from commitments in leaf order.
pub fn build_tree(commitments: &[B256]) -> Result<MerkleTree> {
    MerkleTree::new(
        commitments
            .iter()
            .map(|c| fr_from_be_bytes(c.as_slice()))
            .collect(),
    )
}

/// Options for event scanning.
#[derive(Clone, Debug)]
pub struct SyncOptions {
    /// Maximum blocks per `eth_getLogs` call; halved automatically on errors.
    pub max_block_span: u64,
    /// Blocks newer than `latest - confirmations` are fetched on every sync
    /// but never written to the cache, so a reorg among them cannot corrupt it.
    pub confirmations: u64,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions {
            max_block_span: 10_000,
            confirmations: 64,
        }
    }
}

/// Where deposit events come from. Implemented by [`TornadoClient`]; a
/// separate trait so the sync logic can be tested against a simulated chain.
#[allow(async_fn_in_trait)]
pub trait DepositSource {
    async fn latest_block(&self) -> Result<u64>;
    async fn block_hash(&self, number: u64) -> Result<Option<B256>>;
    /// `(leafIndex, commitment)` for every Deposit in `from..=to`, in log order.
    async fn deposits(&self, pool: &Pool, from: u64, to: u64) -> Result<Vec<(u32, B256)>>;
}

/// Append deposits in `from..=to` to `out`, which must already hold every
/// earlier leaf. Halves the block span when the RPC rejects a range.
async fn scan<S: DepositSource>(
    src: &S,
    pool: &Pool,
    from: u64,
    to: u64,
    max_span: u64,
    out: &mut Vec<B256>,
    progress: &mut impl FnMut(u64),
) -> Result<()> {
    let mut span = max_span.max(1);
    let mut start = from;
    while start <= to {
        let end = (start + span - 1).min(to);
        match src.deposits(pool, start, end).await {
            Ok(events) => {
                for (idx, commitment) in events {
                    if idx as usize != out.len() {
                        return Err(Error::Eth(format!(
                            "expected deposit leaf {} but got {idx}; the RPC returned incomplete logs",
                            out.len()
                        )));
                    }
                    out.push(commitment);
                }
                start = end + 1;
                progress(end);
            }
            Err(e) if span > 1 => {
                tracing::debug!("getLogs {start}..{end} failed ({e}), halving span");
                span /= 2;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Bring `cache` up to `latest - confirmations` and return every commitment
/// in the pool, including the not-yet-cached recent ones. If the cached tip
/// block is no longer canonical (a reorg deeper than `confirmations`), the
/// cache is discarded and rebuilt. `progress` receives (scanned, target).
pub async fn sync_deposits<S: DepositSource>(
    src: &S,
    pool: &Pool,
    cache: &mut DepositCache,
    opts: &SyncOptions,
    mut progress: impl FnMut(u64, u64),
) -> Result<Vec<B256>> {
    let latest = src.latest_block().await?;
    let safe = latest.saturating_sub(opts.confirmations);

    let stale = match cache.last_block_hash {
        Some(h) => cache.last_block > latest || src.block_hash(cache.last_block).await? != Some(h),
        None => !cache.commitments.is_empty(),
    };
    if stale {
        tracing::warn!(
            "cached deposits for {} are not on the canonical chain; rescanning",
            pool.address
        );
        *cache = DepositCache {
            chain_id: cache.chain_id,
            ..DepositCache::empty(pool, cache.chain_id)
        };
    }

    if cache.last_block < safe {
        let keep = cache.commitments.len();
        let mut leaves = std::mem::take(&mut cache.commitments);
        let r = scan(
            src,
            pool,
            cache.last_block + 1,
            safe,
            opts.max_block_span,
            &mut leaves,
            &mut |b| progress(b, latest),
        )
        .await;
        if r.is_ok() {
            cache.last_block = safe;
            cache.last_block_hash = src.block_hash(safe).await?;
            cache.commitments = leaves;
        } else {
            // Keep the cache at its last consistent point.
            cache.commitments = leaves;
            cache.commitments.truncate(keep);
        }
        r?;
    }

    let mut all = cache.commitments.clone();
    let tail_from = cache.last_block.max(safe) + 1;
    scan(
        src,
        pool,
        tail_from,
        latest,
        opts.max_block_span,
        &mut all,
        &mut |b| progress(b, latest),
    )
    .await?;
    Ok(all)
}

impl DepositSource for TornadoClient {
    async fn latest_block(&self) -> Result<u64> {
        self.provider.get_block_number().await.map_err(eth_err)
    }

    async fn block_hash(&self, number: u64) -> Result<Option<B256>> {
        let b = self
            .provider
            .get_block_by_number(number.into())
            .await
            .map_err(eth_err)?;
        Ok(b.map(|b| b.header.hash))
    }

    async fn deposits(&self, pool: &Pool, from: u64, to: u64) -> Result<Vec<(u32, B256)>> {
        let filter = Filter::new()
            .address(pool.address)
            .event_signature(ITornadoInstance::Deposit::SIGNATURE_HASH)
            .from_block(from)
            .to_block(to);
        let logs = self.provider.get_logs(&filter).await.map_err(eth_err)?;
        logs.iter()
            .map(|l| {
                ITornadoInstance::Deposit::decode_log_data(l.data())
                    .map(|ev| (ev.leafIndex, ev.commitment))
                    .map_err(eth_err)
            })
            .collect()
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
            for amount in approvals_needed(allowance, denomination) {
                let pending = erc20
                    .approve(pool.address, amount)
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

    /// Check on-chain that `tx` withdrew the note with `nullifier_hash` from
    /// `pool`. Used to verify what a relayer reports instead of trusting it.
    /// Waits briefly for the receipt to become available.
    pub async fn confirm_withdrawal(
        &self,
        pool: &Pool,
        tx: B256,
        nullifier_hash: B256,
    ) -> Result<()> {
        let mut receipt = None;
        for _ in 0..20 {
            receipt = self
                .provider
                .get_transaction_receipt(tx)
                .await
                .map_err(eth_err)?;
            if receipt.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        let r = receipt.ok_or_else(|| Error::Eth(format!("no receipt for {tx:#x}")))?;
        if !r.status() {
            return Err(Error::Eth(format!("transaction {tx:#x} reverted")));
        }
        let logs = r
            .inner
            .logs()
            .iter()
            .map(|l| (l.address(), l.data().clone()));
        if !receipt_withdraws(logs, pool.address, nullifier_hash) {
            return Err(Error::Eth(format!(
                "transaction {tx:#x} does not withdraw this note from {}",
                pool.address
            )));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::chain_by_name;
    use alloy::primitives::address;
    use std::cell::RefCell;

    /// A simulated chain: block i has hash `hashes[i]` and the listed deposits.
    struct MockChain {
        blocks: RefCell<Vec<(B256, Vec<B256>)>>,
    }

    impl MockChain {
        fn new(n: usize, salt: u8) -> Self {
            let blocks = (0..n)
                .map(|i| {
                    (
                        B256::repeat_byte(salt)
                            ^ B256::left_padding_from(&(i as u64).to_be_bytes()),
                        vec![],
                    )
                })
                .collect();
            MockChain {
                blocks: RefCell::new(blocks),
            }
        }
        fn deposit(&self, block: usize, c: B256) {
            self.blocks.borrow_mut()[block].1.push(c);
        }
        /// Replace blocks from `from` onward with a new fork.
        fn reorg(&self, from: usize, salt: u8) {
            let mut b = self.blocks.borrow_mut();
            for (i, blk) in b.iter_mut().enumerate().skip(from) {
                *blk = (
                    B256::repeat_byte(salt) ^ B256::left_padding_from(&(i as u64).to_be_bytes()),
                    vec![],
                );
            }
        }
        fn all_commitments(&self) -> Vec<B256> {
            self.blocks
                .borrow()
                .iter()
                .flat_map(|b| b.1.clone())
                .collect()
        }
    }

    impl DepositSource for MockChain {
        async fn latest_block(&self) -> Result<u64> {
            Ok(self.blocks.borrow().len() as u64 - 1)
        }
        async fn block_hash(&self, n: u64) -> Result<Option<B256>> {
            Ok(self.blocks.borrow().get(n as usize).map(|b| b.0))
        }
        async fn deposits(&self, _: &Pool, from: u64, to: u64) -> Result<Vec<(u32, B256)>> {
            let b = self.blocks.borrow();
            let mut idx = b[..from as usize].iter().map(|x| x.1.len()).sum::<usize>() as u32;
            let mut out = vec![];
            for blk in &b[from as usize..=to as usize] {
                for c in &blk.1 {
                    out.push((idx, *c));
                    idx += 1;
                }
            }
            Ok(out)
        }
    }

    fn pool() -> Pool {
        let mut p = chain_by_name("mainnet")
            .unwrap()
            .pool("eth", "0.1")
            .unwrap()
            .clone();
        p.start_block = 0;
        p
    }

    fn opts() -> SyncOptions {
        SyncOptions {
            max_block_span: 7,
            confirmations: 5,
        }
    }

    #[tokio::test]
    async fn shallow_reorg_never_reaches_the_cache() {
        let chain = MockChain::new(100, 1);
        for i in [3, 50, 97, 98] {
            chain.deposit(i, B256::repeat_byte(i as u8));
        }
        let pool = pool();
        let mut cache = DepositCache::empty(&pool, 1);
        let all = sync_deposits(&chain, &pool, &mut cache, &opts(), |_, _| {})
            .await
            .unwrap();
        assert_eq!(all, chain.all_commitments());
        assert_eq!(
            cache.commitments.len(),
            2,
            "recent deposits must not be cached"
        );

        // Reorg the last 3 blocks: deposit at 97 disappears, a different one lands at 98.
        chain.reorg(97, 2);
        chain.deposit(98, B256::repeat_byte(0xee));
        let all = sync_deposits(&chain, &pool, &mut cache, &opts(), |_, _| {})
            .await
            .unwrap();
        assert_eq!(all, chain.all_commitments());
        assert_eq!(
            build_tree(&all).unwrap().root(),
            build_tree(&chain.all_commitments()).unwrap().root()
        );
    }

    #[tokio::test]
    async fn deep_reorg_rebuilds_the_cache() {
        let chain = MockChain::new(100, 1);
        chain.deposit(10, B256::repeat_byte(1));
        chain.deposit(80, B256::repeat_byte(2));
        let pool = pool();
        let mut cache = DepositCache::empty(&pool, 1);
        sync_deposits(&chain, &pool, &mut cache, &opts(), |_, _| {})
            .await
            .unwrap();
        assert_eq!(cache.commitments.len(), 2);

        // A reorg deeper than `confirmations` replaces the cached deposit at 80.
        chain.reorg(60, 3);
        chain.deposit(70, B256::repeat_byte(9));
        // Round-trip through disk like the CLI does.
        let dir = tempfile::tempdir().unwrap();
        cache.save(dir.path()).unwrap();
        let mut cache = DepositCache::load(dir.path(), &pool, 1);
        let all = sync_deposits(&chain, &pool, &mut cache, &opts(), |_, _| {})
            .await
            .unwrap();
        assert_eq!(all, chain.all_commitments());
        assert_eq!(cache.commitments, chain.all_commitments());
    }

    #[test]
    fn withdrawal_must_match_pool_and_nullifier() {
        let pool = address!("12D66f87A04A9E220743712cE6d9bB1B5616B8Fc");
        let nh = B256::repeat_byte(7);
        let ev = ITornadoInstance::Withdrawal {
            to: Address::repeat_byte(1),
            nullifierHash: nh,
            relayer: Address::repeat_byte(2),
            fee: U256::from(1u64),
        };
        let data = ev.encode_log_data();
        assert!(receipt_withdraws([(pool, data.clone())], pool, nh));
        assert!(!receipt_withdraws(
            [(pool, data.clone())],
            pool,
            B256::repeat_byte(8)
        ));
        assert!(!receipt_withdraws(
            [(Address::repeat_byte(9), data)],
            pool,
            nh
        ));
        assert!(!receipt_withdraws([], pool, nh));
    }

    #[test]
    fn approval_resets_nonzero_allowance_first() {
        let need = U256::from(100u64);
        assert!(approvals_needed(U256::ZERO, need) == vec![need]);
        assert!(approvals_needed(need, need).is_empty());
        assert!(approvals_needed(U256::from(500u64), need).is_empty());
        assert_eq!(
            approvals_needed(U256::from(50u64), need),
            vec![U256::ZERO, need]
        );
    }

    #[test]
    fn deposit_calldata_encodes_the_commitment() {
        let note = Note::random(1, "eth", "0.1");
        let data = deposit_calldata(&note);
        assert_eq!(data[..4], ITornadoInstance::depositCall::SELECTOR);
        let call = ITornadoInstance::depositCall::abi_decode(&data).unwrap();
        assert_eq!(call._commitment, note.commitment_bytes());
    }
}
