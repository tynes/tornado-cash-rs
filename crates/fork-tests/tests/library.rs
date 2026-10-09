//! Library-level tests against a mainnet fork. Each test spawns its own
//! in-process anvil; all of them skip when ETH_RPC_URL is not set.

use alloy::primitives::{Address, U256};
use tornado_cash_rs::chains::Pool;
use tornado_cash_rs::eth::{build_tree, TornadoClient};
use tornado_cash_rs::note::Note;
use tornado_cash_rs::prover::WithdrawProof;
use tornado_cash_rs::relayer::RelayerClient;
use tornado_cash_rs_fork_tests::relayer::{MockRelayer, RelayerConfig};
use tornado_cash_rs_fork_tests::{ether, prover, Fork};

fn pool(client: &TornadoClient, currency: &str, amount: &str) -> Pool {
    client.chain.pool(currency, amount).unwrap().clone()
}

/// Deposit a fresh note into `pool` from a newly funded account.
async fn deposit(fork: &Fork, pool: &Pool) -> (Note, u32) {
    let signer = fork.funded_signer(ether(1000)).await;
    if pool.token.is_some() {
        fork.set_dai_balance(signer.address(), pool.denomination())
            .await;
    }
    let client = fork.client(Some(signer)).await;
    let note = Note::random(1, pool.currency, pool.amount);
    let r = client.deposit(pool, &note).await.unwrap();
    (note, r.leaf_index)
}

/// Sync the pool's tree on the fork and prove a withdrawal of `note`.
async fn prove(
    fork: &Fork,
    client: &TornadoClient,
    pool: &Pool,
    note: &Note,
    recipient: Address,
    relayer: Address,
    fee: U256,
) -> WithdrawProof {
    let tree = build_tree(&fork.commitments(client, pool).await).unwrap();
    let leaf = tree.index_of(&note.commitment()).expect("deposit in tree");
    let path = tree.proof(leaf).unwrap();
    assert!(client.is_known_root(pool, path.root_bytes()).await.unwrap());
    let prover = prover().await;
    tokio::task::spawn_blocking({
        let note = note.clone();
        move || {
            prover
                .prove_withdrawal(&note, &path, recipient, relayer, fee, U256::ZERO)
                .unwrap()
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn connects_and_reads_pool_stats() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let client = fork.client(None).await;
    assert_eq!(client.chain.name, "mainnet");
    for p in client.chain.pools.clone() {
        let count = client.deposit_count(&p).await.unwrap();
        assert!(
            count > 0,
            "{} {} pool has no deposits",
            p.amount,
            p.currency
        );
        client.balance_of(&p, p.address).await.unwrap();
    }
    let eth = pool(&client, "eth", "0.1");
    assert!(client.balance_of(&eth, eth.address).await.unwrap() > U256::ZERO);
}

#[tokio::test(flavor = "multi_thread")]
async fn deposits_eth() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let signer = fork.funded_signer(ether(1)).await;
    let from = signer.address();
    let client = fork.client(Some(signer)).await;
    let pool = pool(&client, "eth", "0.1");
    let next = client.deposit_count(&pool).await.unwrap();
    let held = fork.balance(pool.address).await;

    let note = Note::random(1, "eth", "0.1");
    let r = client.deposit(&pool, &note).await.unwrap();

    assert_eq!(r.leaf_index, next);
    assert_eq!(client.deposit_count(&pool).await.unwrap(), next + 1);
    assert_eq!(fork.balance(pool.address).await, held + pool.denomination());
    let spent = ether(1) - fork.balance(from).await;
    assert!(spent > pool.denomination(), "sender also pays gas");
    assert!(!client
        .is_spent(&pool, note.nullifier_hash_bytes())
        .await
        .unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn deposits_dai() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let signer = fork.funded_signer(ether(1)).await;
    let from = signer.address();
    let client = fork.client(Some(signer)).await;
    let pool = pool(&client, "dai", "100");
    fork.set_dai_balance(from, pool.denomination()).await;
    assert_eq!(
        client.balance_of(&pool, from).await.unwrap(),
        pool.denomination()
    );
    let next = client.deposit_count(&pool).await.unwrap();
    let held = client.balance_of(&pool, pool.address).await.unwrap();

    // Approves the pool first, then deposits.
    let note = Note::random(1, "dai", "100");
    let r = client.deposit(&pool, &note).await.unwrap();

    assert_eq!(r.leaf_index, next);
    assert_eq!(client.balance_of(&pool, from).await.unwrap(), U256::ZERO);
    assert_eq!(
        client.balance_of(&pool, pool.address).await.unwrap(),
        held + pool.denomination()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deposit_without_funds_fails_before_sending() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let signer = fork.funded_signer(ether(1) / U256::from(20)).await;
    let from = signer.address();
    let client = fork.client(Some(signer)).await;
    let pool = pool(&client, "eth", "0.1");

    let err = client
        .deposit(&pool, &Note::random(1, "eth", "0.1"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("insufficient"), "{err}");
    assert_eq!(
        fork.api.transaction_count(from, None).await.unwrap(),
        U256::ZERO
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn synced_tree_matches_contract_root() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let client = fork.client(None).await;
    let pool = pool(&client, "eth", "0.1");
    let (note, leaf) = deposit(&fork, &pool).await;

    let commitments = fork.commitments(&client, &pool).await;
    assert_eq!(
        commitments.len() as u32,
        client.deposit_count(&pool).await.unwrap()
    );
    assert_eq!(commitments[leaf as usize], note.commitment_bytes());
    let tree = build_tree(&commitments).unwrap();
    assert_eq!(tree.index_of(&note.commitment()), Some(leaf as usize));
    let root = tree.proof(leaf as usize).unwrap().root_bytes();
    assert!(client.is_known_root(&pool, root).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn self_relayed_withdraw() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let reader = fork.client(None).await;
    let pool = pool(&reader, "eth", "0.1");
    let (note, _) = deposit(&fork, &pool).await;

    let recipient = Address::random();
    let proof = prove(
        &fork,
        &reader,
        &pool,
        &note,
        recipient,
        Address::ZERO,
        U256::ZERO,
    )
    .await;
    let sender = fork.client(Some(fork.funded_signer(ether(1)).await)).await;
    sender.withdraw(&pool, &proof).await.unwrap();

    assert_eq!(fork.balance(recipient).await, pool.denomination());
    assert!(reader
        .is_spent(&pool, note.nullifier_hash_bytes())
        .await
        .unwrap());
    // The same nullifier cannot be spent twice.
    assert!(sender.withdraw(&pool, &proof).await.is_err());
    assert_eq!(fork.balance(recipient).await, pool.denomination());
}

/// Deposit, then withdraw through the mock relayer; returns
/// (recipient, relayer, fee) for balance checks.
async fn relayed_withdraw(fork: &Fork, pool: &Pool) -> (Address, Address, U256) {
    let reader = fork.client(None).await;
    let (note, _) = deposit(fork, pool).await;
    let relayer_key = fork.funded_signer(ether(1)).await;
    let relayer = MockRelayer::start(&fork.url(), relayer_key, RelayerConfig::default()).await;

    let rc = RelayerClient::new(&relayer.url, None).unwrap();
    let status = rc.status().await.unwrap();
    assert!(status.serves_chain(1));
    assert_eq!(status.reward_account, relayer.reward_account);
    let gas_price = reader.gas_price().await.unwrap();
    let fee = RelayerClient::quote_fee(&status, pool, gas_price, U256::ZERO).unwrap();
    assert!(fee > U256::ZERO);

    let recipient = Address::random();
    let proof = prove(
        fork,
        &reader,
        pool,
        &note,
        recipient,
        status.reward_account,
        fee,
    )
    .await;
    let job = rc.submit(pool, &proof).await.unwrap();
    rc.wait(&job, |_| {}).await.unwrap();
    assert!(reader
        .is_spent(pool, note.nullifier_hash_bytes())
        .await
        .unwrap());
    (recipient, relayer.reward_account, fee)
}

#[tokio::test(flavor = "multi_thread")]
async fn relayed_withdraw_eth() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let pool = pool(&fork.client(None).await, "eth", "0.1");
    let (recipient, _, fee) = relayed_withdraw(&fork, &pool).await;
    assert_eq!(fork.balance(recipient).await, pool.denomination() - fee);
}

#[tokio::test(flavor = "multi_thread")]
async fn relayed_withdraw_dai() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let client = fork.client(None).await;
    let pool = pool(&client, "dai", "100");
    let (recipient, relayer, fee) = relayed_withdraw(&fork, &pool).await;
    assert_eq!(
        client.balance_of(&pool, recipient).await.unwrap(),
        pool.denomination() - fee
    );
    assert_eq!(client.balance_of(&pool, relayer).await.unwrap(), fee);
}
