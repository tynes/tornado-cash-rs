//! Drives `tornado-rs` commands in-process against a mainnet fork and checks
//! the note database and chain state after each step. Skips when ETH_RPC_URL
//! is not set.

use alloy::primitives::{Address, U256};
use alloy::signers::local::PrivateKeySigner;
use std::io::IsTerminal;
use std::path::Path;
use tornado_cash_rs::db::{NoteDb, NoteRecord, NoteStatus};
use tornado_cash_rs::eth::DepositCache;
use tornado_cash_rs::note::Note;
use tornado_cash_rs_cli::{run, Cli, Parser};
use tornado_cash_rs_fork_tests::relayer::{MockRelayer, RelayerConfig};
use tornado_cash_rs_fork_tests::{artifacts_dir, base_cache, ether, Fork};

const PASSWORD: &str = "fork-test-password";
// Throwaway key, funded on each fork.
const PRIVATE_KEY: &str = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";

fn signer() -> PrivateKeySigner {
    PRIVATE_KEY.parse().unwrap()
}

async fn tornado(fork: &Fork, data_dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let url = fork.url();
    let mut argv = vec![
        "tornado-rs",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--rpc-url",
        &url,
        "--password",
        PASSWORD,
        "--private-key",
        PRIVATE_KEY,
    ];
    argv.extend_from_slice(args);
    run(Cli::try_parse_from(argv)?).await
}

/// A data dir with the deposit cache up to the fork block and the proving
/// artifacts already in place, so the CLI neither rescans history nor
/// downloads 34 MB per test.
async fn data_dir(fork: &Fork) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let client = fork.client(None).await;
    for (currency, amount) in [("eth", "0.1")] {
        let pool = client.chain.pool(currency, amount).unwrap();
        base_cache(pool)
            .await
            .save(&dir.path().join("cache"))
            .unwrap();
    }
    std::os::unix::fs::symlink(artifacts_dir().await, dir.path().join("artifacts")).unwrap();
    dir
}

fn notes(dir: &Path) -> Vec<NoteRecord> {
    NoteDb::open(dir.join("notes.db"), PASSWORD)
        .unwrap()
        .notes()
        .to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn deposit_sync_withdraw_self_relay() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    fork.set_balance(signer().address(), ether(1)).await;
    let client = fork.client(None).await;
    let pool = client.chain.pool("eth", "0.1").unwrap().clone();
    let dir = data_dir(&fork).await;
    let d = dir.path();

    tornado(&fork, d, &["init"]).await.unwrap();
    assert!(notes(d).is_empty());

    let next = client.deposit_count(&pool).await.unwrap();
    tornado(&fork, d, &["deposit", "eth", "0.1", "--yes"])
        .await
        .unwrap();
    let rec = notes(d).pop().unwrap();
    assert_eq!(rec.status, NoteStatus::Deposited);
    assert_eq!(rec.leaf_index, Some(next));
    assert!(rec.deposit_tx.is_some());
    assert_eq!(rec.pool, pool.address);

    // The new deposit is fewer than 64 blocks deep, so sync reads it but
    // leaves the on-disk cache at the fork block.
    tornado(&fork, d, &["sync", "eth", "0.1"]).await.unwrap();
    let cache = DepositCache::load(&d.join("cache"), &pool, 1);
    assert_eq!(cache.last_block, fork.block);
    assert_eq!(cache.commitments.len() as u32, next);

    tornado(&fork, d, &["balances", "--check"]).await.unwrap();
    assert_eq!(notes(d)[0].status, NoteStatus::Deposited);

    let recipient = Address::random();
    let to = recipient.to_string();
    tornado(
        &fork,
        d,
        &["withdraw", &rec.id, &to, "--self-relay", "--yes"],
    )
    .await
    .unwrap();
    let rec = notes(d).pop().unwrap();
    assert_eq!(rec.status, NoteStatus::Spent);
    assert_eq!(rec.withdraw_recipient, Some(recipient));
    assert_eq!(fork.balance(recipient).await, pool.denomination());

    // A spent note is refused before anything is sent.
    let err = tornado(
        &fork,
        d,
        &["withdraw", &rec.id, &to, "--self-relay", "--yes"],
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("already withdrawn"), "{err}");

    tornado(&fork, d, &["balances", "--check"]).await.unwrap();
    tornado(&fork, d, &["stats"]).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn import_and_withdraw_through_relayer() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let dir = data_dir(&fork).await;
    let d = dir.path();
    tornado(&fork, d, &["init"]).await.unwrap();

    // A note deposited elsewhere (here, straight through the library).
    let depositor = fork.client(Some(fork.funded_signer(ether(1)).await)).await;
    let pool = depositor.chain.pool("eth", "0.1").unwrap().clone();
    let note = Note::random(1, "eth", "0.1");
    let r = depositor.deposit(&pool, &note).await.unwrap();

    tornado(
        &fork,
        d,
        &[
            "notes",
            "import",
            &note.to_note_string(),
            "--label",
            "imported",
        ],
    )
    .await
    .unwrap();
    let rec = notes(d).pop().unwrap();
    assert_eq!(rec.status, NoteStatus::Deposited);
    assert_eq!(rec.leaf_index, Some(r.leaf_index));
    assert_eq!(rec.label.as_deref(), Some("imported"));

    // A note that was never deposited imports as pending.
    let stray = Note::random(1, "eth", "0.1");
    tornado(&fork, d, &["notes", "import", &stray.to_note_string()])
        .await
        .unwrap();
    assert_eq!(notes(d).pop().unwrap().status, NoteStatus::Pending);

    let relayer = MockRelayer::start(
        &fork.url(),
        fork.funded_signer(ether(1)).await,
        RelayerConfig::default(),
    )
    .await;
    let recipient = Address::random();
    let to = recipient.to_string();
    tornado(
        &fork,
        d,
        &["withdraw", &rec.id, &to, "--relayer", &relayer.url, "--yes"],
    )
    .await
    .unwrap();
    let rec = notes(d).into_iter().find(|n| n.id == rec.id).unwrap();
    assert_eq!(rec.status, NoteStatus::Spent);
    let got = fork.balance(recipient).await;
    assert!(got > U256::ZERO && got < pool.denomination(), "{got}");
    // The fee covers the relayer's gas with room to spare.
    assert!(fork.balance(relayer.reward_account).await > ether(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_deposit_leaves_no_note() {
    let Some(fork) = Fork::spawn().await else {
        return;
    };
    let dir = data_dir(&fork).await;
    let d = dir.path();
    tornado(&fork, d, &["init"]).await.unwrap();

    // Not enough ETH: refused before anything is saved or sent.
    fork.set_balance(signer().address(), ether(1) / U256::from(20))
        .await;
    let err = tornado(&fork, d, &["deposit", "eth", "0.1", "-y"])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("insufficient"), "{err}");
    assert!(notes(d).is_empty());

    // Without a terminal to confirm on, --yes is required.
    if !std::io::stdin().is_terminal() {
        let from = signer().address();
        fork.set_balance(from, ether(1)).await;
        let nonce = fork.api.transaction_count(from, None).await.unwrap();
        let err = tornado(&fork, d, &["deposit", "eth", "0.1"])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--yes"), "{err}");
        assert!(notes(d).is_empty());
        assert_eq!(fork.api.transaction_count(from, None).await.unwrap(), nonce);
    }
}
