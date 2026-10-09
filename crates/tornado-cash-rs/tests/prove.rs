//! End-to-end proof generation with the real Tornado Cash Classic circuit and
//! proving key. Needs the artifacts: set TORNADO_ARTIFACTS_DIR to a directory
//! holding `tornado.json` and `tornadoProvingKey.bin`, or let the test
//! download them. Run with `cargo test --release -- --ignored`.

use alloy::primitives::{address, U256};
use ark_bn254::Fr;
use std::path::PathBuf;
use std::time::Instant;
use tornado_cash_rs::merkle::MerkleTree;
use tornado_cash_rs::note::Note;
use tornado_cash_rs::prover::{artifacts, Prover};

async fn prover() -> Prover {
    let dir = std::env::var("TORNADO_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("tornado-cash-rs-artifacts"));
    let client = reqwest::Client::new();
    let c = artifacts::CIRCUIT.load(&dir, &client).await.unwrap();
    let k = artifacts::PROVING_KEY.load(&dir, &client).await.unwrap();
    Prover::from_bytes(&c, &k).unwrap()
}

#[tokio::test]
#[ignore = "needs the 34 MB proving artifacts"]
async fn proves_and_verifies_withdrawal() {
    let t = Instant::now();
    let prover = prover().await;
    eprintln!("loaded artifacts in {:?}", t.elapsed());

    let note = Note::random(1, "eth", "0.1");
    let mut leaves: Vec<Fr> = (0..6u64).map(|i| Fr::from(1000 + i)).collect();
    leaves.push(note.commitment());
    leaves.push(Fr::from(77u64));
    let tree = MerkleTree::new(leaves).unwrap();
    let path = tree.proof(6).unwrap();

    let t = Instant::now();
    let w = prover
        .prove_withdrawal(
            &note,
            &path,
            address!("8589427373D6D84E98730D7795D8f6f8731FDA16"),
            address!("6A31736e7490AbE5D5676be059DFf064AB4aC754"),
            U256::from(1_000_000_000_000_000u64),
            U256::ZERO,
        )
        .unwrap();
    eprintln!("proved and self-verified in {:?}", t.elapsed());
    assert_eq!(w.args.root, path.root_bytes());
    assert_eq!(w.args.nullifier_hash, note.nullifier_hash_bytes());
}

#[tokio::test]
#[ignore = "needs the 34 MB proving artifacts"]
async fn rejects_wrong_root() {
    let prover = prover().await;
    let note = Note::random(1, "eth", "0.1");
    let tree = MerkleTree::new(vec![note.commitment()]).unwrap();
    let mut path = tree.proof(0).unwrap();
    path.root = Fr::from(12345u64);
    let err = prover
        .prove_withdrawal(
            &note,
            &path,
            Default::default(),
            Default::default(),
            U256::ZERO,
            U256::ZERO,
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("Constraint doesn't match"),
        "{err}"
    );
}
