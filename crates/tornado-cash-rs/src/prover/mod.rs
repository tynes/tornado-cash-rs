//! Proof generation for Tornado Cash Classic withdrawals.

pub mod artifacts;
pub mod groth16;
pub mod witness;

use crate::error::{Error, Result};
use crate::hash::{fr_from_be_bytes, fr_to_decimal};
use crate::merkle::MerkleProof;
use crate::note::Note;
use alloy::primitives::{Address, B256, U256};
use ark_bn254::Fr;
use groth16::{Proof, ProvingKey, VerifyingKey};
use serde_json::json;
use std::path::Path;
use witness::Circuit;

/// Public inputs of a withdrawal, in circuit order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawArgs {
    pub root: B256,
    pub nullifier_hash: B256,
    pub recipient: Address,
    pub relayer: Address,
    pub fee: U256,
    pub refund: U256,
}

impl WithdrawArgs {
    pub fn public_inputs(&self) -> Vec<Fr> {
        let addr = |a: &Address| fr_from_be_bytes(a.as_slice());
        let u = |x: &U256| fr_from_be_bytes(&x.to_be_bytes::<32>());
        vec![
            fr_from_be_bytes(self.root.as_slice()),
            fr_from_be_bytes(self.nullifier_hash.as_slice()),
            addr(&self.recipient),
            addr(&self.relayer),
            u(&self.fee),
            u(&self.refund),
        ]
    }
}

/// A withdrawal proof plus its public inputs, ready for the contract or a relayer.
#[derive(Clone, Debug)]
pub struct WithdrawProof {
    pub proof: Proof,
    pub args: WithdrawArgs,
}

impl WithdrawProof {
    pub fn proof_bytes(&self) -> [u8; 256] {
        self.proof.to_solidity_bytes()
    }
}

/// Holds the parsed circuit and proving key. Loading takes a few seconds, so
/// build one and reuse it.
pub struct Prover {
    circuit: Circuit,
    pk: ProvingKey,
    vk: VerifyingKey,
}

impl Prover {
    pub fn from_bytes(circuit_json: &[u8], proving_key: &[u8]) -> Result<Self> {
        let circuit = Circuit::from_json(circuit_json)?;
        let pk = ProvingKey::from_bytes(proving_key)?;
        if pk.n_vars != circuit.n_vars {
            return Err(Error::ProvingKey(
                "proving key does not match circuit".into(),
            ));
        }
        Ok(Prover {
            circuit,
            pk,
            vk: VerifyingKey::tornado_classic(),
        })
    }

    /// Load the artifacts from `cache_dir`, downloading them if needed.
    pub async fn load(cache_dir: &Path, http: Option<reqwest::Client>) -> Result<Self> {
        let client = http.unwrap_or_default();
        let c = artifacts::CIRCUIT.load(cache_dir, &client).await?;
        let k = artifacts::PROVING_KEY.load(cache_dir, &client).await?;
        Self::from_bytes(&c, &k)
    }

    /// Build and self-verify a withdrawal proof.
    pub fn prove_withdrawal(
        &self,
        note: &Note,
        path: &MerkleProof,
        recipient: Address,
        relayer: Address,
        fee: U256,
        refund: U256,
    ) -> Result<WithdrawProof> {
        let args = WithdrawArgs {
            root: path.root_bytes(),
            nullifier_hash: note.nullifier_hash_bytes(),
            recipient,
            relayer,
            fee,
            refund,
        };
        let pubs = args.public_inputs();
        let d = |x: &Fr| fr_to_decimal(x);
        let input = json!({
            "root": d(&pubs[0]),
            "nullifierHash": d(&pubs[1]),
            "recipient": d(&pubs[2]),
            "relayer": d(&pubs[3]),
            "fee": d(&pubs[4]),
            "refund": d(&pubs[5]),
            "nullifier": d(&note.nullifier_fr()),
            "secret": d(&note.secret_fr()),
            "pathElements": path.path_elements.iter().map(d).collect::<Vec<_>>(),
            "pathIndices": path.path_indices.iter().map(|b| if *b { "1" } else { "0" }).collect::<Vec<_>>(),
        });
        let w = self.circuit.calculate_witness(&input)?;
        let proof = self.pk.prove(&w, &mut rand::thread_rng())?;
        if !self.vk.verify(&proof, &pubs) {
            return Err(Error::ProofSelfCheck);
        }
        Ok(WithdrawProof { proof, args })
    }
}
