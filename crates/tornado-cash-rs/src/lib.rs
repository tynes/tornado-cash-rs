//! Building blocks for Tornado Cash Classic in Rust.
//!
//! * [`note`]: deposit notes and the tornado-cli note string format
//! * [`hash`] / [`merkle`]: Pedersen, MiMCSponge and the pool Merkle tree
//! * [`prover`]: witness generation and Groth16 proofs using the original
//!   trusted-setup proving key, self-checked against the on-chain verifier key
//! * [`eth`]: deposits, withdrawals and event sync over JSON-RPC
//! * [`relayer`]: the Tornado relayer HTTP API
//! * [`db`]: a password-encrypted local note database
//! * [`chains`]: deployment table

pub mod chains;
pub mod db;
pub mod error;
pub mod eth;
pub mod hash;
pub mod merkle;
pub mod note;
pub mod prover;
pub mod relayer;

pub use error::{Error, Result};
