use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid note: {0}")]
    InvalidNote(String),
    #[error("unsupported pool: {0}")]
    UnsupportedPool(String),
    #[error("circuit: {0}")]
    Circuit(String),
    #[error("witness generation failed: {0}")]
    Witness(String),
    #[error("proving key: {0}")]
    ProvingKey(String),
    #[error("generated proof did not verify against the on-chain verifying key")]
    ProofSelfCheck,
    #[error("artifact {name}: {msg}")]
    Artifact { name: String, msg: String },
    #[error("merkle tree: {0}")]
    Merkle(String),
    #[error("note database: {0}")]
    Database(String),
    #[error("wrong password or corrupted note database")]
    Decrypt,
    #[error("relayer: {0}")]
    Relayer(String),
    #[error("ethereum: {0}")]
    Eth(String),
    /// The deposit definitely did not happen (rejected or reverted), so a
    /// note saved for it can be discarded.
    #[error("deposit not made: {0}")]
    NotDeposited(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
