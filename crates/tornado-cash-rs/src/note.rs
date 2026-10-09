//! Deposit notes and the `tornado-<currency>-<amount>-<chainId>-0x<preimage>`
//! string format shared with tornado-cli and the Tornado UI.

use crate::error::{Error, Result};
use crate::hash::{fr_from_le_bytes, fr_to_bytes32, pedersen_hash};
use alloy::primitives::B256;
use ark_bn254::Fr;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 31 random bytes, interpreted little-endian (always below the field modulus).
pub type Secret31 = [u8; 31];

/// The secret part of a deposit. Whoever holds it can withdraw the funds.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Note {
    pub chain_id: u64,
    /// Lower-case pool currency symbol, e.g. `eth`, `dai`, `bnb`.
    pub currency: String,
    /// Denomination as written in the pool table, e.g. `0.1`, `100`.
    pub amount: String,
    #[serde(with = "hex31")]
    pub nullifier: Secret31,
    #[serde(with = "hex31")]
    pub secret: Secret31,
}

impl fmt::Debug for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Note")
            .field("chain_id", &self.chain_id)
            .field("currency", &self.currency)
            .field("amount", &self.amount)
            .field("commitment", &self.commitment_bytes())
            .finish_non_exhaustive()
    }
}

impl Note {
    /// A fresh note with random nullifier and secret.
    pub fn random(chain_id: u64, currency: &str, amount: &str) -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut nullifier = [0u8; 31];
        let mut secret = [0u8; 31];
        rng.fill_bytes(&mut nullifier);
        rng.fill_bytes(&mut secret);
        Note {
            chain_id,
            currency: currency.to_lowercase(),
            amount: amount.to_string(),
            nullifier,
            secret,
        }
    }

    /// `nullifier || secret`, the 62-byte Pedersen preimage.
    pub fn preimage(&self) -> [u8; 62] {
        let mut p = [0u8; 62];
        p[..31].copy_from_slice(&self.nullifier);
        p[31..].copy_from_slice(&self.secret);
        p
    }

    pub fn nullifier_fr(&self) -> Fr {
        fr_from_le_bytes(&self.nullifier)
    }

    pub fn secret_fr(&self) -> Fr {
        fr_from_le_bytes(&self.secret)
    }

    /// The leaf inserted into the pool's Merkle tree on deposit.
    pub fn commitment(&self) -> Fr {
        pedersen_hash(&self.preimage())
    }

    pub fn commitment_bytes(&self) -> B256 {
        B256::from(fr_to_bytes32(&self.commitment()))
    }

    /// Revealed on withdrawal; marks the note as spent on-chain.
    pub fn nullifier_hash(&self) -> Fr {
        pedersen_hash(&self.nullifier)
    }

    pub fn nullifier_hash_bytes(&self) -> B256 {
        B256::from(fr_to_bytes32(&self.nullifier_hash()))
    }

    /// Parse `tornado-eth-0.1-1-0x<124 hex chars>`.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let bad = |m: &str| Error::InvalidNote(m.to_string());
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 || parts[0] != "tornado" {
            return Err(bad(
                "expected tornado-<currency>-<amount>-<chainId>-0x<hex>",
            ));
        }
        let chain_id: u64 = parts[3]
            .parse()
            .map_err(|_| bad("chain id is not a number"))?;
        let hex_part = parts[4]
            .strip_prefix("0x")
            .ok_or_else(|| bad("preimage must start with 0x"))?;
        let bytes = hex::decode(hex_part).map_err(|_| bad("preimage is not hex"))?;
        if bytes.len() != 62 {
            return Err(bad("preimage must be 62 bytes"));
        }
        let mut nullifier = [0u8; 31];
        let mut secret = [0u8; 31];
        nullifier.copy_from_slice(&bytes[..31]);
        secret.copy_from_slice(&bytes[31..]);
        Ok(Note {
            chain_id,
            currency: parts[1].to_lowercase(),
            amount: parts[2].to_string(),
            nullifier,
            secret,
        })
    }

    /// Format as a tornado-cli compatible note string. Treat it like a private key.
    pub fn to_note_string(&self) -> String {
        format!(
            "tornado-{}-{}-{}-0x{}",
            self.currency,
            self.amount,
            self.chain_id,
            hex::encode(self.preimage())
        )
    }
}

mod hex31 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 31], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 31], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 31 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_string_roundtrip() {
        let n = Note::random(1, "ETH", "0.1");
        let s = n.to_note_string();
        assert!(s.starts_with("tornado-eth-0.1-1-0x"));
        assert_eq!(Note::parse(&s).unwrap(), n);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Note::parse("tornado-eth-0.1-1-0x1234").is_err());
        assert!(Note::parse("hello").is_err());
    }
}
