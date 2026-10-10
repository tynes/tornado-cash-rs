//! A password-encrypted local database of deposit notes.
//!
//! The whole database is one file. Its contents are serialized to JSON and
//! sealed with XChaCha20-Poly1305 under a key derived from the password with
//! Argon2id. The unencrypted header (format version, KDF parameters, salt,
//! nonce) is authenticated as associated data, so tampering with it is
//! detected. Every save uses a fresh nonce and replaces the file atomically.
//!
//! Notes are written *before* their deposit transaction is broadcast, so a
//! crash between the two cannot lose the secret for funds already sent.
//!
//! An open [`NoteDb`] holds an exclusive lock on `<path>.lock` for its whole
//! lifetime. Every handle reads the full file and writes back its own
//! snapshot, so two handles open at once could otherwise silently drop each
//! other's notes; the lock makes a second process fail fast instead.

use crate::chains::{chain_by_id, format_units, same_amount};
use crate::error::{Error, Result};
use crate::note::Note;
use alloy::primitives::{Address, B256, U256};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const FORMAT: &str = "tornado-cash-rs-notes";
const VERSION: u32 = 1;

/// Argon2id parameters stored in the header so they can be raised later.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "hex_vec")]
    pub salt: Vec<u8>,
}

impl KdfParams {
    fn new_random() -> Self {
        let mut salt = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        // OWASP's first recommended Argon2id configuration.
        KdfParams {
            m_cost_kib: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
            salt,
        }
    }

    fn derive(&self, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| Error::Database(format!("bad KDF parameters: {e}")))?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, &self.salt, key.as_mut())
            .map_err(|e| Error::Database(format!("key derivation failed: {e}")))?;
        Ok(key)
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    format: String,
    version: u32,
    kdf: KdfParams,
    #[serde(with = "hex_vec")]
    nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    header: Header,
    #[serde(with = "hex_vec")]
    ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    /// Saved, deposit not yet confirmed on-chain.
    Pending,
    /// Deposit confirmed; spendable.
    Deposited,
    /// Withdrawn.
    Spent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteRecord {
    /// Short handle derived from the commitment.
    pub id: String,
    pub note: Note,
    pub pool: Address,
    pub status: NoteStatus,
    pub created_at: u64,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub deposit_tx: Option<B256>,
    #[serde(default)]
    pub deposit_block: Option<u64>,
    #[serde(default)]
    pub leaf_index: Option<u32>,
    #[serde(default)]
    pub withdraw_tx: Option<B256>,
    #[serde(default)]
    pub withdraw_recipient: Option<Address>,
}

/// Selects notes by chain, currency and amount. Unset fields match anything.
#[derive(Clone, Debug, Default)]
pub struct NoteFilter {
    pub chain_id: Option<u64>,
    pub currency: Option<String>,
    pub amount: Option<String>,
}

impl NoteFilter {
    pub fn is_empty(&self) -> bool {
        self.chain_id.is_none() && self.currency.is_none() && self.amount.is_none()
    }

    pub fn matches(&self, r: &NoteRecord) -> bool {
        self.chain_id.is_none_or(|c| r.note.chain_id == c)
            && self
                .currency
                .as_deref()
                .is_none_or(|c| r.note.currency.eq_ignore_ascii_case(c.trim()))
            && self
                .amount
                .as_deref()
                .is_none_or(|a| same_amount(&r.note.amount, a))
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Contents {
    notes: Vec<NoteRecord>,
}

/// Spendable balance in one pool currency on one chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    pub chain_id: u64,
    pub currency: String,
    pub notes: usize,
    pub pending: usize,
    pub total: U256,
    pub decimals: u8,
}

impl Balance {
    pub fn formatted(&self) -> String {
        format_units(self.total, self.decimals)
    }
}

pub struct NoteDb {
    path: PathBuf,
    /// Exclusive lock held until the handle is dropped.
    _lock: std::fs::File,
    kdf: KdfParams,
    key: Zeroizing<[u8; 32]>,
    contents: Contents,
}

fn lock_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

/// Take the database's exclusive lock, failing if another handle holds it.
fn acquire_lock(path: &Path) -> Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path(path))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::Database(format!(
            "{} is in use by another process; wait for it to finish",
            path.display()
        ))),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl NoteDb {
    /// Create a new, empty database. Fails if the file already exists.
    pub fn create(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if password.is_empty() {
            return Err(Error::Database("password must not be empty".into()));
        }
        let lock = acquire_lock(&path)?;
        if path.exists() {
            return Err(Error::Database(format!(
                "{} already exists",
                path.display()
            )));
        }
        let kdf = KdfParams::new_random();
        let key = kdf.derive(password.as_bytes())?;
        let db = NoteDb {
            path,
            _lock: lock,
            kdf,
            key,
            contents: Contents::default(),
        };
        db.save()?;
        Ok(db)
    }

    /// Open and decrypt an existing database.
    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(Error::Database(format!(
                "{} does not exist",
                path.display()
            )));
        }
        let lock = acquire_lock(&path)?;
        let raw = std::fs::read(&path)?;
        let env: Envelope = serde_json::from_slice(&raw)
            .map_err(|_| Error::Database("not a tornado-cash-rs note database".into()))?;
        if env.header.format != FORMAT {
            return Err(Error::Database(
                "not a tornado-cash-rs note database".into(),
            ));
        }
        if env.header.version != VERSION {
            return Err(Error::Database(format!(
                "unsupported version {}",
                env.header.version
            )));
        }
        let key = env.header.kdf.derive(password.as_bytes())?;
        let aad = serde_json::to_vec(&env.header)?;
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        if env.header.nonce.len() != 24 {
            return Err(Error::Decrypt);
        }
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&env.header.nonce),
                    Payload {
                        msg: &env.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Decrypt)?,
        );
        let contents: Contents = serde_json::from_slice(&plain)?;
        Ok(NoteDb {
            path,
            _lock: lock,
            kdf: env.header.kdf,
            key,
            contents,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Encrypt and atomically write the database.
    pub fn save(&self) -> Result<()> {
        let mut nonce = vec![0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let header = Header {
            format: FORMAT.into(),
            version: VERSION,
            kdf: self.kdf.clone(),
            nonce,
        };
        let aad = serde_json::to_vec(&header)?;
        let plain = Zeroizing::new(serde_json::to_vec(&self.contents)?);
        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&header.nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Database("encryption failed".into()))?;
        let bytes = serde_json::to_vec_pretty(&Envelope { header, ciphertext })?;

        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let tmp = self.path.with_extension("tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Re-encrypt under a new password (and a new salt).
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        if new_password.is_empty() {
            return Err(Error::Database("password must not be empty".into()));
        }
        let kdf = KdfParams::new_random();
        self.key = kdf.derive(new_password.as_bytes())?;
        self.kdf = kdf;
        self.save()
    }

    /// Add a note and save immediately. Returns its id.
    pub fn insert(&mut self, note: Note, pool: Address, status: NoteStatus) -> Result<String> {
        let commitment = note.commitment_bytes();
        if self
            .contents
            .notes
            .iter()
            .any(|r| r.note.commitment_bytes() == commitment)
        {
            return Err(Error::Database("note is already in the database".into()));
        }
        let id = hex::encode(&commitment[..4]);
        self.contents.notes.push(NoteRecord {
            id: id.clone(),
            note,
            pool,
            status,
            created_at: now(),
            label: None,
            deposit_tx: None,
            deposit_block: None,
            leaf_index: None,
            withdraw_tx: None,
            withdraw_recipient: None,
        });
        self.save()?;
        Ok(id)
    }

    pub fn notes(&self) -> &[NoteRecord] {
        &self.contents.notes
    }

    /// Notes matching `filter`, oldest first.
    pub fn select(&self, filter: &NoteFilter) -> Vec<&NoteRecord> {
        self.contents
            .notes
            .iter()
            .filter(|r| filter.matches(r))
            .collect()
    }

    /// Find a note by id or unique id prefix.
    pub fn get(&self, id: &str) -> Result<&NoteRecord> {
        let id = id.trim().to_lowercase();
        let matches: Vec<&NoteRecord> = self
            .contents
            .notes
            .iter()
            .filter(|r| r.id.starts_with(&id))
            .collect();
        match matches.len() {
            1 => Ok(matches[0]),
            0 => Err(Error::Database(format!("no note with id {id}"))),
            _ => Err(Error::Database(format!("id {id} is ambiguous"))),
        }
    }

    /// Apply `f` to a note and save.
    pub fn update(&mut self, id: &str, f: impl FnOnce(&mut NoteRecord)) -> Result<()> {
        let full = self.get(id)?.id.clone();
        let rec = self
            .contents
            .notes
            .iter_mut()
            .find(|r| r.id == full)
            .expect("just found");
        f(rec);
        self.save()
    }

    /// Delete a note and save. Only for notes whose deposit never happened:
    /// a deposited note's secret is the only way to withdraw it.
    pub fn remove(&mut self, id: &str) -> Result<()> {
        let full = self.get(id)?.id.clone();
        self.contents.notes.retain(|r| r.id != full);
        self.save()
    }

    /// Spendable (and pending) totals per chain and currency, from local state only.
    pub fn balances(&self) -> Vec<Balance> {
        let mut map: BTreeMap<(u64, String), Balance> = BTreeMap::new();
        for r in &self.contents.notes {
            if r.status == NoteStatus::Spent {
                continue;
            }
            let chain_id = r.note.chain_id;
            let Ok(chain) = chain_by_id(chain_id) else {
                continue;
            };
            let Ok(pool) = chain.pool(&r.note.currency, &r.note.amount) else {
                continue;
            };
            let b = map
                .entry((chain_id, r.note.currency.clone()))
                .or_insert(Balance {
                    chain_id,
                    currency: r.note.currency.clone(),
                    notes: 0,
                    pending: 0,
                    total: U256::ZERO,
                    decimals: pool.decimals,
                });
            match r.status {
                NoteStatus::Deposited => {
                    b.notes += 1;
                    b.total += pool.denomination();
                }
                NoteStatus::Pending => b.pending += 1,
                NoteStatus::Spent => {}
            }
        }
        map.into_values().collect()
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn roundtrip_and_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.db");
        let pool = address!("12D66f87A04A9E220743712cE6d9bB1B5616B8Fc");
        let note = Note::random(1, "eth", "0.1");
        let secret = note.to_note_string();
        {
            let mut db = NoteDb::create(&path, "hunter2").unwrap();
            let id = db.insert(note, pool, NoteStatus::Pending).unwrap();
            db.update(&id, |r| r.status = NoteStatus::Deposited)
                .unwrap();
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(&secret[20..]), "note leaked in plaintext");

        assert!(matches!(NoteDb::open(&path, "wrong"), Err(Error::Decrypt)));
        let db = NoteDb::open(&path, "hunter2").unwrap();
        assert_eq!(db.notes().len(), 1);
        assert_eq!(db.notes()[0].note.to_note_string(), secret);
        let b = db.balances();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].formatted(), "0.1");
    }

    #[test]
    fn select_filters_by_chain_currency_and_amount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.db");
        let pool = address!("12D66f87A04A9E220743712cE6d9bB1B5616B8Fc");
        let mut db = NoteDb::create(&path, "pw").unwrap();
        for (chain, cur, amt) in [
            (1, "eth", "0.1"),
            (1, "eth", "1"),
            (1, "dai", "100"),
            (11155111, "eth", "0.1"),
        ] {
            db.insert(Note::random(chain, cur, amt), pool, NoteStatus::Deposited)
                .unwrap();
        }
        let count = |f: NoteFilter| db.select(&f).len();
        assert_eq!(count(NoteFilter::default()), 4);
        assert_eq!(
            count(NoteFilter {
                chain_id: Some(1),
                ..Default::default()
            }),
            3
        );
        assert_eq!(
            count(NoteFilter {
                currency: Some("ETH".into()),
                ..Default::default()
            }),
            3
        );
        assert_eq!(
            count(NoteFilter {
                amount: Some("0.10".into()),
                ..Default::default()
            }),
            2
        );
        assert_eq!(
            count(NoteFilter {
                chain_id: Some(1),
                currency: Some("eth".into()),
                amount: Some("0.1".into()),
            }),
            1
        );
        assert_eq!(
            count(NoteFilter {
                chain_id: Some(56),
                ..Default::default()
            }),
            0
        );
    }

    #[test]
    fn second_handle_is_refused_while_first_is_open() {
        // Regression: two open handles each saved their own snapshot, so the
        // later save erased notes the other had added.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.db");
        let pool = address!("12D66f87A04A9E220743712cE6d9bB1B5616B8Fc");
        drop(NoteDb::create(&path, "pw").unwrap());

        let withdraw = NoteDb::open(&path, "pw").unwrap();
        let err = NoteDb::open(&path, "pw")
            .err()
            .expect("second open must fail");
        assert!(err.to_string().contains("in use"), "{err}");
        drop(withdraw);

        let mut deposit = NoteDb::open(&path, "pw").unwrap();
        deposit
            .insert(Note::random(1, "eth", "0.1"), pool, NoteStatus::Pending)
            .unwrap();
        drop(deposit);
        assert_eq!(NoteDb::open(&path, "pw").unwrap().notes().len(), 1);
    }

    #[test]
    fn tampered_header_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.db");
        NoteDb::create(&path, "pw").unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let tampered = raw.replace("\"t_cost\": 2", "\"t_cost\": 3");
        std::fs::write(&path, tampered).unwrap();
        assert!(NoteDb::open(&path, "pw").is_err());
    }
}
