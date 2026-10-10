//! Download-once, hash-pinned cache for the circuit and proving key.
//!
//! The files are ~34 MB together, too large to ship inside the crate, so they
//! are fetched from the tornado-cli repository on first use and verified
//! against SHA-256 digests compiled into this crate.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

macro_rules! artifact_url {
    ($f:literal) => {
        concat!(
            "https://raw.githubusercontent.com/tornadocash/tornado-cli/378ddf8b8b92a4924037d7b64a94dbfd5a7dd6e8/build/circuits/",
            $f
        )
    };
}

pub struct Artifact {
    pub file_name: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub const CIRCUIT: Artifact = Artifact {
    file_name: "tornado.json",
    url: artifact_url!("tornado.json"),
    sha256: "3ddd61dbff09caeec82d8edde95c674a3c34f9e66b1fe9f2c8783e72fe536f98",
};

pub const PROVING_KEY: Artifact = Artifact {
    file_name: "tornadoProvingKey.bin",
    url: artifact_url!("tornadoProvingKey.bin"),
    sha256: "8e2d2f22beafb5a9666daebca57b13f8029c3656c65fcfbcc86e2418fa16a3af",
};

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

impl Artifact {
    fn err(&self, msg: impl Into<String>) -> Error {
        Error::Artifact {
            name: self.file_name.to_string(),
            msg: msg.into(),
        }
    }

    /// Read the artifact from `dir`, downloading it first if it is missing.
    /// The digest is checked on every load, not only after download.
    pub async fn load(&self, dir: &Path, client: &reqwest::Client) -> Result<Vec<u8>> {
        let path = dir.join(self.file_name);
        if let Ok(bytes) = std::fs::read(&path) {
            if sha256_hex(&bytes) == self.sha256 {
                return Ok(bytes);
            }
            tracing::warn!("{} failed its checksum, downloading again", path.display());
        }
        let what = format!("download {}", self.file_name);
        let bytes = crate::net::fetch(client, client.get(self.url), &what, true, true)
            .await?
            .body
            .to_vec();
        if sha256_hex(&bytes) != self.sha256 {
            return Err(self.err("downloaded file does not match the pinned SHA-256"));
        }
        std::fs::create_dir_all(dir)?;
        // A unique temp name per writer, so concurrent downloads into the same
        // directory don't rename each other's file away.
        let tmp: PathBuf = dir.join(format!(
            "{}.{}-{:016x}.part",
            self.file_name,
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(bytes)
    }

    /// Load from an explicit local file (offline use).
    pub fn load_file(&self, path: &Path) -> Result<Vec<u8>> {
        let bytes = std::fs::read(path)?;
        if sha256_hex(&bytes) != self.sha256 {
            return Err(self.err(format!(
                "{} does not match the pinned SHA-256",
                path.display()
            )));
        }
        Ok(bytes)
    }
}
