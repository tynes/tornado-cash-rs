//! Client for the Tornado Cash relayer HTTP API (tornado-relayer v4/v5):
//! `GET /status`, `POST /v1/tornadoWithdraw`, `GET /v1/jobs/:id`.

use crate::chains::Pool;
use crate::error::{Error, Result};
use crate::net::fetch;
use crate::prover::WithdrawProof;
use alloy::primitives::{Address, B256, U256};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

/// A public relayer from the on-chain Relayer Registry.
#[derive(Clone, Copy, Debug)]
pub struct KnownRelayer {
    /// The relayer's ENS name in the registry.
    pub ens: &'static str,
    /// The `url` text record of `<chain>-tornado.<ens>`.
    pub url: &'static str,
    /// TORN staked in the registry, rounded down.
    pub stake: u32,
}

/// Mainnet block the [`known_relayers`] snapshot was read at.
pub const RELAYER_SNAPSHOT_BLOCK: u64 = 26_166_543;

const fn r(ens: &'static str, url: &'static str, stake: u32) -> KnownRelayer {
    KnownRelayer { ens, url, stake }
}

/// Relayers registered in the Relayer Registry (relayer-registry.eth,
/// 0x58E8dCC13BE9780fC42E8723D8EaD4CF46943dF2) that served `/status` for the
/// chain at [`RELAYER_SNAPSHOT_BLOCK`], most TORN staked first. The official
/// UI picks relayers weighted by that stake, so the first is the most used.
/// Empty for chains with no live registered relayer (Sepolia).
pub fn known_relayers(chain_id: u64) -> &'static [KnownRelayer] {
    match chain_id {
        1 => {
            const L: &[KnownRelayer] = &[
                r("reltor.eth", "https://eth.reltor.su", 42_943),
                r("safe-torn.eth", "https://eth3.safetorn.ovh", 26_604),
                r("00relayer.eth", "https://eth.00relayer.xyz", 17_148),
                r("sky-relayer.eth", "https://sky-relayer.xyz", 14_630),
                r(
                    "master-relayer.eth",
                    "https://eth.master-relayer.com",
                    12_263,
                ),
            ];
            L
        }
        56 => {
            const L: &[KnownRelayer] = &[
                r("reltor.eth", "https://binance.reltor.su", 42_943),
                r("safe-torn.eth", "https://bsc3.safetorn.ovh", 26_604),
                r("00relayer.eth", "https://bsc.00relayer.xyz", 17_148),
            ];
            L
        }
        100 => {
            const L: &[KnownRelayer] = &[
                r("torntool.eth", "https://gnosis.theavengers.me", 5_332),
                r(
                    "dieguis-and-martis.eth",
                    "https://gnosis.dieguis-and-martis.xyz",
                    995,
                ),
            ];
            L
        }
        137 => {
            const L: &[KnownRelayer] = &[
                r("reltor.eth", "https://polygon.reltor.su", 42_943),
                r("safe-torn.eth", "https://poly3.safetorn.ovh", 26_604),
                r("hello-relayer.eth", "https://polygon.hirelay04.xyz", 9_764),
            ];
            L
        }
        42161 => {
            const L: &[KnownRelayer] = &[
                r("safe-torn.eth", "https://arb3.safetorn.ovh", 26_604),
                r("torn-city.eth", "https://arb.torncity.fun", 9_420),
                r("torntool.eth", "https://arb.theavengers.me", 5_332),
            ];
            L
        }
        10 => {
            const L: &[KnownRelayer] = &[
                r("torntool.eth", "https://op.theavengers.me", 5_332),
                r(
                    "dieguis-and-martis.eth",
                    "https://op.dieguis-and-martis.xyz",
                    995,
                ),
                r("bitah.eth", "https://optimism-tornado.bitah.link", 739),
            ];
            L
        }
        43114 => {
            const L: &[KnownRelayer] = &[
                r("hello-relayer.eth", "https://avax.hirelay04.xyz", 9_764),
                r("torntool.eth", "https://avax.theavengers.me", 5_332),
                r(
                    "dieguis-and-martis.eth",
                    "https://avax.dieguis-and-martis.xyz",
                    995,
                ),
            ];
            L
        }
        _ => &[],
    }
}

/// Gas budgeted for a relayed withdrawal when quoting the fee (tornado-cli uses the same).
pub const WITHDRAW_GAS_LIMIT: u64 = 500_000;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerStatus {
    pub reward_account: Address,
    /// Chain id the relayer serves; older relayers call it `netId`.
    #[serde(alias = "netId", default)]
    pub chain_id: Option<Value>,
    /// Token prices in wei of the native coin, keyed by lower-case symbol.
    #[serde(default)]
    pub eth_prices: HashMap<String, Value>,
    /// Service fee in percent, e.g. `0.3`.
    pub tornado_service_fee: f64,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub health: Option<Value>,
}

impl RelayerStatus {
    pub fn serves_chain(&self, chain_id: u64) -> bool {
        match &self.chain_id {
            None => true,
            Some(Value::Number(n)) => n.as_u64() == Some(chain_id),
            Some(Value::String(s)) => s == "*" || s.parse::<u64>().ok() == Some(chain_id),
            _ => false,
        }
    }

    fn price(&self, currency: &str) -> Option<U256> {
        match self.eth_prices.get(currency)? {
            Value::String(s) => U256::from_str_radix(s, 10).ok(),
            Value::Number(n) => n.as_u64().map(U256::from),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobStatus {
    pub status: String,
    #[serde(default)]
    pub tx_hash: Option<B256>,
    #[serde(default)]
    pub confirmations: Option<u64>,
    #[serde(default)]
    pub failed_reason: Option<String>,
}

pub struct RelayerClient {
    base: String,
    http: reqwest::Client,
}

impl RelayerClient {
    pub fn new(url: &str, http: Option<reqwest::Client>) -> Result<Self> {
        let base = url.trim_end_matches('/').to_string();
        if base.ends_with(".eth") {
            return Err(Error::Relayer(
                "ENS relayer names are not supported; use the relayer's https URL".into(),
            ));
        }
        let base = if base.starts_with("http://") || base.starts_with("https://") {
            base
        } else {
            format!("https://{base}")
        };
        Ok(RelayerClient {
            base,
            http: http.unwrap_or_default(),
        })
    }

    pub async fn status(&self) -> Result<RelayerStatus> {
        let req = self.http.get(format!("{}/status", self.base));
        let r = fetch(&self.http, req, "relayer status", false, true).await?;
        Ok(serde_json::from_slice(&r.body)?)
    }

    /// The fee to put in the proof: gas for the relayed transaction plus the
    /// relayer's percentage, converted to the pool token for ERC-20 pools.
    pub fn quote_fee(
        status: &RelayerStatus,
        pool: &Pool,
        gas_price: u128,
        refund: U256,
    ) -> Result<U256> {
        let total = pool.denomination();
        // Percent with up to 6 decimal places, applied in integer math.
        let ppm = (status.tornado_service_fee * 1_000_000.0).round();
        if !(0.0..=100_000_000.0).contains(&ppm) {
            return Err(Error::Relayer("relayer reported a nonsensical fee".into()));
        }
        let fee_percent = total * U256::from(ppm as u64) / U256::from(100_000_000u64);
        let expense = U256::from(gas_price) * U256::from(WITHDRAW_GAS_LIMIT);
        let fee = if pool.is_native() {
            expense + fee_percent
        } else {
            let price = status.price(pool.currency).ok_or_else(|| {
                Error::Relayer(format!("relayer has no price for {}", pool.currency))
            })?;
            if price.is_zero() {
                return Err(Error::Relayer("relayer reported a zero token price".into()));
            }
            (expense + refund) * U256::from(10u64).pow(U256::from(pool.decimals)) / price
                + fee_percent
        };
        if fee >= total {
            return Err(Error::Relayer("relayer fee exceeds the note amount".into()));
        }
        tracing::debug!(
            "relayer fee {fee} = gas {expense} (gas price {gas_price}) + service fee {fee_percent} ({}%), refund {refund}",
            status.tornado_service_fee
        );
        Ok(fee)
    }

    /// Submit a withdrawal job; returns the job id.
    pub async fn submit(&self, pool: &Pool, w: &WithdrawProof) -> Result<String> {
        let a = &w.args;
        let u = |x: &U256| format!("0x{}", hex::encode(x.to_be_bytes::<32>()));
        let body = json!({
            "contract": format!("{:#x}", pool.address),
            "proof": format!("0x{}", hex::encode(w.proof_bytes())),
            "args": [
                format!("{:#x}", a.root),
                format!("{:#x}", a.nullifier_hash),
                format!("{:#x}", a.recipient),
                format!("{:#x}", a.relayer),
                u(&a.fee),
                u(&a.refund),
            ],
        });
        let req = self
            .http
            .post(format!("{}/v1/tornadoWithdraw", self.base))
            .json(&body);
        let r = fetch(&self.http, req, "relayer withdraw", false, false).await?;
        let status = r.status;
        let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = v
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("request rejected");
            return Err(Error::Relayer(format!("{status}: {msg}")));
        }
        let id = v
            .get("id")
            .and_then(|i| i.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Relayer("relayer did not return a job id".into()))?;
        tracing::info!("relayer accepted withdrawal job {id}");
        Ok(id)
    }

    pub async fn job(&self, id: &str) -> Result<JobStatus> {
        let req = self.http.get(format!("{}/v1/jobs/{id}", self.base));
        let r = fetch(&self.http, req, "relayer job status", false, true).await?;
        Ok(serde_json::from_slice(&r.body)?)
    }

    /// Poll a job until it is CONFIRMED (returns its tx hash) or FAILED.
    pub async fn wait(&self, id: &str, mut on_update: impl FnMut(&JobStatus)) -> Result<B256> {
        loop {
            let j = self.job(id).await?;
            tracing::debug!("relayer job {id}: {}", j.status);
            on_update(&j);
            match j.status.as_str() {
                "CONFIRMED" => {
                    return j
                        .tx_hash
                        .ok_or_else(|| Error::Relayer("confirmed job has no tx hash".into()))
                }
                "FAILED" => {
                    return Err(Error::Relayer(
                        j.failed_reason.unwrap_or_else(|| "job failed".into()),
                    ))
                }
                _ => tokio::time::sleep(Duration::from_secs(3)).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::chain_by_name;

    fn status(fee: f64) -> RelayerStatus {
        serde_json::from_value(json!({
            "rewardAccount": "0x0000000000000000000000000000000000000001",
            "netId": 1,
            "ethPrices": {"dai": "500000000000000"},
            "tornadoServiceFee": fee,
        }))
        .unwrap()
    }

    #[test]
    fn eth_fee() {
        let c = chain_by_name("mainnet").unwrap();
        let p = c.pool("eth", "1").unwrap();
        // 10 gwei * 500k gas = 0.005 ETH, plus 0.3% of 1 ETH = 0.003 ETH
        let fee = RelayerClient::quote_fee(&status(0.3), p, 10_000_000_000, U256::ZERO).unwrap();
        assert_eq!(fee, U256::from(8_000_000_000_000_000u64));
        assert!(status(0.3).serves_chain(1));
        assert!(!status(0.3).serves_chain(56));
    }

    #[test]
    fn token_fee() {
        let c = chain_by_name("mainnet").unwrap();
        let p = c.pool("dai", "100").unwrap();
        // 0.005 ETH at 0.0005 ETH/DAI = 10 DAI, plus 0.3 DAI
        let fee = RelayerClient::quote_fee(&status(0.3), p, 10_000_000_000, U256::ZERO).unwrap();
        assert_eq!(fee, U256::from(10_300_000_000_000_000_000u128));
    }

    #[test]
    fn known_relayers_sorted_by_stake() {
        for c in crate::chains::all_chains() {
            let rs = known_relayers(c.chain_id);
            assert!(
                rs.windows(2).all(|w| w[0].stake >= w[1].stake),
                "{}",
                c.name
            );
            assert!(rs.iter().all(|r| r.url.starts_with("https://")));
        }
        assert_eq!(known_relayers(1)[0].ens, "reltor.eth");
        assert!(known_relayers(11155111).is_empty());
    }
}
