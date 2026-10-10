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
        v.get("id")
            .and_then(|i| i.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Relayer("relayer did not return a job id".into()))
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
}
