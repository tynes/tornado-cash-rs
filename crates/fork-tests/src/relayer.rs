//! A minimal in-process tornado-relayer: enough of `GET /status`,
//! `POST /v1/tornadoWithdraw` and `GET /v1/jobs/:id` for `RelayerClient`.
//! Jobs are sent to the fork from the relayer's own account and confirmed
//! before the POST returns.

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tornado_cash_rs::eth::TornadoClient;

mod bindings {
    #![allow(clippy::too_many_arguments)]

    alloy::sol! {
        #[sol(rpc)]
        interface ITornadoInstance {
            function withdraw(
                bytes calldata _proof,
                bytes32 _root,
                bytes32 _nullifierHash,
                address _recipient,
                address _relayer,
                uint256 _fee,
                uint256 _refund
            ) external payable;
        }
    }
}
use bindings::ITornadoInstance;

/// Values reported by `/status`.
#[derive(Clone, Debug)]
pub struct RelayerConfig {
    /// Service fee in percent.
    pub service_fee: f64,
    /// Token prices in wei, keyed by lower-case symbol.
    pub eth_prices: HashMap<String, U256>,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        RelayerConfig {
            service_fee: 0.3,
            // 0.0005 ETH per DAI
            eth_prices: [("dai".to_string(), U256::from(500_000_000_000_000u64))].into(),
        }
    }
}

struct Inner {
    client: TornadoClient,
    reward_account: Address,
    config: RelayerConfig,
    jobs: Mutex<HashMap<String, Value>>,
}

pub struct MockRelayer {
    pub url: String,
    pub reward_account: Address,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for MockRelayer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl MockRelayer {
    /// Serve on 127.0.0.1, sending transactions to `rpc_url` as `signer`.
    pub async fn start(rpc_url: &str, signer: PrivateKeySigner, config: RelayerConfig) -> Self {
        let reward_account = signer.address();
        let client = TornadoClient::connect(rpc_url, Some(signer), None)
            .await
            .expect("relayer connects to fork");
        let state = Arc::new(Inner {
            client,
            reward_account,
            config,
            jobs: Mutex::default(),
        });
        let app = Router::new()
            .route("/status", get(status))
            .route("/v1/tornadoWithdraw", post(withdraw))
            .route("/v1/jobs/{id}", get(job))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        MockRelayer {
            url,
            reward_account,
            server,
        }
    }
}

async fn status(State(s): State<Arc<Inner>>) -> Json<Value> {
    let prices: HashMap<_, _> = s
        .config
        .eth_prices
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect();
    Json(json!({
        "rewardAccount": s.reward_account,
        "netId": s.client.chain.chain_id,
        "ethPrices": prices,
        "tornadoServiceFee": s.config.service_fee,
        "version": "mock",
        "health": {"status": true},
    }))
}

fn bad_request(msg: impl ToString) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": msg.to_string()})),
    )
}

async fn withdraw(
    State(s): State<Arc<Inner>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let field = |v: &Value| v.as_str().map(str::to_string).ok_or("expected a string");
    let contract: Address = field(&body["contract"])
        .map_err(bad_request)?
        .parse()
        .map_err(bad_request)?;
    let proof: Bytes = field(&body["proof"])
        .map_err(bad_request)?
        .parse()
        .map_err(bad_request)?;
    let args = body["args"]
        .as_array()
        .filter(|a| a.len() == 6)
        .ok_or_else(|| bad_request("args must have 6 entries"))?;
    let word = |i: usize| -> Result<B256, _> {
        field(&args[i])
            .map_err(bad_request)?
            .parse::<B256>()
            .map_err(bad_request)
    };
    let addr = |i: usize| -> Result<Address, _> {
        field(&args[i])
            .map_err(bad_request)?
            .parse::<Address>()
            .map_err(bad_request)
    };
    let (root, nullifier_hash) = (word(0)?, word(1)?);
    let (recipient, relayer) = (addr(2)?, addr(3)?);
    let fee = U256::from_be_bytes(word(4)?.0);
    let refund = U256::from_be_bytes(word(5)?.0);
    if relayer != s.reward_account {
        return Err(bad_request("proof is not for this relayer"));
    }

    let instance = ITornadoInstance::new(contract, s.client.provider());
    let pending = instance
        .withdraw(proof, root, nullifier_hash, recipient, relayer, fee, refund)
        .value(refund)
        .send()
        .await
        .map_err(bad_request)?;
    let tx = *pending.tx_hash();
    let receipt = pending.get_receipt().await.map_err(bad_request)?;
    let job = if receipt.status() {
        json!({"status": "CONFIRMED", "txHash": tx, "confirmations": 1})
    } else {
        json!({"status": "FAILED", "txHash": tx, "failedReason": "withdraw reverted"})
    };
    let mut jobs = s.jobs.lock().unwrap();
    let id = format!("job-{}", jobs.len() + 1);
    jobs.insert(id.clone(), job);
    Ok(Json(json!({"id": id})))
}

async fn job(
    State(s): State<Arc<Inner>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    s.jobs
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
