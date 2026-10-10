//! Logging for every request this crate sends over the network.
//!
//! All events go to the [`TARGET`] tracing target, so they can be switched on
//! without the rest of the crate's logs:
//!
//! * `info`: one line per request saying what it is (JSON-RPC methods, relayer
//!   endpoint, artifact download), where it goes, how it ended (HTTP status or
//!   RPC error), the response size and how long it took.
//! * `trace`: the request and response bodies as well. These hold addresses,
//!   proofs, signed transactions and RPC results.
//!
//! RPC URLs often carry an API key in the path or query, so only their origin
//! is logged.

use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket, ResponsePayload};
use alloy::transports::{TransportError, TransportFut};
use bytes::Bytes;
use reqwest::{RequestBuilder, StatusCode, Url};
use std::fmt::Write;
use std::task::{Context, Poll};
use std::time::Instant;
use tower::{Layer, Service};

/// The tracing target for network events.
pub const TARGET: &str = "tornado_cash_rs::net";

/// `scheme://host:port` of `url`, with `/…` appended when a path, query or
/// credentials were dropped.
pub fn redact_url(url: &Url) -> String {
    // Built by hand: `Url::origin` is opaque ("null") for socks:// URLs.
    let mut origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));
    if let Some(port) = url.port() {
        let _ = write!(origin, ":{port}");
    }
    let hidden = !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || !url.username().is_empty()
        || url.password().is_some();
    if hidden {
        format!("{origin}/…")
    } else {
        origin
    }
}

/// `e` followed by its sources, which say why a request failed (connection
/// refused, DNS, TLS, proxy).
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        let c_str = c.to_string();
        // Wrappers often repeat their source's message.
        if !c_str.is_empty() && !s.contains(&c_str) {
            let _ = write!(s, ": {c_str}");
        }
        src = c.source();
    }
    s
}

fn size(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    }
}

/// A response whose body has been read.
pub(crate) struct Fetched {
    pub status: StatusCode,
    pub body: Bytes,
}

/// Send `req` on `client`, read the whole response and log both. `what` says
/// what the request is for. Bodies are logged at trace level unless
/// `binary`. With `check_status`, a non-2xx status is returned as an error.
pub(crate) async fn fetch(
    client: &reqwest::Client,
    req: RequestBuilder,
    what: &str,
    binary: bool,
    check_status: bool,
) -> reqwest::Result<Fetched> {
    let req = req.build()?;
    let line = format!("{} {} [{what}]", req.method(), req.url());
    if !binary {
        if let Some(b) = req.body().and_then(|b| b.as_bytes()) {
            tracing::trace!(target: TARGET, "{line} request body: {}", String::from_utf8_lossy(b));
        }
    }
    let start = Instant::now();
    let result = async {
        let resp = client.execute(req).await?;
        let status = resp.status();
        let status_err = resp.error_for_status_ref().err();
        let body = resp.bytes().await?;
        Ok::<_, reqwest::Error>((status, status_err, body))
    }
    .await;
    let ms = start.elapsed().as_millis();
    let (status, status_err, body) = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(target: TARGET, "{line} -> failed after {ms} ms: {}", error_chain(&e));
            return Err(e);
        }
    };
    tracing::info!(target: TARGET, "{line} -> {status}, {} in {ms} ms", size(body.len()));
    if !binary {
        tracing::trace!(target: TARGET, "{line} response body: {}", String::from_utf8_lossy(&body));
    }
    match status_err {
        Some(e) if check_status => Err(e),
        _ => Ok(Fetched { status, body }),
    }
}

/// A transport layer that logs each JSON-RPC request and its outcome.
#[derive(Clone, Debug)]
pub struct RpcLogLayer {
    dest: String,
}

impl RpcLogLayer {
    /// `url` is the RPC endpoint; only its origin is logged.
    pub fn new(url: &Url) -> Self {
        RpcLogLayer {
            dest: redact_url(url),
        }
    }
}

impl<S> Layer<S> for RpcLogLayer {
    type Service = RpcLogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcLogService {
            inner,
            dest: self.dest.clone(),
        }
    }
}

/// The service built by [`RpcLogLayer`].
#[derive(Clone, Debug)]
pub struct RpcLogService<S> {
    inner: S,
    dest: String,
}

impl<S> Service<RequestPacket> for RpcLogService<S>
where
    S: Service<RequestPacket, Future = TransportFut<'static>, Error = TransportError>
        + Send
        + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let methods = req.method_names().collect::<Vec<_>>().join(",");
        let line = format!("POST {} [rpc {methods}]", self.dest);
        if tracing::enabled!(target: TARGET, tracing::Level::TRACE) {
            if let Ok(body) = serde_json::to_string(&req) {
                tracing::trace!(target: TARGET, "{line} request body: {body}");
            }
        }
        let start = Instant::now();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let result = fut.await;
            let ms = start.elapsed().as_millis();
            match &result {
                Ok(resp) => {
                    let mut bytes = 0;
                    let mut errors = 0;
                    let mut body = String::new();
                    for p in resp.payloads() {
                        match p {
                            ResponsePayload::Success(raw) => {
                                bytes += raw.get().len();
                                let _ = write!(body, "{} ", raw.get());
                            }
                            ResponsePayload::Failure(e) => {
                                errors += 1;
                                let _ = write!(body, "error {} {} ", e.code, e.message);
                            }
                        }
                    }
                    let outcome = match resp.first_error_message() {
                        Some(msg) if errors > 1 => format!("{errors} errors, first: {msg}"),
                        Some(msg) => format!("error: {msg}"),
                        None => "ok".into(),
                    };
                    tracing::info!(
                        target: TARGET,
                        "{line} -> {outcome}, {} in {ms} ms",
                        size(bytes)
                    );
                    tracing::trace!(target: TARGET, "{line} response: {}", body.trim_end());
                }
                Err(e) => tracing::info!(
                    target: TARGET,
                    "{line} -> failed after {ms} ms: {}",
                    error_chain(e)
                ),
            }
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_api_keys() {
        let u = |s: &str| redact_url(&s.parse().unwrap());
        assert_eq!(
            u("https://mainnet.infura.io/v3/abc123"),
            "https://mainnet.infura.io/…"
        );
        assert_eq!(u("https://rpc.example?key=abc"), "https://rpc.example/…");
        assert_eq!(u("https://user:pw@rpc.example"), "https://rpc.example/…");
        assert_eq!(u("http://127.0.0.1:8545"), "http://127.0.0.1:8545");
        assert_eq!(u("http://127.0.0.1:8545/"), "http://127.0.0.1:8545");
        assert_eq!(
            u("socks5h://user:pw@127.0.0.1:9050"),
            "socks5h://127.0.0.1:9050/…"
        );
    }

    /// Serve one canned HTTP response on a local port.
    fn serve_once(status: &str, body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            sock.write_all(head.as_bytes()).unwrap();
            sock.write_all(body.as_bytes()).unwrap();
        });
        url
    }

    #[tokio::test]
    async fn fetch_returns_body_and_checks_status() {
        let client = reqwest::Client::new();
        let url = serve_once("200 OK", r#"{"ok":true}"#);
        let r = fetch(&client, client.get(&url), "test", false, true)
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(&r.body[..], br#"{"ok":true}"#);

        let url = serve_once("500 Internal Server Error", r#"{"error":"boom"}"#);
        assert!(fetch(&client, client.get(&url), "test", false, true)
            .await
            .is_err());
        let url = serve_once("500 Internal Server Error", r#"{"error":"boom"}"#);
        let r = fetch(&client, client.get(&url), "test", false, false)
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(&r.body[..], br#"{"error":"boom"}"#);
    }
}
