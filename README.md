# tornado-cash-rs

Rust crates for [Tornado Cash Classic](https://github.com/tornadocash/tornado-core):

| crate | what it is |
| --- | --- |
| [`tornado-cash-rs`](crates/tornado-cash-rs) | Library: note types, Pedersen/MiMC hashing, Merkle tree, Groth16 prover using the original trusted-setup key, Ethereum client, relayer client, encrypted note database |
| [`tornado-cash-rs-cli`](crates/tornado-cash-rs-cli) | The `tornado-rs` command line client |

> **Unaudited software.** Losing a note or its database password means losing the funds it controls. Try Sepolia first.

## Install

```sh
cargo install --path crates/tornado-cash-rs-cli
```

## Use

```sh
export ETH_RPC_URL=https://...           # mainnet or Sepolia
tornado-rs init                          # create the encrypted note database
PRIVATE_KEY=0x... tornado-rs deposit eth 0.1
tornado-rs balances
tornado-rs notes list
tornado-rs withdraw <note-id> 0xRecipient --relayer https://relayer.example
tornado-rs withdraw <note-id> 0xRecipient --self-relay   # pays gas from PRIVATE_KEY's account
tornado-rs notes import tornado-eth-0.1-1-0x...          # bring in tornado-cli notes
tornado-rs stats                                         # deposit counts per pool
```

Environment variables: `ETH_RPC_URL`, `PRIVATE_KEY` or `PRIVATE_KEY_FILE`, `TORNADO_PASSWORD` (for scripts),
`TORNADO_RS_DATA_DIR`, `TORNADO_RS_PROXY` (e.g. `socks5h://127.0.0.1:9050` to route RPC, relayer and artifact
traffic through Tor).

## Supported chains

| tier | chains | pools |
| --- | --- | --- |
| primary | Ethereum mainnet | ETH 0.1/1/10/100, DAI 100–100k, USDT 100/1k, WBTC 0.1/1/10 |
| primary | Sepolia | ETH 0.1/1, DAI 100 |
| secondary | BNB Chain, Gnosis, Polygon, Arbitrum, Optimism, Avalanche | native-coin pools |

USDC pools are excluded (Circle froze the pool contracts, so withdrawals revert) and cDAI pools are excluded
(Compound v2 is deprecated). Secondary chains share the same contracts but have small anonymity sets and few
relayers; the CLI warns when you use them.

## How it works

* **Notes** use the tornado-cli string format `tornado-<currency>-<amount>-<chainId>-0x<nullifier‖secret>`, so
  notes move freely between this tool, tornado-cli and the Tornado UI.
* **Proving** uses the circom 0.0.x circuit (`tornado.json`) and websnark proving key
  (`tornadoProvingKey.bin`) from the 2020 trusted setup. They are downloaded on first use from a pinned
  tornado-cli commit and checked against SHA-256 digests compiled into the crate. The witness is computed by
  running the circuit's own template code in an embedded JavaScript engine (boa), exactly as snarkjs did, and
  the Groth16 prover is native arkworks. Every proof is verified against the verifying key from the deployed
  `Verifier.sol` before it is sent anywhere.
* **The note database** is a single file sealed with XChaCha20-Poly1305 under an Argon2id key; the header is
  authenticated, writes are atomic and `0600`. A deposit's note is saved *before* the transaction is sent.
* **Event sync** pulls `Deposit` events with chunked `eth_getLogs` (span halves on RPC errors) into a
  plaintext cache of public commitments under the data directory.

## Tests

```sh
cargo test                                   # unit tests
cargo test --release -- --ignored            # real proof with the trusted-setup key (downloads 34 MB)
```

## License

MIT OR Apache-2.0
