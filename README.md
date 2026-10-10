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
tornado-rs deposit eth 0.1 --ledger                      # or sign on a Ledger
tornado-rs balances
tornado-rs notes list
tornado-rs withdraw <note-id> 0xRecipient --relayer https://relayer.example
tornado-rs withdraw <note-id> 0xRecipient --self-relay   # pays gas from PRIVATE_KEY's account
tornado-rs withdraw <note-id> 0xRecipient --calldata     # prints the call for another account to send
tornado-rs notes import tornado-eth-0.1-1-0x...          # bring in tornado-cli notes
tornado-rs stats                                         # deposit counts per pool
```

`deposit --calldata` and `withdraw --calldata` send nothing: they print only the `0x` calldata on stdout, so it
can be nested in another tool's command (for example a Safe CLI), and print the target pool and the value to send
on stderr. A deposit made this way saves its note as pending first; `balances --check` marks it deposited once the
call is mined. ETH deposits need the pool's denomination as the call's value, which the other tool supplies.

Environment variables: `ETH_RPC_URL`, `PRIVATE_KEY` or `PRIVATE_KEY_FILE`, `TORNADO_PASSWORD` (for scripts),
`TORNADO_RS_DATA_DIR`, `TORNADO_RS_PROXY` (e.g. `socks5h://127.0.0.1:9050` to route RPC, relayer and artifact
traffic through Tor).

Notes, the event cache and proving artifacts live in `~/.tornado-cash-rs` unless `--data-dir` or
`TORNADO_RS_DATA_DIR` says otherwise.

To sign with a Ledger instead of a private key, open the Ethereum app on the device and pass `--ledger` (or set
`TORNADO_RS_LEDGER=true`). It uses Ledger Live account 0 by default; pick another with `--ledger-index <n>`, or give a
full path with `--hd-path "m/44'/60'/0'/0"`. On Linux you may need Ledger's udev rules to reach the device.

### Seeing network activity

`--log-network` (or `TORNADO_RS_LOG_NETWORK=summary`) prints one line to stderr for every request the CLI
sends: what it is, where it goes, the result, the response size and the time taken. It also says whether
traffic goes through a proxy and who resolves hostnames.

```
INFO tornado_cash_rs::net: no proxy: requests connect directly and hostnames are resolved by the system resolver
INFO tornado_cash_rs::net: POST https://mainnet.infura.io/… [rpc eth_chainId] -> ok, 5 B in 464 ms
INFO tornado_cash_rs::net: GET https://raw.githubusercontent.com/…/tornado.json [download tornado.json] -> 200 OK, 18.6 MiB in 1509 ms
```

RPC URLs are shown as origin only (`/…`), since they often carry an API key. `--log-network=full` also prints
request and response bodies: RPC parameters and results, signed transactions, relayer requests with the
proof and recipient. Treat that output as sensitive. The CLI talks only to the RPC endpoint, the relayer you
pass, and `raw.githubusercontent.com` for the proving artifacts. For connection-level detail (DNS, TLS,
connection reuse), add `TORNADO_RS_LOG=hyper_util=debug,reqwest=debug`.

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
ETH_RPC_URL=https://... cargo test --release -p tornado-cash-rs-fork-tests   # mainnet-fork tests
```

The fork tests (`crates/fork-tests`) start an anvil node inside the test process, forked from `ETH_RPC_URL`
(an archive mainnet endpoint) at a pinned block (`FORK_BLOCK` overrides it). They cover deposits (ETH and DAI), event
sync against the on-chain root, self-relayed and relayed withdrawals through an in-process mock relayer, and the CLI
commands end to end. Without `ETH_RPC_URL` they print `skipping` and pass. The first run scans the pools' deposit
history up to the fork block and caches it under `target/fork-test-cache/` (`FORK_TEST_CACHE` overrides it).

## License

GPL-3.0-or-later; see [COPYING](COPYING). The witness calculator in
`crates/tornado-cash-rs/src/prover/witness.js` is a port of snarkjs 0.1's
`calculateWitness` (Copyright 2018 0kims association, GPL-3.0-or-later), so the
crates are distributed under the same license.
