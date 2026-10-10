//! `tornado-rs`: a command line client for Tornado Cash Classic.
//!
//! The binary is a thin wrapper around [`run`], which lets tests drive the CLI
//! in-process.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, B256, U256};
use alloy::signers::ledger::{HDPath, LedgerSigner};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
pub use clap::Parser;
use clap::Subcommand;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use tornado_cash_rs::chains::{all_chains, chain_by_id, format_units, parse_units, Tier};
use tornado_cash_rs::db::{NoteDb, NoteStatus};
use tornado_cash_rs::error::Error;
use tornado_cash_rs::eth::{
    self, build_tree, sync_deposits, DepositCache, GasFees, SyncOptions, TornadoClient,
};
use tornado_cash_rs::note::Note;
use tornado_cash_rs::prover::Prover;
use tornado_cash_rs::relayer::RelayerClient;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "tornado-rs",
    version,
    about = "Deposit to and withdraw from Tornado Cash Classic pools"
)]
pub struct Cli {
    /// Directory for the note database, event cache and proving artifacts
    /// [default: ~/.tornado-cash-rs].
    #[arg(long, global = true, env = "TORNADO_RS_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Ethereum JSON-RPC endpoint.
    #[arg(long, global = true, env = "ETH_RPC_URL", hide_env_values = true)]
    rpc_url: Option<String>,

    /// Route RPC, relayer and artifact traffic through a proxy, e.g. socks5h://127.0.0.1:9050 for Tor.
    #[arg(long, global = true, env = "TORNADO_RS_PROXY")]
    proxy: Option<String>,

    /// Log every network request to stderr: what it is, where it goes, status, size and time.
    /// `full` also logs request and response bodies (addresses, proofs, signed transactions).
    #[arg(
        long,
        global = true,
        env = "TORNADO_RS_LOG_NETWORK",
        value_name = "DETAIL",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "summary"
    )]
    log_network: Option<NetLog>,

    /// Maximum block range per eth_getLogs request.
    #[arg(long, global = true, default_value_t = 10_000)]
    log_span: u64,

    // Secrets come from the environment (or a prompt when unset). The flags
    // are hidden so they stay out of help text and shell history.
    /// Note database password.
    #[arg(
        long,
        global = true,
        env = "TORNADO_PASSWORD",
        hide = true,
        hide_env_values = true
    )]
    password: Option<String>,

    /// Key for deposits and self-relayed withdrawals.
    #[arg(
        long,
        global = true,
        env = "PRIVATE_KEY",
        hide = true,
        hide_env_values = true
    )]
    private_key: Option<String>,

    /// File holding the private key; takes precedence over PRIVATE_KEY.
    #[arg(long, global = true, env = "PRIVATE_KEY_FILE")]
    private_key_file: Option<PathBuf>,

    /// Sign with a Ledger hardware wallet instead of a private key.
    #[arg(long, global = true, env = "TORNADO_RS_LEDGER")]
    ledger: bool,

    /// Ledger Live account index to sign with (path m/44'/60'/<index>'/0/0).
    #[arg(long, global = true, default_value_t = 0, requires = "ledger")]
    ledger_index: usize,

    /// Full derivation path for the Ledger account, e.g. m/44'/60'/0'/0 for legacy MEW/MyCrypto accounts.
    #[arg(
        long,
        global = true,
        requires = "ledger",
        conflicts_with = "ledger_index"
    )]
    hd_path: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum NetLog {
    /// One line per request.
    Summary,
    /// Request and response bodies as well.
    Full,
}

impl Cli {
    /// The tracing directive `--log-network` asks for, if any.
    pub fn network_log_directive(&self) -> Option<String> {
        let level = match self.log_network? {
            NetLog::Summary => "info",
            NetLog::Full => "trace",
        };
        Some(format!("{}={level}", tornado_cash_rs::net::TARGET))
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an encrypted note database.
    Init,
    /// Deposit one note into a pool, e.g. `deposit eth 0.1`. Shows the estimated gas and fee and asks before sending.
    Deposit {
        currency: String,
        amount: String,
        /// Send without asking for confirmation (required when stdin is not a terminal).
        #[arg(long, short)]
        yes: bool,
        /// Save the note as pending and print the deposit calldata instead of sending
        /// it, e.g. for a Safe. The pool address and value go to stderr.
        #[arg(long)]
        calldata: bool,
    },
    /// Withdraw a note to a recipient, through a relayer or from your own account. Shows the fee and asks before sending.
    Withdraw {
        /// Note id (or unique prefix) from `notes list`.
        id: String,
        recipient: Address,
        /// Relayer URL. Without it you must pass --self-relay or --calldata.
        #[arg(long)]
        relayer: Option<String>,
        /// Send the withdrawal from your own account (PRIVATE_KEY or --ledger) (links that account to the withdrawal).
        #[arg(long, conflicts_with = "relayer")]
        self_relay: bool,
        /// ERC-20 pools only: native coin the relayer should send the recipient, e.g. 0.01.
        #[arg(long)]
        refund: Option<String>,
        /// Send without asking for confirmation (required when stdin is not a terminal).
        #[arg(long, short)]
        yes: bool,
        /// Print the withdrawal calldata for another account (e.g. a Safe) to send
        /// instead of sending it. The pool address and value go to stderr.
        #[arg(long, conflicts_with_all = ["relayer", "self_relay", "refund"])]
        calldata: bool,
    },
    /// Show balances from the local note database.
    Balances {
        /// Also check each unspent note on-chain (needs --rpc-url for each chain's notes).
        #[arg(long)]
        check: bool,
    },
    /// Manage notes in the database.
    #[command(subcommand)]
    Notes(NotesCmd),
    /// Download deposit events for a pool into the local cache.
    Sync { currency: String, amount: String },
    /// List supported chains and pools.
    Pools,
    /// Show deposit counts and current holdings for every pool on the RPC's chain.
    Stats,
    /// Download and verify the circuit and proving key.
    FetchArtifacts,
    /// Re-encrypt the database under a new password.
    ChangePassword,
}

#[derive(Subcommand)]
enum NotesCmd {
    /// List notes (without secrets).
    List,
    /// Print a note's secret string, for backup or use in another wallet.
    Export { id: String },
    /// Import a tornado-cli note string. Checks the chain for its deposit when --rpc-url is set.
    Import {
        /// Read from the TORNADO_NOTE env var or a prompt if omitted, to keep it out of shell history.
        #[arg(env = "TORNADO_NOTE", hide_env_values = true)]
        note: Option<String>,
        #[arg(long)]
        label: Option<String>,
    },
}

struct App {
    data_dir: PathBuf,
    rpc_url: Option<String>,
    http: reqwest::Client,
    sync: SyncOptions,
    password: Option<Zeroizing<String>>,
    private_key: Option<Zeroizing<String>>,
    private_key_file: Option<PathBuf>,
    ledger: Option<HDPath>,
}

impl App {
    fn db_path(&self) -> PathBuf {
        self.data_dir.join("notes.db")
    }
    fn cache_dir(&self) -> PathBuf {
        self.data_dir.join("cache")
    }
    fn artifacts_dir(&self) -> PathBuf {
        self.data_dir.join("artifacts")
    }

    fn open_db(&self) -> Result<NoteDb> {
        let path = self.db_path();
        if !path.exists() {
            bail!(
                "no note database at {}; run `tornado-rs init` first",
                path.display()
            );
        }
        let pw = self.password("Database password: ")?;
        NoteDb::open(&path, &pw).context("opening note database")
    }

    async fn client(&self, signer: Option<EthereumWallet>) -> Result<TornadoClient> {
        let url = self
            .rpc_url
            .as_deref()
            .context("set --rpc-url or ETH_RPC_URL")?;
        let c = TornadoClient::connect_with_wallet(url, signer, Some(self.http.clone())).await?;
        if c.chain.tier == Tier::Secondary {
            eprintln!(
                "warning: {} has small anonymity sets and few relayers; mainnet gives far better privacy",
                c.chain.name
            );
        }
        Ok(c)
    }

    async fn synced_cache(
        &self,
        client: &TornadoClient,
        pool: &tornado_cash_rs::chains::Pool,
    ) -> Result<Vec<B256>> {
        let dir = self.cache_dir();
        let mut cache = DepositCache::load(&dir, pool, client.chain.chain_id);
        eprint!(
            "Syncing deposits for {} {}...",
            pool.amount,
            pool.currency.to_uppercase()
        );
        let r = sync_deposits(client, pool, &mut cache, &self.sync, |done, target| {
            eprint!(
                "\rSyncing deposits for {} {}: block {done}/{target}",
                pool.amount,
                pool.currency.to_uppercase()
            );
        })
        .await;
        // Keep whatever finalized blocks were fetched even if the scan stopped early.
        cache.save(&dir)?;
        let commitments = r?;
        eprintln!(" ({} deposits)", commitments.len());
        Ok(commitments)
    }
}

impl App {
    fn password(&self, prompt: &str) -> Result<Zeroizing<String>> {
        match &self.password {
            Some(p) => Ok(p.clone()),
            None => Ok(Zeroizing::new(rpassword::prompt_password(prompt)?)),
        }
    }

    /// The wallet for deposits and self-relayed withdrawals: the Ledger when
    /// --ledger is set, otherwise the private key.
    async fn signer(&self) -> Result<EthereumWallet> {
        if let Some(path) = &self.ledger {
            // The chain id comes from each transaction. The HID transport
            // panics when USB is unavailable, so contain that in a task.
            let ledger = tokio::spawn(LedgerSigner::new(path.clone(), None))
                .await
                .map_err(|_| anyhow::anyhow!("could not open USB HID to look for a Ledger"))?
                .context(
                    "connecting to the Ledger; is it plugged in, unlocked, and on the Ethereum app?",
                )?;
            eprintln!(
                "Using Ledger account {} ({path}); confirm each transaction on the device",
                alloy::signers::Signer::address(&ledger)
            );
            return Ok(EthereumWallet::from(ledger));
        }
        let raw = if let Some(path) = &self.private_key_file {
            Zeroizing::new(std::fs::read_to_string(path).context("reading PRIVATE_KEY_FILE")?)
        } else if let Some(k) = &self.private_key {
            k.clone()
        } else {
            Zeroizing::new(rpassword::prompt_password("Private key: ")?)
        };
        raw.trim()
            .parse::<PrivateKeySigner>()
            .map(EthereumWallet::from)
            .context("invalid private key")
    }
}

fn confirm(yes: bool, msg: &str) -> Result<()> {
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    confirm_from(yes, msg, interactive, &mut stdin.lock())
}

/// Ask `msg` on stderr and read the answer from `input`. Without a terminal
/// nobody can answer, so refuse rather than hang or read a stray "y".
fn confirm_from(yes: bool, msg: &str, interactive: bool, input: &mut impl BufRead) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !interactive {
        bail!("stdin is not a terminal, so there is nobody to confirm; pass --yes to go ahead without the prompt");
    }
    eprint!("{msg} [y/N] ");
    std::io::stderr().flush()?;
    let mut s = String::new();
    input.read_line(&mut s)?;
    if !matches!(s.trim(), "y" | "Y" | "yes") {
        bail!("aborted");
    }
    Ok(())
}

/// Base units as a decimal with about four significant digits, for display.
fn approx_units(v: U256, decimals: u8) -> String {
    let x: f64 = format_units(v, decimals).parse().unwrap_or(0.0);
    if x == 0.0 {
        return "0".into();
    }
    let places = (3 - x.log10().floor() as i32).max(0) as usize;
    let s = format!("{x:.places$}");
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

fn gwei(wei: u128) -> String {
    approx_units(U256::from(wei), 9)
}

/// Print an estimate's gas and fee lines, as shown before a confirmation.
fn print_estimate(gas: u64, fees: &GasFees, fee: U256, max_fee: U256, coin: &str) {
    println!("  Gas:   {gas} (estimated)");
    println!(
        "  Fee:   ~{} {coin} at {} gwei (at most {} {coin})",
        approx_units(fee, 18),
        gwei(fees.gas_price),
        approx_units(max_fee, 18)
    );
}

/// Say where requests will physically go, since the per-request log lines
/// show only their final destination.
fn log_route(proxy: Option<&str>) {
    use tornado_cash_rs::net::{redact_url, TARGET};
    match proxy {
        Some(p) => {
            let shown = p.parse().map(|u| redact_url(&u)).unwrap_or_default();
            let dns = if p.starts_with("socks5://") || p.starts_with("socks4://") {
                "hostnames are resolved locally by the system resolver (use socks5h:// to resolve through the proxy)"
            } else {
                "the proxy resolves hostnames"
            };
            tracing::info!(target: TARGET, "all requests go through proxy {shown}; {dns}");
        }
        None => {
            // Without --proxy, reqwest picks up the standard proxy variables.
            let env: Vec<String> = [
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
                "all_proxy",
            ]
            .iter()
            .filter_map(|k| {
                let v = std::env::var(k).ok().filter(|v| !v.is_empty())?;
                let shown = v.parse().map(|u| redact_url(&u)).unwrap_or_default();
                Some(format!("{k}={shown}"))
            })
            .collect();
            if env.is_empty() {
                tracing::info!(
                    target: TARGET,
                    "no proxy: requests connect directly and hostnames are resolved by the system resolver"
                );
            } else {
                tracing::info!(
                    target: TARGET,
                    "no --proxy, but requests use the proxy from {} (hosts in NO_PROXY connect directly)",
                    env.join(", ")
                );
            }
        }
    }
}

/// Run one `tornado-rs` command.
pub async fn run(cli: Cli) -> Result<()> {
    let data_dir = match cli.data_dir {
        Some(d) => d,
        None => dirs::home_dir()
            .context("no home directory; pass --data-dir")?
            .join(".tornado-cash-rs"),
    };
    let mut http = reqwest::Client::builder();
    if let Some(p) = &cli.proxy {
        http = http.proxy(reqwest::Proxy::all(p).context("invalid --proxy")?);
    }
    log_route(cli.proxy.as_deref());
    let app = App {
        data_dir,
        rpc_url: cli.rpc_url,
        http: http.build()?,
        sync: SyncOptions {
            max_block_span: cli.log_span,
            ..Default::default()
        },
        password: cli.password.map(Zeroizing::new),
        private_key: cli.private_key.map(Zeroizing::new),
        private_key_file: cli.private_key_file,
        ledger: cli.ledger.then_some(match cli.hd_path {
            Some(p) => HDPath::Other(p),
            None => HDPath::LedgerLive(cli.ledger_index),
        }),
    };

    match cli.cmd {
        Cmd::Init => init(&app),
        Cmd::Deposit {
            currency,
            amount,
            yes: _,
            calldata: true,
        } => deposit_calldata(&app, &currency, &amount).await,
        Cmd::Deposit {
            currency,
            amount,
            yes,
            calldata: false,
        } => deposit(&app, &currency, &amount, yes).await,
        Cmd::Withdraw {
            id,
            recipient,
            relayer,
            self_relay,
            refund,
            yes,
            calldata,
        } => {
            withdraw(
                &app, &id, recipient, relayer, self_relay, refund, yes, calldata,
            )
            .await
        }
        Cmd::Balances { check } => balances(&app, check).await,
        Cmd::Notes(n) => notes(&app, n).await,
        Cmd::Sync { currency, amount } => {
            let client = app.client(None).await?;
            let pool = client.chain.pool(&currency, &amount)?.clone();
            app.synced_cache(&client, &pool).await?;
            Ok(())
        }
        Cmd::Pools => {
            pools();
            Ok(())
        }
        Cmd::Stats => stats(&app).await,
        Cmd::FetchArtifacts => {
            Prover::load(&app.artifacts_dir(), Some(app.http.clone())).await?;
            println!("Artifacts verified in {}", app.artifacts_dir().display());
            Ok(())
        }
        Cmd::ChangePassword => {
            let mut db = app.open_db()?;
            let a = Zeroizing::new(rpassword::prompt_password("New password: ")?);
            let b = Zeroizing::new(rpassword::prompt_password("Repeat new password: ")?);
            if a != b {
                bail!("passwords do not match");
            }
            db.change_password(&a)?;
            println!("Password changed");
            Ok(())
        }
    }
}

fn init(app: &App) -> Result<()> {
    let path = app.db_path();
    let pw = match &app.password {
        Some(p) => p.clone(),
        None => {
            let a = Zeroizing::new(rpassword::prompt_password("New database password: ")?);
            let b = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
            if a != b {
                bail!("passwords do not match");
            }
            a
        }
    };
    NoteDb::create(&path, &pw)?;
    println!("Created encrypted note database at {}", path.display());
    println!("If you lose the password, the notes in it (and the funds they control) cannot be recovered.");
    Ok(())
}

async fn deposit(app: &App, currency: &str, amount: &str, yes: bool) -> Result<()> {
    let mut db = app.open_db()?;
    let client = app.client(Some(app.signer().await?)).await?;
    let pool = client.chain.pool(currency, amount)?.clone();
    let from = client.sender()?;
    let coin = client.chain.native_symbol;

    let note = Note::random(client.chain.chain_id, pool.currency, pool.amount);
    let est = client.estimate_deposit(&pool, &note).await?;
    println!(
        "Deposit {} {} on {} from {from}",
        pool.amount,
        pool.currency.to_uppercase(),
        client.chain.name
    );
    if !est.approval_gas.is_empty() {
        println!(
            "  {} approval(s) first, gas {}",
            est.approval_gas.len(),
            est.approval_gas
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" + ")
        );
    }
    print_estimate(est.gas(), &est.fees, est.fee(), est.max_fee(), coin);
    confirm(yes, "Send the deposit?")?;

    // Persist the secret before the deposit is broadcast, so a crash after
    // that point can't lose funds; drop it only if the deposit surely failed.
    let mut saved = None;
    let result = client
        .deposit_with(&pool, &note, |tx| {
            let id = db.insert(note.clone(), pool.address, NoteStatus::Pending)?;
            db.update(&id, |rec| rec.deposit_tx = Some(tx))?;
            saved = Some(id);
            Ok(())
        })
        .await;
    let (r, id) = match (result, saved) {
        (Ok(r), Some(id)) => (r, id),
        (Ok(_), None) => unreachable!("the note is saved before the deposit is sent"),
        (Err(e), None) => return Err(e.into()),
        (Err(e @ Error::NotDeposited(_)), Some(id)) => {
            db.remove(&id)?;
            return Err(e.into());
        }
        (Err(e), Some(id)) => bail!(
            "{e}\nNote {id} is kept as pending in case the deposit was mined; \
             run `tornado-rs balances --check` to update it"
        ),
    };
    db.update(&id, |rec| {
        rec.status = NoteStatus::Deposited;
        rec.deposit_block = Some(r.block_number);
        rec.leaf_index = Some(r.leaf_index);
    })?;
    println!(
        "Deposited note {id} (leaf {}) in {}",
        r.leaf_index,
        client.tx_url(&r.tx_hash)
    );
    println!(
        "Gas used: {}, fee paid: {} {coin}",
        r.gas_used,
        approx_units(r.fee, 18)
    );
    println!("Back up the note with `tornado-rs notes export {id}` and keep it secret.");
    Ok(())
}

/// Generate and save a note, then print the calldata for depositing it from
/// another account. The note stays pending until `balances --check` finds the
/// deposit on-chain.
async fn deposit_calldata(app: &App, currency: &str, amount: &str) -> Result<()> {
    let mut db = app.open_db()?;
    let client = app.client(None).await?;
    let pool = client.chain.pool(currency, amount)?.clone();
    let note = Note::random(client.chain.chain_id, pool.currency, pool.amount);
    // The other account may send the call much later, so the note must be
    // saved before the calldata is handed out.
    let id = db.insert(note.clone(), pool.address, NoteStatus::Pending)?;
    eprintln!("Saved note {id} to the database as pending");
    let denomination = pool.denomination();
    if let Some(token) = pool.token {
        eprintln!(
            "First approve the pool to spend {} {}: to {token}, value 0, data {}",
            pool.amount,
            pool.currency.to_uppercase(),
            eth::approve_calldata(pool.address, denomination)
        );
        eprintln!("(Tokens like USDT need the allowance set to 0 before a new approval.)");
        eprintln!("Then send the deposit: to {}, value 0", pool.address);
    } else {
        eprintln!(
            "Send the deposit: to {}, value {denomination} wei ({} {})",
            pool.address,
            pool.amount,
            pool.currency.to_uppercase()
        );
    }
    eprintln!("Once it is mined, run `tornado-rs balances --check` to mark the note deposited.");
    eprintln!("Back up the note with `tornado-rs notes export {id}` and keep it secret.");
    println!("{}", eth::deposit_calldata(&note));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn withdraw(
    app: &App,
    id: &str,
    recipient: Address,
    relayer: Option<String>,
    self_relay: bool,
    refund: Option<String>,
    yes: bool,
    calldata: bool,
) -> Result<()> {
    if relayer.is_none() && !self_relay && !calldata {
        bail!("pass --relayer <url>, --self-relay to pay gas from your own account (which links it to this withdrawal), or --calldata to print the call for another account to send");
    }
    let mut db = app.open_db()?;
    // The local status is only a hint; the chain decides whether the note is spent.
    let rec = db.get(id)?.clone();
    let signer = if self_relay {
        Some(app.signer().await?)
    } else {
        None
    };
    let client = app.client(signer).await?;
    if client.chain.chain_id != rec.note.chain_id {
        bail!(
            "note {} is for chain {}, but the RPC is chain {}",
            rec.id,
            rec.note.chain_id,
            client.chain.chain_id
        );
    }
    let pool = client
        .chain
        .pool(&rec.note.currency, &rec.note.amount)?
        .clone();
    let refund = match &refund {
        Some(r) if pool.is_native() => bail!("--refund only applies to ERC-20 pools (got {r})"),
        Some(r) => parse_units(r, 18).context("invalid --refund")?,
        None => U256::ZERO,
    };

    if client
        .is_spent(&pool, rec.note.nullifier_hash_bytes())
        .await?
    {
        db.update(&rec.id, |r| r.status = NoteStatus::Spent)?;
        bail!(
            "note {} was already withdrawn on-chain; marked spent",
            rec.id
        );
    }

    let commitments = app.synced_cache(&client, &pool).await?;
    let tree = build_tree(&commitments)?;
    let leaf = tree
        .index_of(&rec.note.commitment())
        .context("deposit not found in the pool's events; is the deposit mined?")?;
    let path = tree.proof(leaf)?;
    if !client.is_known_root(&pool, path.root_bytes()).await? {
        bail!(
            "computed Merkle root is not known to the contract; run again after the RPC catches up"
        );
    }

    eprintln!("Loading proving key...");
    let prover = Prover::load(&app.artifacts_dir(), Some(app.http.clone())).await?;

    if calldata {
        eprintln!("Generating proof...");
        let proof = prover.prove_withdrawal(
            &rec.note,
            &path,
            recipient,
            Address::ZERO,
            U256::ZERO,
            U256::ZERO,
        )?;
        eprintln!(
            "Send the withdrawal of {} {} to {recipient}: to {}, value 0",
            pool.amount,
            pool.currency.to_uppercase(),
            pool.address
        );
        eprintln!(
            "Once it is mined, run `tornado-rs balances --check` to mark note {} spent.",
            rec.id
        );
        println!("{}", eth::withdraw_calldata(&proof));
        return Ok(());
    }

    let coin = client.chain.native_symbol;
    let tx = if let Some(url) = relayer {
        let rc = RelayerClient::new(&url, Some(app.http.clone()))?;
        let status = rc.status().await?;
        if !status.serves_chain(client.chain.chain_id) {
            bail!("relayer does not serve {}", client.chain.name);
        }
        let gas_price = client.gas_price().await?;
        let fee = RelayerClient::quote_fee(&status, &pool, gas_price, refund)?;
        println!(
            "Withdraw {} {} to {recipient} via {url} (relayer {})",
            pool.amount,
            pool.currency.to_uppercase(),
            status.reward_account
        );
        println!(
            "  Fee:   {} {} to the relayer, which pays the gas (at {} gwei)",
            format_units(fee, pool.decimals),
            pool.currency.to_uppercase(),
            gwei(gas_price)
        );
        confirm(yes, "Send the withdrawal?")?;
        eprintln!("Generating proof...");
        let proof = prover.prove_withdrawal(
            &rec.note,
            &path,
            recipient,
            status.reward_account,
            fee,
            refund,
        )?;
        let job = rc.submit(&pool, &proof).await?;
        eprintln!("Submitted job {job}");
        rc.wait(&job, |j| eprintln!("  relayer: {}", j.status))
            .await?
    } else {
        // The gas can only be estimated with a valid proof, so prove first.
        eprintln!("Generating proof...");
        let proof = prover.prove_withdrawal(
            &rec.note,
            &path,
            recipient,
            Address::ZERO,
            U256::ZERO,
            U256::ZERO,
        )?;
        let est = client.estimate_withdraw(&pool, &proof).await?;
        println!(
            "Withdraw {} {} to {recipient}, paying gas from {}",
            pool.amount,
            pool.currency.to_uppercase(),
            client.sender()?
        );
        print_estimate(est.gas, &est.fees, est.fee(), est.max_fee(), coin);
        confirm(yes, "Send the withdrawal?")?;
        client.withdraw(&pool, &proof).await?
    };

    // Never trust a relayer's word that the withdrawal happened: only mark the
    // note spent once the receipt shows this pool emitting our nullifier hash.
    db.update(&rec.id, |r| r.withdraw_tx = Some(tx))?;
    if let Err(e) = client
        .confirm_withdrawal(&pool, tx, rec.note.nullifier_hash_bytes())
        .await
    {
        bail!(
            "could not confirm withdrawal tx {tx} on-chain ({e}); note {} is still marked unspent. \
             Run `tornado-rs balances --check` later, or withdraw again if the tx never landed",
            rec.id
        );
    }
    db.update(&rec.id, |r| {
        r.status = NoteStatus::Spent;
        r.withdraw_recipient = Some(recipient);
    })?;
    println!("Withdrew note {} in {}", rec.id, client.tx_url(&tx));
    match client.tx_cost(tx).await {
        Ok((gas, fee)) if self_relay => {
            println!(
                "Gas used: {gas}, fee paid: {} {coin}",
                approx_units(fee, 18)
            )
        }
        Ok((gas, fee)) => println!(
            "Gas used: {gas}, paid by the relayer: {} {coin}",
            approx_units(fee, 18)
        ),
        Err(e) => eprintln!("could not read the withdrawal's gas use: {e}"),
    }
    Ok(())
}

async fn balances(app: &App, check: bool) -> Result<()> {
    let mut db = app.open_db()?;
    if check {
        let client = app.client(None).await?;
        // Re-check every note on this chain, including ones marked spent locally,
        // so a wrong local status can always be repaired from the chain.
        let ids: Vec<String> = db
            .notes()
            .iter()
            .filter(|r| r.note.chain_id == client.chain.chain_id)
            .map(|r| r.id.clone())
            .collect();
        let mut synced: std::collections::HashMap<Address, Vec<B256>> = Default::default();
        for id in ids {
            let rec = db.get(&id)?.clone();
            let Ok(pool) = client.chain.pool(&rec.note.currency, &rec.note.amount) else {
                continue;
            };
            let pool = pool.clone();
            if rec.status == NoteStatus::Pending {
                // A deposit can be mined after the CLI lost track of it (crash, RPC
                // timeout); promote it once its commitment shows up in the events.
                if let std::collections::hash_map::Entry::Vacant(e) = synced.entry(pool.address) {
                    e.insert(app.synced_cache(&client, &pool).await?);
                }
                // Hash once: the Pedersen hash is slow and pools hold ~10^5 deposits.
                let commitment = rec.note.commitment_bytes();
                let leaf = synced[&pool.address].iter().position(|c| *c == commitment);
                let Some(leaf) = leaf else { continue };
                eprintln!("note {id} found on-chain at leaf {leaf}; marking deposited");
                db.update(&id, |r| {
                    r.status = NoteStatus::Deposited;
                    r.leaf_index = Some(leaf as u32);
                })?;
            }
            let spent = client
                .is_spent(&pool, rec.note.nullifier_hash_bytes())
                .await?;
            let status = db.get(&id)?.status;
            if spent && status != NoteStatus::Spent {
                eprintln!("note {id} is spent on-chain; updating");
                db.update(&id, |r| r.status = NoteStatus::Spent)?;
            } else if !spent && status == NoteStatus::Spent {
                eprintln!(
                    "note {id} is marked spent but its nullifier is unused on-chain; restoring"
                );
                db.update(&id, |r| r.status = NoteStatus::Deposited)?;
            }
        }
    }
    let bals = db.balances();
    if bals.is_empty() {
        println!("No unspent notes.");
        return Ok(());
    }
    println!(
        "{:<10} {:<6} {:>14} {:>6} {:>8}",
        "CHAIN", "ASSET", "BALANCE", "NOTES", "PENDING"
    );
    for b in bals {
        let chain = chain_by_id(b.chain_id).map(|c| c.name).unwrap_or("?");
        println!(
            "{:<10} {:<6} {:>14} {:>6} {:>8}",
            chain,
            b.currency.to_uppercase(),
            b.formatted(),
            b.notes,
            b.pending
        );
    }
    Ok(())
}

async fn notes(app: &App, cmd: NotesCmd) -> Result<()> {
    match cmd {
        NotesCmd::List => {
            let db = app.open_db()?;
            println!(
                "{:<9} {:<10} {:<6} {:>8} {:<10} {:>7}  LABEL",
                "ID", "CHAIN", "ASSET", "AMOUNT", "STATUS", "LEAF"
            );
            for r in db.notes() {
                let chain = chain_by_id(r.note.chain_id).map(|c| c.name).unwrap_or("?");
                println!(
                    "{:<9} {:<10} {:<6} {:>8} {:<10} {:>7}  {}",
                    r.id,
                    chain,
                    r.note.currency.to_uppercase(),
                    r.note.amount,
                    format!("{:?}", r.status).to_lowercase(),
                    r.leaf_index
                        .map(|l| l.to_string())
                        .unwrap_or_else(|| "-".into()),
                    r.label.as_deref().unwrap_or("")
                );
            }
            Ok(())
        }
        NotesCmd::Export { id } => {
            let db = app.open_db()?;
            let r = db.get(&id)?;
            eprintln!("Anyone with this string can withdraw the note:");
            println!("{}", r.note.to_note_string());
            Ok(())
        }
        NotesCmd::Import { note, label } => {
            let s = match note {
                Some(s) => Zeroizing::new(s),
                None => Zeroizing::new(rpassword::prompt_password("Note: ")?),
            };
            let note = Note::parse(&s)?;
            let chain = chain_by_id(note.chain_id)?;
            let pool = chain.pool(&note.currency, &note.amount)?.clone();
            let mut db = app.open_db()?;

            let mut status = NoteStatus::Pending;
            let mut leaf = None;
            if app.rpc_url.is_some() {
                let client = app.client(None).await?;
                if client.chain.chain_id == note.chain_id {
                    let commitments = app.synced_cache(&client, &pool).await?;
                    let commitment = note.commitment_bytes();
                    leaf = commitments.iter().position(|c| *c == commitment);
                    if leaf.is_some() {
                        status = if client.is_spent(&pool, note.nullifier_hash_bytes()).await? {
                            NoteStatus::Spent
                        } else {
                            NoteStatus::Deposited
                        };
                    }
                } else {
                    eprintln!("RPC is a different chain; importing without checking the deposit");
                }
            }
            let id = db.insert(note, pool.address, status)?;
            db.update(&id, |r| {
                r.label = label;
                r.leaf_index = leaf.map(|l| l as u32);
            })?;
            println!("Imported note {id} ({:?})", status);
            if status == NoteStatus::Pending {
                println!("Deposit not confirmed yet; withdraw will check again.");
            }
            Ok(())
        }
    }
}

fn pools() {
    for c in all_chains() {
        let tier = match c.tier {
            Tier::Primary => "primary",
            Tier::Secondary => "secondary",
        };
        println!("{} (chain {}, {tier})", c.name, c.chain_id);
        for p in &c.pools {
            println!(
                "  {:>7} {:<5} {:#x}",
                p.amount,
                p.currency.to_uppercase(),
                p.address
            );
        }
    }
}

async fn stats(app: &App) -> Result<()> {
    let client = app.client(None).await?;
    println!("{} (chain {})", client.chain.name, client.chain.chain_id);
    println!(
        "{:<6} {:>8} {:>10} {:>16}",
        "ASSET", "AMOUNT", "DEPOSITS", "HELD"
    );
    for p in client.chain.pools.clone() {
        let count = client.deposit_count(&p).await?;
        let held = client.balance_of(&p, p.address).await?;
        println!(
            "{:<6} {:>8} {:>10} {:>16}",
            p.currency.to_uppercase(),
            p.amount,
            count,
            format_units(held, p.decimals)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_needs_yes_without_a_terminal() {
        let err = confirm_from(false, "go?", false, &mut &b"y\n"[..]).unwrap_err();
        assert!(err.to_string().contains("--yes"), "{err}");
        confirm_from(true, "go?", false, &mut &b""[..]).unwrap();
    }

    #[test]
    fn confirm_reads_the_answer() {
        confirm_from(false, "go?", true, &mut &b"y\n"[..]).unwrap();
        confirm_from(false, "go?", true, &mut &b"yes\n"[..]).unwrap();
        for answer in [&b"\n"[..], b"n\n", b""] {
            let mut input = answer;
            let err = confirm_from(false, "go?", true, &mut input).unwrap_err();
            assert_eq!(err.to_string(), "aborted");
        }
    }

    #[test]
    fn approx_units_keeps_four_significant_digits() {
        let wei = |s: &str| parse_units(s, 18).unwrap();
        assert_eq!(approx_units(wei("0.00123456789"), 18), "0.001235");
        assert_eq!(approx_units(wei("1.5"), 18), "1.5");
        assert_eq!(approx_units(wei("0.000000123"), 18), "0.000000123");
        assert_eq!(approx_units(U256::ZERO, 18), "0");
        assert_eq!(gwei(12_345_678_901), "12.35");
    }
}
