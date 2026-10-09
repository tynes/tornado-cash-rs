use tornado_cash_rs_cli::{run, Cli, Parser};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("TORNADO_RS_LOG"))
        .with_writer(std::io::stderr)
        .init();
    run(Cli::parse()).await
}
