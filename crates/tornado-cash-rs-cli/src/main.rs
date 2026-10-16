use tornado_cash_rs_cli::{run, Cli, Parser};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let env = std::env::var("TORNADO_RS_LOG").ok();
    let filter = tracing_subscriber::EnvFilter::try_new(cli.log_filter(env.as_deref()))?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    run(cli).await
}
