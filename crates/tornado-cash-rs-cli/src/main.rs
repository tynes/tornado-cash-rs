use tornado_cash_rs_cli::{run, Cli, Parser};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut filter = tracing_subscriber::EnvFilter::from_env("TORNADO_RS_LOG");
    if let Some(d) = cli.network_log_directive() {
        filter = filter.add_directive(d.parse()?);
    }
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    run(cli).await
}
