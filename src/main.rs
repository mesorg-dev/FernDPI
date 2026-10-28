use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use ferndpi::config::{Cli, Config};
use ferndpi::i18n::Key;
use ferndpi::Core;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::from_cli(&cli)?;
    let lang = cfg.lang;
    let verbose = cfg.verbose;

    let filter = match std::env::var("RUST_LOG") {
        Ok(_) => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        Err(_) => EnvFilter::new(match verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    for w in &cfg.import_warnings {
        tracing::warn!("[flowseal] {w}");
    }

    let core = Core::new(cfg);

    let listener = tokio::net::TcpListener::bind(core.config.listen)
        .await
        .with_context(|| format!("bind {}", core.config.listen))?;

    let serve = core.serve(listener);
    tokio::pin!(serve);

    tokio::select! {
        r = &mut serve => {
            r.context("socks5 server")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("{}", lang.t(Key::ShuttingDown));
        }
    }

    info!("{} {}", lang.t(Key::Stats), core.stats());
    info!("{}", lang.t(Key::Shutdown));
    Ok(())
}
