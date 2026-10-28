//! Core: frontend-agnostic engine. Feed it any `TcpStream` (SOCKS5 frontend
//! today; Android VpnService / system proxy frontends later) and it applies
//! per-domain desync strategies.

use std::sync::Arc;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tracing::info;

use crate::config::Config;
use crate::i18n::Key;
use crate::pipeline::{self, Session};
use crate::socks5;
use crate::stats::{Stats, StatsSnapshot};

pub struct Core {
    pub config: Config,
    pub(crate) stats: Arc<Stats>,
}

impl Core {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            config,
            stats: Arc::new(Stats::default()),
        })
    }

    pub fn stats_handle(&self) -> Arc<Stats> {
        Arc::clone(&self.stats)
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Full SOCKS5 server on `listener`; runs until error (caller decides
    /// shutdown, e.g. select! with ctrl_c).
    pub async fn serve(self: &Arc<Self>, listener: TcpListener) -> Result<()> {
        let lang = self.config.lang;
        info!(
            "{} {} (default={}, rules={})",
            lang.t(Key::Listening),
            self.config.listen,
            self.config.default,
            self.config.rules.len()
        );
        socks5::serve(listener, Arc::clone(self)).await
    }

    /// Handle one already-established client stream (frontends: VpnService
    /// protected sockets, test harnesses). Performs SOCKS5 handshake.
    pub async fn handle_stream(self: &Arc<Self>, stream: TcpStream) -> Result<()> {
        socks5::handle_client(stream, self).await
    }

    /// UDP policy for a datagram flow — for frontends (VpnService, UDP relay).
    ///
    /// For every outgoing datagram: send `policy.fakes()` first from the same
    /// relay socket, then the real payload (zapret fake semantics, no raw
    /// sockets needed). `host` is optional (QUIC SNI not parsed yet — rules
    /// then match by ports/IP only).
    pub fn udp_policy(
        &self,
        host: Option<&str>,
        port: u16,
        ip: Option<std::net::IpAddr>,
    ) -> crate::udp::UdpPolicy {
        self.config.udp_policy(host, port, ip)
    }

    /// Handle a raw connection after SOCKS5 (frontends that do their own
    /// SOCKS termination): apply strategy for `host`/`port`/`ip` and relay.
    pub async fn relay_session(
        self: &Arc<Self>,
        client: TcpStream,
        upstream: TcpStream,
        host: Option<String>,
        port: u16,
        ip: Option<std::net::IpAddr>,
    ) -> Result<()> {
        let strategy = self.config.strategy_for(host.as_deref(), port, ip).clone();
        let session = Session {
            strategy,
            host,
            stats: self.stats_handle(),
            lang: self.config.lang,
            timeouts: self.config.timeouts,
        };
        pipeline::relay(client, upstream, &session).await?;
        Ok(())
    }

    /// Bind `config.listen` and serve. Convenience for simple frontends.
    pub async fn run(self: &Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen).await?;
        self.serve(listener).await
    }
}
