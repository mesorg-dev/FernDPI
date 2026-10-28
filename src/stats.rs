//! Session statistics — public for frontends (VpnService status, UI, …).

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Stats {
    sessions: AtomicU64,
    desynced: AtomicU64,
    tunneled: AtomicU64,
    http_desynced: AtomicU64,
    errors: AtomicU64,
    bytes_to_target: AtomicU64,
    bytes_to_client: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub sessions: u64,
    pub desynced: u64,
    pub tunneled: u64,
    pub http_desynced: u64,
    pub errors: u64,
    pub bytes_to_target: u64,
    pub bytes_to_client: u64,
}

impl Stats {
    pub fn on_session(&self) {
        self.sessions.fetch_add(1, Ordering::Relaxed);
    }
    pub fn on_desync(&self) {
        self.desynced.fetch_add(1, Ordering::Relaxed);
    }
    pub fn on_tunnel(&self) {
        self.tunneled.fetch_add(1, Ordering::Relaxed);
    }
    pub fn on_http_desync(&self) {
        self.http_desynced.fetch_add(1, Ordering::Relaxed);
    }
    pub fn on_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_bytes_to_target(&self, n: u64) {
        self.bytes_to_target.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_bytes_to_client(&self, n: u64) {
        self.bytes_to_client.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            sessions: self.sessions.load(Ordering::Relaxed),
            desynced: self.desynced.load(Ordering::Relaxed),
            tunneled: self.tunneled.load(Ordering::Relaxed),
            http_desynced: self.http_desynced.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_to_target: self.bytes_to_target.load(Ordering::Relaxed),
            bytes_to_client: self.bytes_to_client.load(Ordering::Relaxed),
        }
    }
}

impl std::fmt::Display for StatsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sessions={} desynced={} http={} tunneled={} errors={} up={}B down={}B",
            self.sessions,
            self.desynced,
            self.http_desynced,
            self.tunneled,
            self.errors,
            self.bytes_to_target,
            self.bytes_to_client
        )
    }
}
