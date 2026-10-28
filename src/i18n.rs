//! Tiny i18n stub: one place for user-facing strings (ru/en).
//! Future: load from files / add more languages without touching logic.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ru,
}

impl Lang {
    pub fn t(self, key: Key) -> &'static str {
        match (self, key) {
            (Lang::En, Key::Listening) => "listening on",
            (Lang::Ru, Key::Listening) => "слушаю на",

            (Lang::En, Key::ConnectTo) => "CONNECT to",
            (Lang::Ru, Key::ConnectTo) => "соединение к",

            (Lang::En, Key::UpstreamOk) => "upstream connected",
            (Lang::Ru, Key::UpstreamOk) => "выходное соединение установлено",

            (Lang::En, Key::TunnelPlain) => "no desync applicable, plain tunnel",
            (Lang::Ru, Key::TunnelPlain) => "рез неприменим, обычный туннель",

            (Lang::En, Key::NoSni) => "ClientHello without SNI, tunnel as-is",
            (Lang::Ru, Key::NoSni) => "ClientHello без SNI, туннель без реза",

            (Lang::En, Key::SplitApplied) => "SNI split applied",
            (Lang::Ru, Key::SplitApplied) => "SNI-рез применён",

            (Lang::En, Key::FragApplied) => "TLS record fragmentation applied",
            (Lang::Ru, Key::FragApplied) => "фрагментация TLS-записи применена",

            (Lang::En, Key::HttpSplitApplied) => "HTTP Host split applied",
            (Lang::Ru, Key::HttpSplitApplied) => "рез HTTP Host применён",

            (Lang::En, Key::SocksBadVersion) => "unsupported SOCKS version",
            (Lang::Ru, Key::SocksBadVersion) => "неподдерживаемая версия SOCKS",

            (Lang::En, Key::SocksNoAuth) => "no acceptable auth method",
            (Lang::Ru, Key::SocksNoAuth) => "нет подходящего метода авторизации",

            (Lang::En, Key::SocksCmdUnsupported) => "only CONNECT is supported",
            (Lang::Ru, Key::SocksCmdUnsupported) => "поддерживается только CONNECT",

            (Lang::En, Key::SocksTimeout) => "SOCKS handshake timeout",
            (Lang::Ru, Key::SocksTimeout) => "таймаут SOCKS-рукопожатия",

            (Lang::En, Key::FirstDataTimeout) => "first data timeout, tunnel",
            (Lang::Ru, Key::FirstDataTimeout) => "таймаут первого пакета, туннель",

            (Lang::En, Key::ShuttingDown) => "shutdown signal received",
            (Lang::Ru, Key::ShuttingDown) => "получен сигнал остановки",

            (Lang::En, Key::Shutdown) => "shutting down",
            (Lang::Ru, Key::Shutdown) => "завершаю работу",

            (Lang::En, Key::Stats) => "stats",
            (Lang::Ru, Key::Stats) => "статистика",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Listening,
    ConnectTo,
    UpstreamOk,
    TunnelPlain,
    NoSni,
    SplitApplied,
    FragApplied,
    HttpSplitApplied,
    SocksBadVersion,
    SocksNoAuth,
    SocksCmdUnsupported,
    SocksTimeout,
    FirstDataTimeout,
    ShuttingDown,
    Shutdown,
    Stats,
}
