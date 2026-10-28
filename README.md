# FernDPI

Userspace DPI-bypass engine (аналог zapret) без root: SOCKS5-прокси с десинхронизацией TLS/HTTP/UDP-трафика. Чистый Rust, один бинарник на **Linux / Windows / Android**.

## Что умеет (v0.3, готово)

- **SOCKS5** (no-auth, CONNECT, IPv4/IPv6/домены) — трафик приложений идёт через прокси.
- **Стратегии обхода**: `split`, `multisplit`, `frag` (фрагментация TLS-записи с маппингом offset'ов), `http` (рез Host), цепочки `frag,split` + `delay_ms`.
- **Импорт конфигов Flowseal / zapret-discord-youtube**: `ferndpi --flowseal general.bat` (или `-c file.bat`, автодетект) парсит командную строку winws — `--filter-tcp/udp`, `--hostlist*`, `--ipset*`, `--dpi-desync*` — и перекладывает в правила ядра. Все **22 реальных `general*.bat`** покрыты тестами-фикстурами.
- **UDP-фейки** (QUIC / Discord-голос / STUN): семантика zapret — перед каждым датаграммом `repeats` копий payload'ов из `bin/*.bin`, без raw-сокетов (обычная `sendto` — работает из VPN/relay без root).
- **Hostlist/ipset**: паттерны zapret (`example.com`, `*.foo.net`, `^exact`), CIDR-сети, exclude-списки, портовые фильтры, правило-первы-совпал.
- **Деградация с варнами**: то, что требует raw-сокетов (fake/seqovl на TCP, `%GameFilter%`), честно упрощается и пишется в лог.
- TOML-конфиг + zapret-стиль CLI-флагов, `[hosts]`-оверрайды, i18n ru/en, статистика сессий.

## Сборка

```bash
cargo build --release          # локальный бинарник
cargo test                     # 77 тестов (фикстуры — реальные батники Flowseal)
```

Кросс-сборка под Android (GitHub Actions делает это в CI):

```bash
rustup target add aarch64-linux-android
cargo build --release --target aarch64-linux-android \
  --config 'target.aarch64-linux-android.linker="aarch64-linux-android26-clang"'
```

## Запуск

```bash
# Импорт конфига флоссеала + локальный прокси
ferndpi --flowseal 'general (ALT9).bat' --listen 127.0.0.1:1080

# Свой TOML + zapret-флаги
ferndpi -c ferndpi.toml --hostlist blocked.txt --dpi-desync multisplit --dpi-desync-split-pos 1,mid
```

Примеры: [`examples/ferndpi.toml`](examples/ferndpi.toml), демо-стенд `demo_site.py`.

## CI (GitHub Actions)

На каждый push/PR:

| Job | Что делает |
|---|---|
| `test` | `cargo test` на Linux и Windows |
| `build-linux` | release-бинарник `ferndpi-linux-x86_64` |
| `build-windows` | release-бинарник `ferndpi-windows-x86_64.exe` |
| `build-android` | `ferndpi-android-aarch64` (NDK, minSdk 26) |

На тег `v*` всё собирается и публикуется в GitHub Release.

## Дорожная карта

- **Android APK** (в этом же репо, `android/`): VpnService → `hev-socks5-tunnel` (tun2socks, MIT) → SOCKS5 ядра; Material 3 (тёмная), конфиг-пикер с оценкой «пробивает N/M доменов», автовыбор рабочего конфига, маршрутизация по приложениям, виртуальные hosts, хотспот-LAN (SOCKS на `0.0.0.0`), автостарт, wake lock, нотификация статуса.
- SOCKS5 UDP ASSOCIATE в ядре (для голоса Discord через tun2socks).
- QUIC SNI парсер (дешифр Initial) — точное матчирование UDP-hostlist'ов.

## Лицензия

MIT
