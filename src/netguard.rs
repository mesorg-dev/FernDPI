//! Optional socket protect hook.
//!
//! Android's VpnService must `protect()` every socket the app opens, or the
//! traffic loops back into the tun. Frontends (the Android JNI bridge) install
//! a hook here; without it (desktop) everything is a no-op.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

pub type ProtectFn = fn(i32) -> bool;

static HOOK: OnceLock<ProtectFn> = OnceLock::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn set_protect_hook(f: ProtectFn) {
    let _ = HOOK.set(f);
    ACTIVE.store(true, Ordering::Release);
}

pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

pub fn protect(fd: i32) {
    if let Some(f) = HOOK.get() {
        f(fd);
    }
}
